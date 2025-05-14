package ctlog

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	mathrand "math/rand/v2"
	"sync"
	"testing"
	"time"

	"crawshaw.io/sqlite"
	"filippo.io/sunlight"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/sync/errgroup"
)

type Log struct {
	c     *Config
	logID [sha256.Size]byte
	m     metrics

	// tree, edgeTiles, lockCheckpoint, and cacheWrite are owned by sequencePool.
	tree           treeWithTimestamp
	lockCheckpoint LockedCheckpoint
	// edgeTiles is a map from level to the right-most tile of that level.
	edgeTiles map[int]tileWithBytes
	// cacheWrite is used to update the deduplication cache at the end of each
	// sequencing batch, before inSequencing and currentPool are rotated.
	cacheWrite *sqlite.Conn

	// poolMu is held for the entire duration of addLeafToPool, and by
	// RunSequencer while rotating currentPool and inSequencing.
	// This guarantees that addLeafToPool will never add to a pool that already
	// started sequencing, and that cacheRead will see entries from older pools
	// before they are rotated out of inSequencing.
	poolMu      sync.Mutex
	currentPool *pool
	// inSequencing is the pool.byHash map of the pool that's currently being
	// sequenced. These entries might not be sequenced yet or might not yet be
	// committed to the deduplication cache.
	inSequencing map[cacheHash]waitEntryFunc
	// cacheRead is used to check the deduplication cache under poolMu.
	cacheRead *sqlite.Conn

	// issuers is a cache of issuers that have been uploaded or checked since
	// the log started. There might be more in the backend.
	issuersMu sync.RWMutex
	issuers   map[[32]byte]bool
}

type treeWithTimestamp struct {
	tlog.Tree
	Time int64
}

type tileWithBytes struct {
	tlog.Tile
	B []byte
}

func (t tileWithBytes) Path() string {
	return sunlight.TilePath(t.Tile)
}

func (t tileWithBytes) String() string {
	return fmt.Sprintf("%s#%d", sunlight.TilePath(t.Tile), len(t.B))
}

type Config struct {
	Name       string
	Key        *ecdsa.PrivateKey
	WitnessKey ed25519.PrivateKey
	PoolSize   int
	Cache      string

	Backend Backend
	Lock    LockBackend
	Log     *slog.Logger

	Roots         *x509util.PEMCertPool
	NotAfterStart time.Time
	NotAfterLimit time.Time
}

var ErrLogExists = errors.New("checkpoint already exist, refusing to initialize log")

func CreateLog(ctx context.Context, config *Config) error {
	logID, err := logIDFromKey(config.Key)
	if err != nil {
		return fmt.Errorf("couldn't compute log ID: %w", err)
	}

	if _, err := config.Lock.Fetch(ctx, logID); err == nil {
		return ErrLogExists
	}
	if _, err := config.Backend.Fetch(ctx, "checkpoint"); err == nil {
		return fmt.Errorf("checkpoint missing from database but present in object storage")
	}

	cacheRead, cacheWrite, err := initCache(config.Cache)
	if err != nil {
		return fmt.Errorf("couldn't initialize cache database: %w", err)
	}
	if err := cacheRead.Close(); err != nil {
		return fmt.Errorf("couldn't close cache database: %w", err)
	}
	if err := cacheWrite.Close(); err != nil {
		return fmt.Errorf("couldn't close cache database: %w", err)
	}

	timestamp := timeNowUnixMilli()
	tree, err := hashTreeHead(0, nil, timestamp)
	if err != nil {
		return fmt.Errorf("couldn't compute empty tree head: %w", err)
	}
	checkpoint, err := signTreeHead(config, tree)
	if err != nil {
		return fmt.Errorf("couldn't sign empty tree head: %w", err)
	}

	if err := config.Lock.Create(ctx, logID, checkpoint); err != nil {
		return fmt.Errorf("couldn't create checkpoint in lock database: %w", err)
	}
	if err := config.Backend.Upload(ctx, "checkpoint", checkpoint, optsCheckpoint); err != nil {
		return fmt.Errorf("couldn't upload checkpoint: %w", err)
	}

	config.Log.InfoContext(ctx, "created log", "timestamp", timestamp,
		"logID", base64.StdEncoding.EncodeToString(logID[:]))
	return nil
}

func logIDFromKey(key *ecdsa.PrivateKey) ([sha256.Size]byte, error) {
	pkix, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("couldn't marshal public key: %w", err)
	}
	return sha256.Sum256(pkix), nil
}

func hashTreeHead(n int64, r tlog.HashReader, t int64) (treeWithTimestamp, error) {
	rootHash, err := tlog.TreeHash(n, r)
	if err != nil {
		return treeWithTimestamp{}, fmtErrorf("couldn't compute tree hash: %w", err)
	}
	return treeWithTimestamp{Tree: tlog.Tree{N: n, Hash: rootHash}, Time: t}, nil
}

func LoadLog(ctx context.Context, config *Config) (*Log, error) {
	logID, err := logIDFromKey(config.Key)
	if err != nil {
		return nil, fmt.Errorf("couldn't compute log ID: %w", err)
	}

	// Load the checkpoint from the lock database. If we crashed during
	// serialization, the one in the lock database is going to be the latest.
	lock, err := config.Lock.Fetch(ctx, logID)
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch checkpoint from lock database: %w", err)
	}
	config.Log.DebugContext(ctx, "loaded checkpoint", "checkpoint", lock.Bytes())
	c, timestamp, err := openCheckpoint(config, lock.Bytes())
	if err != nil {
		return nil, fmt.Errorf("couldn't open checkpoint: %w", err)
	}

	// Load the checkpoint from the object storage backend, verify it, and
	// compare it to the lock checkpoint.
	sth, err := config.Backend.Fetch(ctx, "checkpoint")
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch checkpoint from object storage: %w", err)
	}
	config.Log.DebugContext(ctx, "loaded checkpoint from object storage", "checkpoint", sth)
	c1, _, err := openCheckpoint(config, sth)
	if err != nil {
		return nil, fmt.Errorf("couldn't open checkpoint from object storage: %w", err)
	}
	switch {
	case c1.N == c.N && c1.Hash != c.Hash:
		return nil, fmt.Errorf("checkpoint hash mismatch: %x != %x", c1.Hash, c.Hash)
	case c1.N > c.N:
		return nil, fmt.Errorf("checkpoint in object storage is newer than lock checkpoint: %d > %d", c1.N, c.N)
	case c1.N < c.N:
		// It's possible that we crashed between committing a new checkpoint to
		// the lock backend and uploading it to the object storage backend.
		// Apply the staged tiles before continuing.
		config.Log.WarnContext(ctx, "checkpoint in object storage is older than lock checkpoint",
			"old_size", c1.N, "size", c.N)
		if _, err := config.Backend.Fetch(ctx, legacyStagingPath(c.Tree)); err == nil {
			return nil, fmt.Errorf("legacy staging path exists, terminate Sunlight cleanly before upgrading")
		}
		stagedUploads, err := fetchAndDecompress(ctx, config.Backend, stagingPath(c.Tree))
		if err != nil {
			return nil, fmt.Errorf("couldn't fetch staged uploads: %w", err)
		}
		if err := applyStagedUploads(ctx, config, stagedUploads); err != nil {
			return nil, fmt.Errorf("couldn't apply staged uploads: %w", err)
		}
	}

	cacheRead, cacheWrite, err := initCache(config.Cache)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize cache database: %w", err)
	}

	// Fetch the tiles on the right edge, and verify them against the checkpoint.
	edgeTiles := make(map[int]tileWithBytes)
	if c.N > 0 {
		// Fetch the right-most edge tiles by reading the last leaf.
		// TileHashReader will fetch and verify the right tiles as a
		// side-effect.
		if _, err := tlog.TileHashReader(c.Tree, &tileReader{
			fetch: func(key string) ([]byte, error) {
				return config.Backend.Fetch(ctx, key)
			},
			saveTiles: func(tiles []tlog.Tile, data [][]byte) {
				for i, tile := range tiles {
					if t, ok := edgeTiles[tile.L]; !ok || t.N < tile.N || (t.N == tile.N && t.W < tile.W) {
						edgeTiles[tile.L] = tileWithBytes{tile, data[i]}
					}
				}
			}}).ReadHashes([]int64{tlog.StoredHashIndex(0, c.N-1)}); err != nil {
			return nil, fmt.Errorf("couldn't fetch right edge tiles: %w", err)
		}

		// Fetch the right-most data tile.
		dataTile := edgeTiles[0]
		dataTile.L = -1
		dataTile.B, err = fetchAndDecompress(ctx, config.Backend, dataTile.Path())
		if err != nil {
			return nil, fmt.Errorf("couldn't fetch right edge data tile: %w", err)
		}
		edgeTiles[-1] = dataTile

		// Verify the data tile against the level 0 tile.
		b := edgeTiles[-1].B
		start := sunlight.TileWidth * dataTile.N
		for i := start; i < start+int64(dataTile.W); i++ {
			e, rest, err := sunlight.ReadTileLeaf(b)
			if err != nil {
				return nil, fmt.Errorf("invalid data tile %v: %w", dataTile.Tile, err)
			}
			b = rest

			got := tlog.RecordHash(e.MerkleTreeLeaf())
			exp, err := tlog.HashFromTile(edgeTiles[0].Tile, edgeTiles[0].B, tlog.StoredHashIndex(0, i))
			if err != nil {
				return nil, fmt.Errorf("couldn't extract hash for leaf %d: %w", i, err)
			}
			if got != exp {
				return nil, fmt.Errorf("tile leaf entry %d hashes to %v, level 0 hash is %v", i, got, exp)
			}
		}
	}
	for _, t := range edgeTiles {
		config.Log.DebugContext(ctx, "edge tile", "tile", t)
	}

	config.Log.InfoContext(ctx, "loaded log", "logID", base64.StdEncoding.EncodeToString(logID[:]),
		"size", c.N, "timestamp", timestamp)

	m := initMetrics()
	m.TreeSize.Set(float64(c.N))
	m.TreeTime.Set(float64(timestamp))
	m.ConfigRoots.Set(float64(len(config.Roots.RawCertificates())))
	m.ConfigStart.Set(float64(config.NotAfterStart.Unix()))
	m.ConfigEnd.Set(float64(config.NotAfterLimit.Unix()))

	return &Log{
		c:              config,
		logID:          logID,
		m:              m,
		tree:           treeWithTimestamp{c.Tree, timestamp},
		lockCheckpoint: lock,
		edgeTiles:      edgeTiles,
		cacheRead:      cacheRead,
		currentPool:    newPool(),
		cacheWrite:     cacheWrite,
		issuers:        make(map[[32]byte]bool),
	}, nil
}

func openCheckpoint(config *Config, b []byte) (sunlight.Checkpoint, int64, error) {
	v1, err := sunlight.NewRFC6962Verifier(config.Name, config.Key.Public())
	if err != nil {
		return sunlight.Checkpoint{}, 0, fmt.Errorf("couldn't construct verifier: %w", err)
	}
	vk, err := note.NewEd25519VerifierKey(config.Name, config.WitnessKey.Public().(ed25519.PublicKey))
	if err != nil {
		return sunlight.Checkpoint{}, 0, fmt.Errorf("couldn't construct verifier key: %w", err)
	}
	v2, err := note.NewVerifier(vk)
	if err != nil {
		return sunlight.Checkpoint{}, 0, fmt.Errorf("couldn't construct Ed25519 verifier: %w", err)
	}
	n, err := note.Open(b, note.VerifierList(v1, v2))
	if err != nil {
		return sunlight.Checkpoint{}, 0, fmt.Errorf("couldn't verify checkpoint signature: %w", err)
	}
	var timestamp int64
	var v1Found, v2Found bool
	for _, sig := range n.Sigs {
		switch sig.Hash {
		case v1.KeyHash():
			v1Found = true
			timestamp, err = sunlight.RFC6962SignatureTimestamp(sig)
			if err != nil {
				return sunlight.Checkpoint{}, 0, fmt.Errorf("couldn't extract timestamp: %w", err)
			}
		case v2.KeyHash():
			v2Found = true
		}
	}
	if !v1Found || !v2Found {
		return sunlight.Checkpoint{}, 0, errors.New("missing verifier signature")
	}
	c, err := sunlight.ParseCheckpoint(n.Text)
	if err != nil {
		return sunlight.Checkpoint{}, 0, fmt.Errorf("couldn't parse checkpoint: %w", err)
	}

	if now := timeNowUnixMilli(); now < timestamp {
		return sunlight.Checkpoint{}, 0, fmt.Errorf("current time %d is before checkpoint time %d", now, timestamp)
	}
	if c.Origin != config.Name {
		return sunlight.Checkpoint{}, 0, fmt.Errorf("checkpoint name is %q, not %q", c.Origin, config.Name)
	}
	if c.Extension != "" {
		return sunlight.Checkpoint{}, 0, fmt.Errorf("unexpected checkpoint extension %q", c.Extension)
	}

	return c, timestamp, nil
}

var timeNowUnixMilli = func() int64 { return time.Now().UnixMilli() }

// Backend is an object storage. It is dedicated to a single log instance.
//
// It can be eventually consistent, but writes must be durable once they return.
//
// The Upload and Fetch methods must be usable concurrently.
type Backend interface {
	// Upload writes the value for a key. Upload is expected to retry transient
	// errors, and only return an error for unrecoverable errors. When Upload
	// returns, the object must be fully persisted. opts may be nil.
	Upload(ctx context.Context, key string, data []byte, opts *UploadOptions) error

	// Fetch returns the value for a key.
	Fetch(ctx context.Context, key string) ([]byte, error)

	// Discard suggests to the backend that the key can be deleted.
	Discard(ctx context.Context, key string) error

	// Metrics returns the metrics to register for this log. The metrics should
	// not be shared by any other logs.
	Metrics() []prometheus.Collector
}

// UploadOptions are used as part of the Backend.Upload method, and are
// marshaled to JSON and stored in the staging bundles.
type UploadOptions struct {
	// ContentType is the MIME type of the data. If empty, defaults to
	// "application/octet-stream".
	ContentType string

	// Compressed is true if the data is compressed with gzip.
	Compressed bool

	// Immutable is true if the data is never changed after being uploaded.
	// Note that the same value may still be re-uploaded, and must succeed.
	// [Backend.Discard] can still be used on immutable entries.
	Immutable bool
}

var optsHashTile = &UploadOptions{Immutable: true}
var optsDataTile = &UploadOptions{Compressed: true, Immutable: true}
var optsStaging = &UploadOptions{Compressed: true, Immutable: true}
var optsIssuer = &UploadOptions{ContentType: "application/pkix-cert", Immutable: true}
var optsCheckpoint = &UploadOptions{ContentType: "text/plain; charset=utf-8"}

var ErrLogNotFound = errors.New("log not found")

// A LockBackend is a database that supports compare-and-swap operations.
//
// The behavior of calls with the same logID must be serializable and have
// read-after-write consistency, even across processes and restarts, and write
// operations must be durable once they return. Calls with different logID
// values don't need to be consistent.
//
// It is shared across multiple Log instances, and is used only to store the
// latest checkpoint before making it publicly available.
//
// All its methods must be usable concurrently.
type LockBackend interface {
	// Fetch obtains the current checkpoint for a given log, as well as the data
	// necessary to perform a compare-and-swap operation.
	//
	// It must return ErrLogNotFound if the log doesn't exist.
	Fetch(ctx context.Context, logID [sha256.Size]byte) (LockedCheckpoint, error)

	// Replace uploads a new checkpoint, atomically checking that the old
	// checkpoint is the provided one, and returning the new one. Replace is
	// expected to retry transient errors, and only return an error for
	// unrecoverable errors (such as a conflict).
	Replace(ctx context.Context, old LockedCheckpoint, new []byte) (LockedCheckpoint, error)

	// Create uploads a new checkpoint, atomically checking that none exist for
	// the log yet.
	Create(ctx context.Context, logID [sha256.Size]byte, new []byte) error

	// Since a LockBackend is intended to be shared across logs, its metrics
	// should be collected by the application, not by the Log.
}

// A LockedCheckpoint is a checkpoint, along with the backend-specific
// information necessary to perform a compare-and-swap operation.
type LockedCheckpoint interface {
	Bytes() []byte
}

type tileReader struct {
	fetch     func(key string) ([]byte, error)
	saveTiles func(tiles []tlog.Tile, data [][]byte)
}

func (r *tileReader) Height() int {
	return sunlight.TileHeight
}

func (r *tileReader) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	for _, t := range tiles {
		b, err := r.fetch(sunlight.TilePath(t))
		if err != nil {
			return nil, err
		}
		data = append(data, b)
	}
	return data, nil
}

func (r *tileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) { r.saveTiles(tiles, data) }

// PendingLogEntry is a subset of sunlight.LogEntry that was not yet sequenced,
// so doesn't have an index or timestamp.
type PendingLogEntry struct {
	Certificate    []byte
	IsPrecert      bool
	IssuerKeyHash  [32]byte
	Issuers        [][]byte
	PreCertificate []byte
}

func (e *PendingLogEntry) asLogEntry(idx, timestamp int64) *sunlight.LogEntry {
	fingerprints := make([][32]byte, 0, len(e.Issuers))
	for _, i := range e.Issuers {
		fingerprints = append(fingerprints, sha256.Sum256(i))
	}
	return &sunlight.LogEntry{
		Certificate:       e.Certificate,
		IsPrecert:         e.IsPrecert,
		IssuerKeyHash:     e.IssuerKeyHash,
		ChainFingerprints: fingerprints,
		PreCertificate:    e.PreCertificate,
		LeafIndex:         idx,
		Timestamp:         timestamp,
	}
}

type cacheHash [16]byte // birthday bound of 2⁴⁸ entries with collision chance 2⁻³²

func computeCacheHash(Certificate []byte, IsPrecert bool, IssuerKeyHash [32]byte) cacheHash {
	b := &cryptobyte.Builder{}
	if !IsPrecert {
		b.AddUint16(0 /* entry_type = x509_entry */)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(Certificate)
		})
	} else {
		b.AddUint16(1 /* entry_type = precert_entry */)
		b.AddBytes(IssuerKeyHash[:])
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(Certificate)
		})
	}
	h := sha256.Sum256(b.BytesOrPanic())
	return cacheHash(h[:16])
}

type pool struct {
	pendingLeaves []*PendingLogEntry
	byHash        map[cacheHash]waitEntryFunc

	// done is closed when the pool has been sequenced and
	// the results below are ready.
	done chan struct{}

	err error
	// firstLeafIndex is the 0-based index of pendingLeaves[0] in the tree, and
	// every following entry is sequenced contiguously.
	firstLeafIndex int64
	// timestamp is both the STH and the SCT timestamp.
	// "The timestamp MUST be at least as recent as the most recent SCT
	// timestamp in the tree." RFC 6962, Section 3.5.
	timestamp int64
}

type waitEntryFunc func(ctx context.Context) (*sunlight.LogEntry, error)

func newPool() *pool {
	return &pool{
		done:   make(chan struct{}),
		byHash: make(map[cacheHash]waitEntryFunc),
	}
}

var errPoolFull = fmtErrorf("rate limited")

// addLeafToPool adds leaf to the current pool, unless it is found in a
// deduplication cache. It returns a function that will wait until the pool is
// sequenced and return the sequenced leaf, as well as the source of the
// sequenced leaf (pool or cache if deduplicated, sequencer otherwise).
func (l *Log) addLeafToPool(ctx context.Context, leaf *PendingLogEntry) (f waitEntryFunc, source string) {
	// We could marginally more efficiently do uploadIssuer after checking the
	// caches, but it's simpler for the the block below to be under a single
	// poolMu lock, and uploadIssuer goes to the network so we don't want to
	// cause poolMu contention.
	for _, issuer := range leaf.Issuers {
		if err := l.uploadIssuer(ctx, issuer); err != nil {
			l.c.Log.ErrorContext(ctx, "failed to upload issuer", "err", err)
			return func(ctx context.Context) (*sunlight.LogEntry, error) {
				return nil, fmtErrorf("failed to upload issuer: %w", err)
			}, "issuer"
		}
	}

	l.poolMu.Lock()
	defer l.poolMu.Unlock()
	p := l.currentPool
	h := computeCacheHash(leaf.Certificate, leaf.IsPrecert, leaf.IssuerKeyHash)
	if f, ok := p.byHash[h]; ok {
		return f, "pool"
	}
	if f, ok := l.inSequencing[h]; ok {
		return f, "pool"
	}
	if leaf, err := l.cacheGet(leaf); err != nil {
		return func(ctx context.Context) (*sunlight.LogEntry, error) {
			return nil, fmtErrorf("deduplication cache get failed: %w", err)
		}, "cache"
	} else if leaf != nil {
		return func(ctx context.Context) (*sunlight.LogEntry, error) {
			return leaf, nil
		}, "cache"
	}
	n := len(p.pendingLeaves)
	if l.c.PoolSize > 0 && n >= l.c.PoolSize {
		return func(ctx context.Context) (*sunlight.LogEntry, error) {
			return nil, errPoolFull
		}, "ratelimit"
	}
	p.pendingLeaves = append(p.pendingLeaves, leaf)
	f = func(ctx context.Context) (*sunlight.LogEntry, error) {
		select {
		case <-ctx.Done():
			return nil, fmtErrorf("context canceled while waiting for sequencing: %w", ctx.Err())
		case <-p.done:
			if p.err != nil {
				return nil, p.err
			}
			if p.timestamp == 0 {
				panic("internal error: pool is ready but result is missing")
			}
			idx := p.firstLeafIndex + int64(n)
			return leaf.asLogEntry(idx, p.timestamp), nil
		}
	}
	p.byHash[h] = f
	return f, "sequencer"
}

func (l *Log) uploadIssuer(ctx context.Context, issuer []byte) error {
	fingerprint := sha256.Sum256(issuer)

	l.issuersMu.RLock()
	found := l.issuers[fingerprint]
	l.issuersMu.RUnlock()
	if found {
		return nil
	}

	l.issuersMu.Lock()
	defer l.issuersMu.Unlock()

	if l.issuers[fingerprint] {
		return nil
	}

	path := fmt.Sprintf("issuer/%x", fingerprint)
	l.c.Log.InfoContext(ctx, "observed new issuer", "path", path)

	// First we try to download and check the issuer from the backend.
	// If it's not there, we upload it.

	old, err := l.c.Backend.Fetch(ctx, path)
	if err != nil {
		upErr := l.c.Backend.Upload(ctx, path, issuer, optsIssuer)
		l.c.Log.InfoContext(ctx, "uploaded issuer", "path", path, "err", upErr, "fetchErr", err, "size", len(issuer))
		if upErr != nil {
			return fmtErrorf("upload error: %w; fetch error: %v", upErr, err)
		}
	} else {
		if !bytes.Equal(old, issuer) {
			return fmtErrorf("invalid existing issuer: %x", old)
		}
	}

	l.issuers[fingerprint] = true
	l.m.Issuers.Set(float64(len(l.issuers)))
	return nil
}

func (l *Log) RunSequencer(ctx context.Context, period time.Duration) (err error) {
	// If the sequencer stops, return errors for all pending and future leaves.
	defer func() {
		l.poolMu.Lock()
		defer l.poolMu.Unlock()
		l.currentPool.err = err
		close(l.currentPool.done)
	}()

	// Randomly stagger the sequencers to avoid conflicting for resources.
	if !testing.Testing() {
		time.Sleep(time.Duration(mathrand.Int64N(int64(period))))
	}

	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := l.sequence(ctx); err != nil {
				return err
			}
		}
	}
}

// sequenceTimeout is the maximum time a whole sequencing can take, but
// non-fatal network operations (staging bundle and checkpoint uploads) are
// subject to strictTimeout, as we'd rather fail a pool than accumulate backlog.
const sequenceTimeout = 15 * time.Second
const strictTimeout = 1 * time.Second

var errFatal = errors.New("fatal sequencing error")

func (l *Log) sequence(ctx context.Context) error {
	l.poolMu.Lock()
	p := l.currentPool
	l.currentPool = newPool()
	l.inSequencing = p.byHash
	l.poolMu.Unlock()

	err := l.sequencePool(ctx, p)

	// Once sequencePool returns, the entries are either in the deduplication
	// cache or finalized with an error. In the latter case, we don't want
	// a resubmit to deduplicate against the failed sequencing.
	l.poolMu.Lock()
	l.inSequencing = nil
	l.poolMu.Unlock()

	return err
}

func (l *Log) sequencePool(ctx context.Context, p *pool) (err error) {
	oldSize := l.tree.N
	start := time.Now()
	seqLog := l.c.Log.With("old_tree_size", oldSize,
		"entries", len(p.pendingLeaves), "start", start)
	defer prometheus.NewTimer(l.m.SeqDuration).ObserveDuration()
	defer func() {
		if err != nil {
			p.err = err
			seqLog.ErrorContext(ctx, "pool sequencing failed",
				"elapsed", time.Since(start), "err", err)
			l.m.SeqCount.With(prometheus.Labels{"error": errorCategory(err)}).Inc()

			// Non-fatal errors are delivered to the requests waiting on this
			// pool, but do not break the sequencer loop.
			if !errors.Is(err, errFatal) {
				err = nil
			}
		} else {
			l.m.SeqCount.With(prometheus.Labels{"error": ""}).Inc()
		}
		l.m.SeqPoolSize.Observe(float64(len(p.pendingLeaves)))

		close(p.done)
	}()

	ctx, cancel := context.WithTimeout(ctx, sequenceTimeout)
	defer cancel()

	timestamp := timeNowUnixMilli()
	if timestamp <= l.tree.Time {
		return fmt.Errorf("%w: time did not progress! %d -> %d", errFatal, l.tree.Time, timestamp)
	}

	var tileUploads []*uploadAction
	edgeTiles := maps.Clone(l.edgeTiles)
	var dataTile []byte
	// Load the current partial data tile, if any.
	if t, ok := edgeTiles[-1]; ok && t.W < sunlight.TileWidth {
		dataTile = bytes.Clone(t.B)
	}
	newHashes := make(map[int64]tlog.Hash)
	hashReader := l.hashReader(newHashes)
	n := l.tree.N
	var sequencedLeaves []*sunlight.LogEntry
	for _, leaf := range p.pendingLeaves {
		leaf := leaf.asLogEntry(n, timestamp)
		sequencedLeaves = append(sequencedLeaves, leaf)
		oldTileSize := len(dataTile)
		dataTile = sunlight.AppendTileLeaf(dataTile, leaf)
		l.m.SeqLeafSize.Observe(float64(len(dataTile) - oldTileSize))

		// Compute the new tree hashes and add them to the hashReader overlay
		// (we will use them later to insert more leaves and finally to produce
		// the new tiles).
		hashes, err := tlog.StoredHashes(n, leaf.MerkleTreeLeaf(), hashReader)
		if err != nil {
			return fmtErrorf("couldn't compute new hashes for leaf %d: %w", n, err)
		}
		for i, h := range hashes {
			id := tlog.StoredHashIndex(0, n) + int64(i)
			newHashes[id] = h
		}

		n++

		// If the data tile is full, stage it.
		if n%sunlight.TileWidth == 0 {
			tile := tlog.TileForIndex(sunlight.TileHeight, tlog.StoredHashIndex(0, n-1))
			tile.L = -1
			edgeTiles[-1] = tileWithBytes{tile, dataTile}

			gzipData, err := compress(dataTile)
			if err != nil {
				return fmtErrorf("couldn't compress data tile: %w", err)
			}
			l.c.Log.DebugContext(ctx, "staging full data tile", "tree_size", n,
				"tile", tile, "size", len(dataTile), "gzip_size", len(gzipData))
			l.m.SeqDataTileSize.Observe(float64(len(dataTile)))
			l.m.SeqDataTileGzipSize.Observe(float64(len(gzipData)))

			tileUploads = append(tileUploads, &uploadAction{
				sunlight.TilePath(tile), gzipData, optsDataTile})
			dataTile = nil
		}
	}

	// Stage leftover partial data tile, if any.
	if n != l.tree.N && n%sunlight.TileWidth != 0 {
		tile := tlog.TileForIndex(sunlight.TileHeight, tlog.StoredHashIndex(0, n-1))
		tile.L = -1
		edgeTiles[-1] = tileWithBytes{tile, dataTile}
		gzipData, err := compress(dataTile)
		if err != nil {
			return fmtErrorf("couldn't compress data tile: %w", err)
		}
		l.c.Log.DebugContext(ctx, "staging partial data tile", "tree_size", n,
			"tile", tile, "size", len(dataTile), "gzip_size", len(gzipData))
		l.m.SeqDataTileSize.Observe(float64(len(dataTile)))
		l.m.SeqDataTileGzipSize.Observe(float64(len(gzipData)))
		tileUploads = append(tileUploads, &uploadAction{
			sunlight.TilePath(tile), gzipData, optsDataTile})
	}

	// Produce and stage new tree tiles.
	tiles := tlog.NewTiles(sunlight.TileHeight, l.tree.N, n)
	for _, tile := range tiles {
		data, err := tlog.ReadTileData(tile, hashReader)
		if err != nil {
			return fmtErrorf("couldn't generate tile %v: %w", tile, err)
		}
		// Assuming NewTilesForSize produces tiles in order, this tile should
		// always be further right than the one in edgeTiles, but double check.
		if t0, ok := edgeTiles[tile.L]; !ok || t0.N < tile.N || (t0.N == tile.N && t0.W < tile.W) {
			edgeTiles[tile.L] = tileWithBytes{tile, data}
		}
		l.c.Log.DebugContext(ctx, "staging tree tile", "old_tree_size", oldSize,
			"tree_size", n, "tile", tile, "size", len(data))
		tileUploads = append(tileUploads, &uploadAction{
			sunlight.TilePath(tile), data, optsHashTile})
	}

	if testingOnlyPauseSequencing != nil {
		testingOnlyPauseSequencing()
	}

	tree, err := hashTreeHead(n, hashReader, timestamp)
	if err != nil {
		return fmtErrorf("couldn't compute tree head: %w", err)
	}

	// Upload tiles to staging, where they can be recovered by LoadLog if we
	// crash right after updating the lock database. See also
	// https://github.com/FiloSottile/sunlight/issues/11.
	stagedUploads, err := marshalStagedUploads(tileUploads)
	if err != nil {
		return fmtErrorf("couldn't marshal staged uploads: %w", err)
	}
	stagingPath := stagingPath(tree.Tree)
	// Don't upload an empty staging bundle, as it would have the same path of
	// the previous one, but different (empty) content. Note that LoadLog might
	// end up re-uploading the tiles from the previous one, which is harmless.
	if len(tileUploads) > 0 {
		gzipData, err := compress(stagedUploads)
		if err != nil {
			return fmtErrorf("couldn't compress staged uploads: %w", err)
		}
		l.c.Log.DebugContext(ctx, "uploading staged tiles", "old_tree_size", oldSize,
			"tree_size", tree.N, "path", stagingPath, "size", len(stagedUploads), "gzip_size", len(gzipData))
		ctxStrict, cancel := context.WithTimeout(ctx, strictTimeout)
		defer cancel()
		if err := l.c.Backend.Upload(ctxStrict, stagingPath, gzipData, optsStaging); err != nil {
			return fmtErrorf("couldn't upload staged tiles: %w", err)
		}
	}

	checkpoint, err := signTreeHead(l.c, tree)
	if err != nil {
		return fmtErrorf("couldn't sign checkpoint: %w", err)
	}
	l.c.Log.DebugContext(ctx, "uploading checkpoint", "size", len(checkpoint))
	newLock, err := l.c.Lock.Replace(ctx, l.lockCheckpoint, checkpoint)
	if err != nil {
		// This is a critical error, since we don't know the state of the
		// checkpoint in the database at this point. Bail and let LoadLog get us
		// to a good state after restart.
		return fmt.Errorf("%w: couldn't upload checkpoint to database: %w", errFatal, err)
	}

	// At this point the pool is fully serialized: new entries were persisted to
	// object storage (in staging) and the checkpoint was committed to the
	// database. If we were to crash after this, recovery would be clean from
	// database and object storage.
	p.timestamp = timestamp
	p.firstLeafIndex = l.tree.N
	l.tree = tree
	l.lockCheckpoint = newLock
	l.edgeTiles = edgeTiles

	// Use applyStagedUploads instead of going over tileUploads directly, to
	// exercise the same code path as LoadLog.
	if err := applyStagedUploads(ctx, l.c, stagedUploads); err != nil {
		// This is also fatal, since we can't continue leaving behind missing
		// tiles. The next run of sequence would not upload them again, while
		// LoadLog will retry uploading them from the staging bundle.
		return fmtErrorf("%w: couldn't upload a tile: %w", errFatal, err)
	}

	ctxStrict, cancel := context.WithTimeout(ctx, strictTimeout)
	defer cancel()
	if err := l.c.Backend.Upload(ctxStrict, "checkpoint", checkpoint, optsCheckpoint); err != nil {
		// Return an error so we don't produce SCTs that, although safely
		// serialized, wouldn't be part of a publicly visible tree.
		return fmtErrorf("couldn't upload checkpoint to object storage: %w", err)
	}

	// Once the checkpoint is uploaded to object storage, we can safely delete the
	// staging bundle, if any. No need to fail the sequencing if this fails.
	if len(tileUploads) > 0 {
		if err := l.c.Backend.Discard(ctx, stagingPath); err != nil {
			l.c.Log.ErrorContext(ctx, "staging bundle discard failed",
				"tree_size", tree.N, "err", err)
			l.m.StagingDiscardErrors.Inc()
		}
	}

	// At this point if the cache put fails, there's no reason to return errors
	// to users. The only consequence of cache false negatives are duplicated
	// leaves anyway. In fact, an error might cause the clients to resumbit,
	// producing more cache false negatives and duplicates.
	if err := l.cachePut(sequencedLeaves); err != nil {
		l.c.Log.ErrorContext(ctx, "cache put failed",
			"tree_size", tree.N, "entries", len(p.pendingLeaves), "err", err)
		l.m.CachePutErrors.Inc()
	}

	for _, t := range edgeTiles {
		l.c.Log.DebugContext(ctx, "edge tile", "tile", t)
	}
	seqLog.Info("sequenced pool", "tree_size", tree.N,
		"tiles", len(tileUploads), "timestamp", timestamp,
		"elapsed", time.Since(start))
	l.m.SeqTiles.Add(float64(len(tileUploads)))
	l.m.TreeSize.Set(float64(tree.N))
	l.m.TreeTime.Set(float64(timestamp) / 1000)

	return nil
}

var testingOnlyPauseSequencing func()

type uploadAction struct {
	key  string
	data []byte
	opts *UploadOptions
}

func marshalStagedUploads(uploads []*uploadAction) ([]byte, error) {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, u := range uploads {
		opts, err := json.Marshal(u.opts)
		if err != nil {
			return nil, fmtErrorf("couldn't marshal upload options: %w", err)
		}
		if err := writer.WriteHeader(&tar.Header{
			Name:       u.key,
			Size:       int64(len(u.data)),
			PAXRecords: map[string]string{"SUNLIGHT.opts": string(opts)},
		}); err != nil {
			return nil, fmtErrorf("error writing tar header: %w", err)
		}
		if _, err := writer.Write(u.data); err != nil {
			return nil, fmtErrorf("error writing tar data: %w", err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, fmtErrorf("error closing tar writer: %w", err)
	}
	return buffer.Bytes(), nil
}

func applyStagedUploads(ctx context.Context, config *Config, stagedUploads []byte) error {
	g, gctx := errgroup.WithContext(ctx)
	reader := tar.NewReader(bytes.NewReader(stagedUploads))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmtErrorf("error reading tar header: %w", err)
		}
		key := header.Name
		optsBytes, ok := header.PAXRecords["SUNLIGHT.opts"]
		if !ok {
			return fmtErrorf("missing SUNLIGHT.opts in tar header")
		}
		opts := &UploadOptions{}
		if err := json.Unmarshal([]byte(optsBytes), opts); err != nil {
			return fmtErrorf("couldn't unmarshal upload options: %w", err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			return fmtErrorf("error reading tar data: %w", err)
		}
		g.Go(func() error {
			return config.Backend.Upload(gctx, key, data, opts)
		})
	}
	return g.Wait()
}

func stagingPath(tree tlog.Tree) string {
	// We don't segment the path like in [sunlight.TilePath], because old
	// staging bundles are deleted from the local backend (where it would be
	// important not to make a directory listing too long).
	return fmt.Sprintf("staging/%d-%s", tree.N, hex.EncodeToString(tree.Hash[:]))
}

func legacyStagingPath(tree tlog.Tree) string {
	// Encode size in three digit chunks like [sunlight.TilePath].
	n := tree.N
	nStr := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		nStr = fmt.Sprintf("x%03d/%s", n%1000, nStr)
	}

	return fmt.Sprintf("staging/%s/%s", nStr, hex.EncodeToString(tree.Hash[:]))
}

// signTreeHead signs the tree and returns a c2sp.org/checkpoint.
func signTreeHead(c *Config, tree treeWithTimestamp) (checkpoint []byte, err error) {
	sthBytes, err := ct.SerializeSTHSignatureInput(ct.SignedTreeHead{
		Version:        ct.V1,
		TreeSize:       uint64(tree.N),
		Timestamp:      uint64(tree.Time),
		SHA256RootHash: ct.SHA256Hash(tree.Hash),
	})
	if err != nil {
		return nil, fmtErrorf("couldn't serialize STH signature input: %w", err)
	}

	// We compute the signature here and inject it in a fixed note.Signer to
	// avoid a risky serialize-deserialize loop, and to control the timestamp.

	treeHeadSignature, err := digitallySign(c.Key, sthBytes)
	if err != nil {
		return nil, fmtErrorf("couldn't produce signature: %w", err)
	}

	// struct {
	//     uint64 timestamp;
	//     TreeHeadSignature signature;
	// } RFC6962NoteSignature;
	var b cryptobyte.Builder
	b.AddUint64(uint64(tree.Time))
	b.AddBytes(treeHeadSignature)
	sig, err := b.Bytes()
	if err != nil {
		return nil, fmtErrorf("couldn't encode RFC6962NoteSignature: %w", err)
	}

	v, err := sunlight.NewRFC6962Verifier(c.Name, c.Key.Public())
	if err != nil {
		return nil, fmtErrorf("couldn't construct verifier: %w", err)
	}
	rs := &injectedSigner{v, sig}

	ws, err := newEd25519Signer(c.Name, c.WitnessKey)
	if err != nil {
		return nil, fmtErrorf("couldn't construct Ed25519 signer: %w", err)
	}

	signers := []note.Signer{rs, ws}
	// Randomize the order to enforce forward-compatible client behavior.
	mathrand.Shuffle(len(signers), func(i, j int) { signers[i], signers[j] = signers[j], signers[i] })

	signedNote, err := note.Sign(&note.Note{
		Text: sunlight.FormatCheckpoint(sunlight.Checkpoint{
			Origin: c.Name,
			Tree:   tlog.Tree{N: tree.N, Hash: tree.Hash},
		}),
		UnverifiedSigs: greaseSignatures(c.Name),
	}, signers...)
	if err != nil {
		return nil, fmtErrorf("couldn't sign note: %w", err)
	}
	return signedNote, nil
}

type injectedSigner struct {
	v   note.Verifier
	sig []byte
}

func (s *injectedSigner) Sign(msg []byte) ([]byte, error) { return s.sig, nil }
func (s *injectedSigner) Name() string                    { return s.v.Name() }
func (s *injectedSigner) KeyHash() uint32                 { return s.v.KeyHash() }
func (s *injectedSigner) Verifier() note.Verifier         { return s.v }

// digitallySign produces an encoded digitally-signed signature.
//
// It reimplements tls.CreateSignature and tls.Marshal from
// github.com/google/certificate-transparency-go/tls, in part to limit
// complexity and in part because tls.CreateSignature expects non-pointer
// {rsa,ecdsa}.PrivateKey types, which is unusual.
//
// We use deterministic RFC 6979 ECDSA signatures so that when fetching a
// previous SCT's timestamp and index from the deduplication cache, the new SCT
// we produce is identical.
func digitallySign(k *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	sig, err := k.Sign(nil, h[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint8(4 /* hash = sha256 */)
	b.AddUint8(3 /* signature = ecdsa */)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(sig)
	})
	return b.Bytes()
}

// greaseSignatures produces unverifiable but otherwise correct signatures.
// Clients MUST ignore unknown signatures, and including some "grease" ones
// ensures they do.
func greaseSignatures(name string) []note.Signature {
	g1 := make([]byte, 5+mathrand.IntN(100))
	rand.Read(g1)
	g2 := make([]byte, 5+mathrand.IntN(100))
	h := sha256.Sum256(append([]byte("grease\n"), byte(mathrand.IntN(100))))
	copy(g2[:4], h[:])
	rand.Read(g2[4:])
	signatures := []note.Signature{
		{Name: "grease.invalid", Hash: binary.BigEndian.Uint32(g1), Base64: base64.StdEncoding.EncodeToString(g1)},
		{Name: name, Hash: binary.BigEndian.Uint32(g2), Base64: base64.StdEncoding.EncodeToString(g2)},
	}
	mathrand.Shuffle(len(signatures), func(i, j int) { signatures[i], signatures[j] = signatures[j], signatures[i] })
	return signatures
}

// newEd25519Signer can be removed once note.NewEd25519SignerKey is added.
func newEd25519Signer(name string, key ed25519.PrivateKey) (note.Signer, error) {
	vk, err := note.NewEd25519VerifierKey(name, key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	v, err := note.NewVerifier(vk)
	if err != nil {
		return nil, err
	}
	return &ed25519Signer{v, key}, nil
}

type ed25519Signer struct {
	v note.Verifier
	k ed25519.PrivateKey
}

func (s *ed25519Signer) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.k, msg), nil }
func (s *ed25519Signer) Name() string                    { return s.v.Name() }
func (s *ed25519Signer) KeyHash() uint32                 { return s.v.KeyHash() }
func (s *ed25519Signer) Verifier() note.Verifier         { return s.v }

// hashReader returns hashes from l.edgeTiles and from overlay.
func (l *Log) hashReader(overlay map[int64]tlog.Hash) tlog.HashReaderFunc {
	return func(indexes []int64) ([]tlog.Hash, error) {
		list := make([]tlog.Hash, 0, len(indexes))
		for _, id := range indexes {
			if h, ok := overlay[id]; ok {
				list = append(list, h)
				continue
			}
			t := l.edgeTiles[tlog.TileForIndex(sunlight.TileHeight, id).L]
			h, err := tlog.HashFromTile(t.Tile, t.B, id)
			if err != nil {
				return nil, fmt.Errorf("index %d not in overlay and %w", id, err)
			}
			list = append(list, h)
		}
		return list, nil
	}
}

func compress(data []byte) ([]byte, error) {
	b := &bytes.Buffer{}
	w := gzip.NewWriter(b)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

const maxCompressRatio = 100

func fetchAndDecompress(ctx context.Context, backend Backend, key string) ([]byte, error) {
	data, err := backend.Fetch(ctx, key)
	if err != nil {
		return nil, err
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	maxSize := int64(len(data)) * maxCompressRatio
	return io.ReadAll(io.LimitReader(r, maxSize))
}
