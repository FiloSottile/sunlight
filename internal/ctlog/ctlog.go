package ctlog

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"sync"
	"time"

	"crawshaw.io/sqlite"
	"filippo.io/litetlog/internal/rfc6979"
	"filippo.io/litetlog/internal/tlogx"
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

	issuersMu sync.RWMutex
	issuers   *x509util.PEMCertPool
}

type treeWithTimestamp struct {
	tlog.Tree
	Time int64
}

type tileWithBytes struct {
	tlog.Tile
	B []byte
}

func (t tileWithBytes) String() string {
	return fmt.Sprintf("%s#%d", t.Path(), len(t.B))
}

type Config struct {
	Name string
	Key  *ecdsa.PrivateKey

	Cache string

	Backend Backend
	Lock    LockBackend
	Log     *slog.Logger

	Roots         *x509util.PEMCertPool
	NotAfterStart time.Time
	NotAfterLimit time.Time
}

var ErrLogExists = errors.New("checkpoint already exist, refusing to initialize log")

func CreateLog(ctx context.Context, config *Config) error {
	pkix, err := x509.MarshalPKIXPublicKey(config.Key.Public())
	if err != nil {
		return fmt.Errorf("couldn't marshal public key: %w", err)
	}
	logID := sha256.Sum256(pkix)

	if _, err := config.Backend.Fetch(ctx, "checkpoint"); err == nil {
		return ErrLogExists
	}
	if _, err := config.Lock.Fetch(ctx, logID); err == nil {
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

	if err := config.Backend.Upload(ctx, "issuers.pem", []byte{}); err != nil {
		return fmt.Errorf("couldn't upload issuers.pem: %w", err)
	}

	timestamp := timeNowUnixMilli()
	tree := treeWithTimestamp{tlog.Tree{}, timestamp}
	checkpoint, err := signTreeHead(config.Name, logID, config.Key, tree)
	if err != nil {
		return fmt.Errorf("couldn't sign empty tree head: %w", err)
	}

	if err := config.Lock.Create(ctx, logID, checkpoint); err != nil {
		return fmt.Errorf("couldn't create checkpoint in lock database: %w", err)
	}
	if err := config.Backend.Upload(ctx, "checkpoint", checkpoint); err != nil {
		return fmt.Errorf("couldn't upload checkpoint: %w", err)
	}

	config.Log.InfoContext(ctx, "created log", "timestamp", timestamp,
		"logID", base64.StdEncoding.EncodeToString(logID[:]))
	return nil
}

func LoadLog(ctx context.Context, config *Config) (*Log, error) {
	pkix, err := x509.MarshalPKIXPublicKey(config.Key.Public())
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal public key: %w", err)
	}
	logID := sha256.Sum256(pkix)

	lock, err := config.Lock.Fetch(ctx, logID)
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch checkpoint from lock database: %w", err)
	}
	config.Log.DebugContext(ctx, "loaded checkpoint", "checkpoint", lock.Bytes())
	v, err := tlogx.NewRFC6962Verifier(config.Name, config.Key.Public())
	if err != nil {
		return nil, fmt.Errorf("couldn't construct verifier: %w", err)
	}
	var timestamp int64
	v.Timestamp = func(t uint64) { timestamp = int64(t) }
	n, err := note.Open(lock.Bytes(), note.VerifierList(v))
	if err != nil {
		return nil, fmt.Errorf("couldn't verify checkpoint signature: %w", err)
	}
	c, err := tlogx.ParseCheckpoint(n.Text)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse checkpoint: %w", err)
	}

	if now := timeNowUnixMilli(); now < timestamp {
		return nil, fmt.Errorf("current time %d is before checkpoint time %d", now, timestamp)
	}
	if c.Origin != config.Name {
		return nil, fmt.Errorf("checkpoint name for log ID is %q, not %q", c.Origin, config.Name)
	}
	tree := tlog.Tree{N: c.N, Hash: c.Hash}
	if c.Extension != "" {
		return nil, fmt.Errorf("unexpected checkpoint extension %q", c.Extension)
	}

	sth, err := config.Backend.Fetch(ctx, "checkpoint")
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch checkpoint: %w", err)
	}
	config.Log.DebugContext(ctx, "loaded checkpoint from object storage", "checkpoint", sth)
	v.Timestamp = func(t uint64) {}
	n1, err := note.Open(sth, note.VerifierList(v))
	if err != nil {
		return nil, fmt.Errorf("couldn't verify checkpoint signature: %w", err)
	}
	c1, err := tlogx.ParseCheckpoint(n1.Text)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse checkpoint: %w", err)
	}
	if c1.Origin != config.Name {
		return nil, fmt.Errorf("checkpoint name from object storage is %q, not %q", c1.Origin, config.Name)
	}
	if c1.N == c.N && c1.Hash != c.Hash {
		return nil, fmt.Errorf("checkpoint hash mismatch: %x != %x", c1.Hash, c.Hash)
	}
	if c1.N > c.N {
		return nil, fmt.Errorf("checkpoint in object storage is newer than lock checkpoint: %d > %d", c1.N, c.N)
	}
	if c1.N < c.N {
		// It's possible that we crashed between committing a new checkpoint to
		// the lock backend and uploading it to the object storage backend.
		// That's ok, as long as the rest of the tree load correctly against the
		// lock checkpoint.
		config.Log.WarnContext(ctx, "checkpoint in object storage is older than lock checkpoint",
			"old_size", c1.N, "size", c.N)
	}

	pemIssuers, err := config.Backend.Fetch(ctx, "issuers.pem")
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch issuers.pem: %w", err)
	}
	config.Log.DebugContext(ctx, "loaded issuers.pem", "pem", pemIssuers)
	issuers := x509util.NewPEMCertPool()
	if len(pemIssuers) > 0 && !issuers.AppendCertsFromPEM(pemIssuers) {
		return nil, errors.New("invalid issuers.pem")
	}

	cacheRead, cacheWrite, err := initCache(config.Cache)
	if err != nil {
		return nil, fmt.Errorf("couldn't initialize cache database: %w", err)
	}

	edgeTiles := make(map[int]tileWithBytes)
	if c.N > 0 {
		// Fetch the right-most edge tiles by reading the last leaf.
		// TileHashReader will fetch and verify the right tiles as a
		// side-effect.
		if _, err := tlog.TileHashReader(tree, &tileReader{
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
		dataTile.B, err = config.Backend.Fetch(ctx, dataTile.Path())
		if err != nil {
			return nil, fmt.Errorf("couldn't fetch right edge data tile: %w", err)
		}
		edgeTiles[-1] = dataTile

		// Verify the data tile against the level 0 tile.
		b := edgeTiles[-1].B
		start := tileWidth * dataTile.N
		for i := start; i < start+int64(dataTile.W); i++ {
			e, rest, err := ReadTileLeaf(b)
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
		"size", tree.N, "timestamp", timestamp, "issuers", len(issuers.RawCertificates()))

	m := initMetrics()
	m.TreeSize.Set(float64(tree.N))
	m.TreeTime.Set(float64(timestamp))
	m.Issuers.Set(float64(len(issuers.RawCertificates())))
	m.ConfigRoots.Set(float64(len(config.Roots.RawCertificates())))
	m.ConfigStart.Set(float64(config.NotAfterStart.Unix()))
	m.ConfigEnd.Set(float64(config.NotAfterLimit.Unix()))

	return &Log{
		c:              config,
		logID:          logID,
		m:              m,
		tree:           treeWithTimestamp{tree, timestamp},
		lockCheckpoint: lock,
		edgeTiles:      edgeTiles,
		cacheRead:      cacheRead,
		currentPool:    newPool(),
		cacheWrite:     cacheWrite,
		issuers:        issuers,
	}, nil
}

var timeNowUnixMilli = func() int64 { return time.Now().UnixMilli() }

// Backend is a strongly consistent object storage.
//
// It is dedicated to a single log instance.
type Backend interface {
	// Upload is expected to retry transient errors, and only return an error
	// for unrecoverable errors. When Upload returns, the object must be fully
	// persisted. Upload can be called concurrently.
	Upload(ctx context.Context, key string, data []byte) error

	// UploadCompressible is like Upload, but the data is compressible and
	// should be compressed before uploading if possible.
	UploadCompressible(ctx context.Context, key string, data []byte) error

	// Fetch can be called concurrently. It's expected to decompress any data
	// uploaded by UploadCompressible.
	Fetch(ctx context.Context, key string) ([]byte, error)

	// Metrics returns the metrics to register for this log. The metrics should
	// not be shared by any other logs.
	Metrics() []prometheus.Collector
}

// A LockBackend is a database that supports compare-and-swap operations.
//
// It is shared across multiple Log instances, and is used only to store the
// latest checkpoint before making it publicly available.
type LockBackend interface {
	// Fetch obtains the current checkpoint for a given log, as well as the data
	// necessary to perform a compare-and-swap operation.
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

const TileHeight = 8
const tileWidth = 1 << TileHeight

type tileReader struct {
	fetch     func(key string) ([]byte, error)
	saveTiles func(tiles []tlog.Tile, data [][]byte)
}

func (r *tileReader) Height() int {
	return TileHeight
}

func (r *tileReader) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	for _, t := range tiles {
		b, err := r.fetch(t.Path())
		if err != nil {
			return nil, err
		}
		data = append(data, b)
	}
	return data, nil
}

func (r *tileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) { r.saveTiles(tiles, data) }

type LogEntry struct {
	// Certificate is either the x509_entry or the tbs_certificate for precerts.
	Certificate []byte

	IsPrecert          bool
	IssuerKeyHash      [32]byte
	PreCertificate     []byte
	PrecertSigningCert []byte
}

// SignedEntry returns the entry_type and signed_entry fields of
// a RFC 6962 TimestampedEntry.
func (e *LogEntry) SignedEntry() []byte {
	// struct {
	//     LogEntryType entry_type;
	//     select(entry_type) {
	//         case x509_entry: ASN.1Cert;
	//         case precert_entry: PreCert;
	//     } signed_entry;
	// } SignedEntry;

	b := &cryptobyte.Builder{}
	if !e.IsPrecert {
		b.AddUint16(0 /* entry_type = x509_entry */)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.Certificate)
		})
	} else {
		b.AddUint16(1 /* entry_type = precert_entry */)
		b.AddBytes(e.IssuerKeyHash[:])
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.Certificate)
		})
	}
	return b.BytesOrPanic()
}

type cacheHash [16]byte // birthday bound of 2⁴⁸ entries with collision chance 2⁻³²

func (e *LogEntry) cacheHash() cacheHash {
	h := sha256.Sum256(e.SignedEntry())
	return cacheHash(h[:16])
}

type SequencedLogEntry struct {
	LogEntry
	LeafIndex int64
	Timestamp int64
}

// MerkleTreeLeaf returns a RFC 6962 MerkleTreeLeaf.
func (e *SequencedLogEntry) MerkleTreeLeaf() []byte {
	b := &cryptobyte.Builder{}
	b.AddUint8(0 /* version = v1 */)
	b.AddUint8(0 /* leaf_type = timestamped_entry */)
	b.AddUint64(uint64(e.Timestamp))
	b.AddBytes(e.SignedEntry())
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(e.Extensions())
	})
	return b.BytesOrPanic()
}

// Extensions returns the custom structure that's encoded in the
// SignedCertificateTimestamp and TimestampedEntry extensions field.
func (e *SequencedLogEntry) Extensions() []byte {
	// enum {
	//     leaf_index(0), (255)
	// } ExtensionType;
	//
	// struct {
	//     ExtensionType extension_type;
	//     opaque extension_data<0..2^16-1>;
	// } Extension;
	//
	// Extension CTExtensions<0..2^16-1>;
	//
	// uint8 uint40[5];
	// uint40 LeafIndex;

	b := &cryptobyte.Builder{}
	b.AddUint8(0 /* extension_type = leaf_index */)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		addUint40(b, uint64(e.LeafIndex))
	})
	return b.BytesOrPanic()
}

func ParseExtensions(extensions []byte) (leafIndex int64, err error) {
	b := cryptobyte.String(extensions)
	for !b.Empty() {
		var extensionType uint8
		var extension cryptobyte.String
		if !b.ReadUint8(&extensionType) || !b.ReadUint16LengthPrefixed(&extension) {
			return 0, errors.New("invalid extension")
		}
		if extensionType == 0 /* leaf_index */ {
			var leafIndex int64
			if !readUint40(&extension, &leafIndex) || !extension.Empty() {
				return 0, errors.New("invalid leaf_index extension")
			}
			return leafIndex, nil
		}
	}
	return 0, errors.New("missing leaf_index extension")
}

// TileLeaf returns the custom structure that's encoded in data tiles.
func (e *SequencedLogEntry) TileLeaf() []byte {
	// struct {
	//     TimestampedEntry timestamped_entry;
	//     select(entry_type) {
	//         case x509_entry: Empty;
	//         case precert_entry: PreCertExtraData;
	//     } extra_data;
	// } TileLeaf;
	//
	// struct {
	//     ASN.1Cert pre_certificate;
	//     opaque PrecertificateSigningCertificate<0..2^24-1>;
	// } PreCertExtraData;

	b := &cryptobyte.Builder{}
	b.AddUint64(uint64(e.Timestamp))
	b.AddBytes(e.SignedEntry())
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(e.Extensions())
	})
	if e.IsPrecert {
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.PreCertificate)
		})
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.PrecertSigningCert)
		})
	}
	return b.BytesOrPanic()
}

type pool struct {
	pendingLeaves []*LogEntry
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

type waitEntryFunc func(ctx context.Context) (*SequencedLogEntry, error)

func newPool() *pool {
	return &pool{
		done:   make(chan struct{}),
		byHash: make(map[cacheHash]waitEntryFunc),
	}
}

// addLeafToPool adds leaf to the current pool, unless it is found in a
// deduplication cache. It returns a function that will wait until the pool is
// sequenced and return the sequenced leaf, as well as the source of the
// sequenced leaf (pool or cache if deduplicated, sequencer otherwise).
func (l *Log) addLeafToPool(leaf *LogEntry) (f waitEntryFunc, source string) {
	l.poolMu.Lock()
	defer l.poolMu.Unlock()
	p := l.currentPool
	h := leaf.cacheHash()
	if f, ok := p.byHash[h]; ok {
		return f, "pool"
	}
	if f, ok := l.inSequencing[h]; ok {
		return f, "pool"
	}
	if leaf, err := l.cacheGet(leaf); err != nil {
		return func(ctx context.Context) (*SequencedLogEntry, error) {
			return nil, fmtErrorf("deduplication cache get failed: %w", err)
		}, "cache"
	} else if leaf != nil {
		return func(ctx context.Context) (*SequencedLogEntry, error) {
			return leaf, nil
		}, "cache"
	}
	// TODO: check if the pool is full.
	n := len(p.pendingLeaves)
	p.pendingLeaves = append(p.pendingLeaves, leaf)
	f = func(ctx context.Context) (*SequencedLogEntry, error) {
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
			return &SequencedLogEntry{
				LogEntry:  *leaf,
				LeafIndex: p.firstLeafIndex + int64(n),
				Timestamp: p.timestamp,
			}, nil
		}
	}
	p.byHash[h] = f
	return f, "sequencer"
}

func (l *Log) RunSequencer(ctx context.Context, period time.Duration) (err error) {
	// If the sequencer stops, return errors for all pending and future leaves.
	defer func() {
		l.poolMu.Lock()
		defer l.poolMu.Unlock()
		l.currentPool.err = err
		close(l.currentPool.done)
	}()

	t := time.NewTicker(period)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			l.c.Log.InfoContext(ctx, "sequencer stopped")
			return ctx.Err()
		case <-t.C:
			if err := l.sequence(ctx); err != nil {
				l.c.Log.ErrorContext(ctx, "fatal sequencing error", "err", err)
				return err
			}
		}
	}
}

const sequenceTimeout = 5 * time.Second

var errFatal = errors.New("fatal sequencing error")

func (l *Log) sequence(ctx context.Context) error {
	l.poolMu.Lock()
	p := l.currentPool
	l.currentPool = newPool()
	l.inSequencing = p.byHash
	l.poolMu.Unlock()

	return l.sequencePool(ctx, p)
}

func (l *Log) sequencePool(ctx context.Context, p *pool) (err error) {
	oldSize := l.tree.N
	defer prometheus.NewTimer(l.m.SeqDuration).ObserveDuration()
	defer func() {
		if err != nil {
			p.err = err
			l.c.Log.ErrorContext(ctx, "pool sequencing failed", "old_tree_size", oldSize,
				"entries", len(p.pendingLeaves), "err", err)
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

	var tileCount int
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, sequenceTimeout)
	defer cancel()
	g, gctx := errgroup.WithContext(ctx)
	defer g.Wait()

	timestamp := timeNowUnixMilli()
	if timestamp <= l.tree.Time {
		return errors.Join(errFatal, fmtErrorf("time did not progress! %d -> %d", l.tree.Time, timestamp))
	}

	edgeTiles := maps.Clone(l.edgeTiles)
	var dataTile []byte
	// Load the current partial data tile, if any.
	if t, ok := edgeTiles[-1]; ok && t.W < tileWidth {
		dataTile = bytes.Clone(t.B)
	}
	newHashes := make(map[int64]tlog.Hash)
	hashReader := l.hashReader(newHashes)
	n := l.tree.N
	var sequencedLeaves []*SequencedLogEntry
	for _, leaf := range p.pendingLeaves {
		leaf := &SequencedLogEntry{LogEntry: *leaf, Timestamp: timestamp, LeafIndex: n}
		sequencedLeaves = append(sequencedLeaves, leaf)
		leafData := leaf.TileLeaf()
		dataTile = append(dataTile, leafData...)
		l.m.SeqLeafSize.Observe(float64(len(leafData)))

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

		// If the data tile is full, upload it.
		if n%tileWidth == 0 {
			tile := tlog.TileForIndex(TileHeight, tlog.StoredHashIndex(0, n-1))
			tile.L = -1
			edgeTiles[-1] = tileWithBytes{tile, dataTile}
			l.c.Log.DebugContext(ctx, "uploading full data tile",
				"tree_size", n, "tile", tile, "size", len(dataTile))
			l.m.SeqDataTileSize.Observe(float64(len(dataTile)))
			tileCount++
			data := dataTile // data is captured by the g.Go function.
			g.Go(func() error { return l.c.Backend.UploadCompressible(gctx, tile.Path(), data) })
			dataTile = nil
		}
	}

	// Upload leftover partial data tile, if any.
	if n%tileWidth != 0 {
		tile := tlog.TileForIndex(TileHeight, tlog.StoredHashIndex(0, n-1))
		tile.L = -1
		edgeTiles[-1] = tileWithBytes{tile, dataTile}
		l.c.Log.DebugContext(ctx, "uploading partial data tile",
			"tree_size", n, "tile", tile, "size", len(dataTile))
		l.m.SeqDataTileSize.Observe(float64(len(dataTile)))
		tileCount++
		g.Go(func() error { return l.c.Backend.UploadCompressible(gctx, tile.Path(), dataTile) })
	}

	// Produce and upload new tree tiles.
	tiles := tlogx.NewTilesForSize(TileHeight, l.tree.N, n)
	for _, tile := range tiles {
		tile := tile // tile is captured by the g.Go function.
		data, err := tlog.ReadTileData(tile, hashReader)
		if err != nil {
			return fmtErrorf("couldn't generate tile %v: %w", tile, err)
		}
		// Assuming NewTilesForSize produces tiles in order, this tile should
		// always be further right than the one in edgeTiles, but double check.
		if t0, ok := edgeTiles[tile.L]; !ok || t0.N < tile.N || (t0.N == tile.N && t0.W < tile.W) {
			edgeTiles[tile.L] = tileWithBytes{tile, data}
		}
		l.c.Log.DebugContext(ctx, "uploading tree tile", "old_tree_size", oldSize,
			"tree_size", n, "tile", tile, "size", len(data))
		tileCount++
		g.Go(func() error { return l.c.Backend.Upload(gctx, tile.Path(), data) })
	}

	if err := g.Wait(); err != nil {
		return fmtErrorf("couldn't upload a tile: %w", err)
	}

	if testingOnlyPauseSequencing != nil {
		testingOnlyPauseSequencing()
	}

	rootHash, err := tlog.TreeHash(n, hashReader)
	if err != nil {
		return fmtErrorf("couldn't compute tree hash: %w", err)
	}
	tree := treeWithTimestamp{Tree: tlog.Tree{N: n, Hash: rootHash}, Time: timestamp}

	checkpoint, err := signTreeHead(l.c.Name, l.logID, l.c.Key, tree)
	if err != nil {
		return fmtErrorf("couldn't sign checkpoint: %w", err)
	}
	l.c.Log.DebugContext(ctx, "uploading checkpoint", "size", len(checkpoint))
	newLock, err := l.c.Lock.Replace(ctx, l.lockCheckpoint, checkpoint)
	if err != nil {
		// This is a critical error, since we don't know the state of the
		// checkpoint in the database at this point. Bail and let LoadLog get us
		// to a good state after restart.
		return errors.Join(errFatal, fmtErrorf("couldn't upload checkpoint to database: %w", err))
	}

	// At this point the pool is fully serialized: the new tree was uploaded to
	// object storage and the checkpoint was committed to the database. If the
	// checkpoint upload to object storage were to fail, we'd still be in a
	// consistent state and able to make progress. If we were to crash after
	// this, recovery would be clean from database and object storage.
	p.timestamp = timestamp
	p.firstLeafIndex = l.tree.N
	l.tree = tree
	l.lockCheckpoint = newLock
	l.edgeTiles = edgeTiles

	if err := l.c.Backend.Upload(ctx, "checkpoint", checkpoint); err != nil {
		// Return an error so we don't produce SCTs that, although safely
		// serialized, wouldn't be part of a publicly visible tree.
		return fmtErrorf("couldn't upload checkpoint to object storage: %w", err)
	}

	// At this point if the cache put fails, there's no reason to return errors
	// to users. The only consequence of cache false negatives are duplicated
	// leaves anyway. In fact, an error might cause the clients to resumbit,
	// producing more cache false negatives and duplicates.
	if err := l.cachePut(sequencedLeaves); err != nil {
		l.c.Log.ErrorContext(ctx, "cache put failed",
			"tree_size", tree.N, "entries", n-oldSize, "err", err)
		l.m.CachePutErrors.Inc()
	}

	for _, t := range edgeTiles {
		l.c.Log.DebugContext(ctx, "edge tile", "tile", t)
	}
	l.c.Log.Info("sequenced pool",
		"tree_size", tree.N, "entries", n-oldSize,
		"tiles", tileCount, "timestamp", timestamp,
		"elapsed", time.Since(start))
	l.m.SeqTiles.Add(float64(tileCount))
	l.m.TreeSize.Set(float64(tree.N))
	l.m.TreeTime.Set(float64(timestamp) / 1000)

	return nil
}

var testingOnlyPauseSequencing func()

// signTreeHead signs the tree and returns a checkpoint according to
// c2sp.org/checkpoint.
func signTreeHead(name string, logID [sha256.Size]byte, privKey *ecdsa.PrivateKey, tree treeWithTimestamp) (checkpoint []byte, err error) {
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

	treeHeadSignature, err := digitallySign(privKey, sthBytes)
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

	signer, err := tlogx.NewInjectedSigner(name, 0x05, logID[:], sig)
	if err != nil {
		return nil, fmtErrorf("couldn't construct signer: %w", err)
	}
	signedNote, err := note.Sign(&note.Note{
		Text: tlogx.MarshalCheckpoint(tlogx.Checkpoint{
			Origin: name,
			N:      tree.N, Hash: tree.Hash,
		}),
	}, signer)
	if err != nil {
		return nil, fmtErrorf("couldn't sign note: %w", err)
	}
	return signedNote, nil
}

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
	sig, err := rfc6979.Sign(k, h[:], crypto.SHA256)
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

// hashReader returns hashes from l.edgeTiles and from overlay.
func (l *Log) hashReader(overlay map[int64]tlog.Hash) tlog.HashReaderFunc {
	return func(indexes []int64) ([]tlog.Hash, error) {
		list := make([]tlog.Hash, 0, len(indexes))
		for _, id := range indexes {
			if h, ok := overlay[id]; ok {
				list = append(list, h)
				continue
			}
			t := l.edgeTiles[tlog.TileForIndex(TileHeight, id).L]
			h, err := tlog.HashFromTile(t.Tile, t.B, id)
			if err != nil {
				return nil, fmt.Errorf("index %d not in overlay and %w", id, err)
			}
			list = append(list, h)
		}
		return list, nil
	}
}

func ReadTileLeaf(tile []byte) (e *SequencedLogEntry, rest []byte, err error) {
	e = &SequencedLogEntry{}
	s := cryptobyte.String(tile)
	var timestamp uint64
	var entryType uint16
	var extensions cryptobyte.String
	if !s.ReadUint64(&timestamp) || !s.ReadUint16(&entryType) || timestamp > math.MaxInt64 {
		return nil, s, fmtErrorf("invalid data tile")
	}
	e.Timestamp = int64(timestamp)
	switch entryType {
	case 0: // x509_entry
		if !s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.Certificate)) ||
			!s.ReadUint16LengthPrefixed(&extensions) {
			return nil, s, fmtErrorf("invalid data tile x509_entry")
		}
	case 1: // precert_entry
		e.IsPrecert = true
		if !s.CopyBytes(e.IssuerKeyHash[:]) ||
			!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.Certificate)) ||
			!s.ReadUint16LengthPrefixed(&extensions) ||
			!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.PreCertificate)) ||
			!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.PrecertSigningCert)) {
			return nil, s, fmtErrorf("invalid data tile precert_entry")
		}
	default:
		return nil, s, fmtErrorf("invalid data tile: unknown type %d", entryType)
	}
	var extensionType uint8
	var extensionData cryptobyte.String
	if !extensions.ReadUint8(&extensionType) || extensionType != 0 ||
		!extensions.ReadUint16LengthPrefixed(&extensionData) ||
		!readUint40(&extensionData, &e.LeafIndex) || !extensionData.Empty() ||
		!extensions.Empty() {
		return nil, s, fmtErrorf("invalid data tile extensions")
	}
	return e, s, nil
}

// addUint40 appends a big-endian, 40-bit value to the byte string.
func addUint40(b *cryptobyte.Builder, v uint64) {
	b.AddBytes([]byte{byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// readUint40 decodes a big-endian, 40-bit value into out and advances over it.
// It reports whether the read was successful.
func readUint40(s *cryptobyte.String, out *int64) bool {
	var v []byte
	if !s.ReadBytes(&v, 5) {
		return false
	}
	*out = int64(v[0])<<32 | int64(v[1])<<24 | int64(v[2])<<16 | int64(v[3])<<8 | int64(v[4])
	return true
}
