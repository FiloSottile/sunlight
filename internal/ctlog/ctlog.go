package ctlog

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"sync"
	"time"

	"filippo.io/litetlog/internal/tlogx"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509util"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/sync/errgroup"
)

type Log struct {
	c     *Config
	logID [sha256.Size]byte

	tree treeWithTimestamp
	// edgeTiles is a map from level to the right-most tile of that level.
	edgeTiles map[int]tileWithBytes

	// poolMu is held for the entire duration of addLeafToPool, and by
	// sequencePool while swapping the pool. This guarantees that addLeafToPool
	// will never add to a pool that already started sequencing.
	poolMu      sync.Mutex
	currentPool *pool
}

type treeWithTimestamp struct {
	tlog.Tree
	Time int64
}

type tileWithBytes struct {
	tlog.Tile
	B []byte
}

type Config struct {
	Name string
	Key  crypto.Signer

	Backend Backend
	Log     *slog.Logger

	Roots         *x509util.PEMCertPool
	NotAfterStart time.Time
	NotAfterLimit time.Time
}

func CreateLog(ctx context.Context, config *Config) error {
	_, err := config.Backend.Fetch(ctx, "checkpoint")
	if err == nil {
		return errors.New("STH file already exist, refusing to initialize log")
	}

	pkix, err := x509.MarshalPKIXPublicKey(config.Key.Public())
	if err != nil {
		return err
	}
	logID := sha256.Sum256(pkix)

	tree := treeWithTimestamp{tlog.Tree{}, timeNowUnixMilli()}
	checkpoint, err := signTreeHead(config.Name, logID, config.Key, tree)
	if err != nil {
		return err
	}

	return config.Backend.Upload(ctx, "checkpoint", checkpoint)
}

func LoadLog(ctx context.Context, config *Config) (*Log, error) {
	pkix, err := x509.MarshalPKIXPublicKey(config.Key.Public())
	if err != nil {
		return nil, err
	}
	logID := sha256.Sum256(pkix)

	sth, err := config.Backend.Fetch(ctx, "checkpoint")
	if err != nil {
		return nil, err
	}
	v, err := tlogx.NewRFC6962Verifier(config.Name, config.Key.Public())
	if err != nil {
		return nil, err
	}
	var timestamp int64
	v.Timestamp = func(t uint64) { timestamp = int64(t) }
	n, err := note.Open(sth, note.VerifierList(v))
	if err != nil {
		return nil, err
	}
	c, err := tlogx.ParseCheckpoint(n.Text)
	if err != nil {
		return nil, err
	}

	if now := timeNowUnixMilli(); now < timestamp {
		return nil, fmt.Errorf("current time %d is before STH time %d", now, timestamp)
	}
	if c.Origin != config.Name {
		return nil, fmt.Errorf("STH name is %q, not %q", c.Origin, config.Name)
	}
	tree := tlog.Tree{N: c.N, Hash: c.Hash}
	if c.Extension != "" {
		return nil, fmt.Errorf("unexpected STH extension %q", c.Extension)
	}

	edgeTiles := make(map[int]tileWithBytes)
	if c.N > 0 {
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
			return nil, err
		}

		dataTile := edgeTiles[0]
		dataTile.L = -1
		dataTile.B, err = config.Backend.Fetch(ctx, dataTile.Path())
		if err != nil {
			return nil, err
		}
		edgeTiles[-1] = dataTile

		b := edgeTiles[-1].B
		start := tileWidth * dataTile.N
		for i := start; i < start+int64(dataTile.W); i++ {
			e, rest, err := ReadTileLeaf(b)
			if err != nil {
				return nil, fmt.Errorf("invalid data tile %v", dataTile)
			}
			b = rest

			got := tlog.RecordHash(e.MerkleTreeLeaf())
			exp, err := tlog.HashFromTile(edgeTiles[0].Tile, edgeTiles[0].B, tlog.StoredHashIndex(0, i))
			if err != nil {
				return nil, err
			}
			if got != exp {
				return nil, fmt.Errorf("tile leaf entry %d hashes to %v, level 0 hash is %v", i, got, exp)
			}
		}
	}

	return &Log{
		c:           config,
		logID:       logID,
		tree:        treeWithTimestamp{tree, timestamp},
		edgeTiles:   edgeTiles,
		currentPool: &pool{done: make(chan struct{})},
	}, nil
}

var timeNowUnixMilli = func() int64 { return time.Now().UnixMilli() }

// Backend is a strongly consistent object storage.
type Backend interface {
	// Upload is expected to retry transient errors, and only return an error
	// for unrecoverable errors. When Upload returns, the object must be fully
	// persisted. Upload can be called concurrently.
	Upload(ctx context.Context, key string, data []byte) error

	// Fetch can be called concurrently.
	Fetch(ctx context.Context, key string) ([]byte, error)
}

const tileHeight = 10
const tileWidth = 1 << tileHeight

type tileReader struct {
	fetch     func(key string) ([]byte, error)
	saveTiles func(tiles []tlog.Tile, data [][]byte)
}

func (r *tileReader) Height() int {
	return tileHeight
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
	e.timestampedEntry(b)
	return b.BytesOrPanic()
}

func (e *SequencedLogEntry) timestampedEntry(b *cryptobyte.Builder) {
	b.AddUint64(uint64(e.Timestamp))
	if !e.IsPrecert {
		b.AddUint8(0 /* entry_type = x509_entry */)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.Certificate)
		})
	} else {
		b.AddUint8(1 /* entry_type = precert_entry */)
		b.AddBytes(e.IssuerKeyHash[:])
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.Certificate)
		})
	}
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(e.Extensions())
	})
}

func (e *SequencedLogEntry) Extensions() []byte {
	b := &cryptobyte.Builder{}
	b.AddUint8(0 /* extension_type = leaf_index */)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		addUint40(b, uint64(e.LeafIndex))
	})
	return b.BytesOrPanic()
}

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
	e.timestampedEntry(b)
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

// addLeafToPool adds leaf to the current pool, and returns a function that will
// wait until the pool is sequenced and returns the sequenced leaf.
func (l *Log) addLeafToPool(leaf *LogEntry) func(ctx context.Context) (*SequencedLogEntry, error) {
	l.poolMu.Lock()
	defer l.poolMu.Unlock()
	p := l.currentPool
	n := len(p.pendingLeaves)
	// TODO: check if the pool is full.
	p.pendingLeaves = append(p.pendingLeaves, leaf)
	return func(ctx context.Context) (*SequencedLogEntry, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.done:
			if p.err != nil {
				return nil, p.err
			}
			return &SequencedLogEntry{
				LogEntry:  *leaf,
				LeafIndex: p.firstLeafIndex + int64(n),
				Timestamp: p.timestamp,
			}, nil
		}
	}
}

func (l *Log) RunSequencer(ctx context.Context) (err error) {
	defer func() {
		l.poolMu.Lock()
		p := l.currentPool
		l.poolMu.Unlock()
		p.err = err
		close(p.done)
	}()
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			l.poolMu.Lock()
			p := l.currentPool
			l.currentPool = &pool{done: make(chan struct{})}
			l.poolMu.Unlock()
			if err := l.sequencePool(ctx, p); err != nil {
				p.err = err
				close(p.done)
				return err
			}
		}
	}
}

const sequenceTimeout = 5 * time.Second

func (l *Log) sequencePool(ctx context.Context, p *pool) error {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, sequenceTimeout)
	defer cancel()
	g, gctx := errgroup.WithContext(ctx)
	defer g.Wait()

	timestamp := timeNowUnixMilli()
	if timestamp <= l.tree.Time {
		return fmt.Errorf("time did not progress! %d -> %d", l.tree.Time, timestamp)
	}

	edgeTiles := maps.Clone(l.edgeTiles)
	var dataTile []byte
	if t, ok := edgeTiles[-1]; ok && t.W < tileWidth {
		dataTile = bytes.Clone(t.B)
	}
	newHashes := make(map[int64]tlog.Hash)
	hashReader := l.hashReader(newHashes)
	n := l.tree.N
	for _, leaf := range p.pendingLeaves {
		leaf := &SequencedLogEntry{LogEntry: *leaf, Timestamp: timestamp, LeafIndex: n}
		hashes, err := tlog.StoredHashes(n, leaf.MerkleTreeLeaf(), hashReader)
		if err != nil {
			return fmt.Errorf("couldn't fetch stored hashes for leaf %d: %w", n, err)
		}
		for i, h := range hashes {
			id := tlog.StoredHashIndex(0, n) + int64(i)
			newHashes[id] = h
		}
		dataTile = append(dataTile, leaf.TileLeaf()...)

		n++

		if n%tileWidth == 0 { // Data tile is full.
			tile := tlog.TileForIndex(tileHeight, tlog.StoredHashIndex(0, n-1))
			tile.L = -1
			data := dataTile
			edgeTiles[-1] = tileWithBytes{tile, data}
			g.Go(func() error { return l.c.Backend.Upload(gctx, tile.Path(), data) })
			dataTile = nil
		}
	}

	// Upload partial data tile.
	if n%tileWidth != 0 {
		tile := tlog.TileForIndex(tileHeight, tlog.StoredHashIndex(0, n-1))
		tile.L = -1
		edgeTiles[-1] = tileWithBytes{tile, dataTile}
		g.Go(func() error { return l.c.Backend.Upload(gctx, tile.Path(), dataTile) })
	}

	tiles := tlog.NewTiles(tileHeight, l.tree.N, n)
	for _, tile := range tiles {
		data, err := tlog.ReadTileData(tile, hashReader)
		if err != nil {
			return err
		}
		tile := tile
		if t, ok := edgeTiles[tile.L]; !ok || t.N < tile.N || (t.N == tile.N && t.W < tile.W) {
			edgeTiles[tile.L] = tileWithBytes{tile, data}
		}
		g.Go(func() error { return l.c.Backend.Upload(gctx, tile.Path(), data) })
	}

	if err := g.Wait(); err != nil {
		return err
	}

	rootHash, err := tlog.TreeHash(n, hashReader)
	if err != nil {
		return err
	}
	tree := treeWithTimestamp{Tree: tlog.Tree{N: n, Hash: rootHash}, Time: timestamp}

	checkpoint, err := signTreeHead(l.c.Name, l.logID, l.c.Key, tree)
	if err != nil {
		return err
	}
	if err := l.c.Backend.Upload(ctx, "checkpoint", checkpoint); err != nil {
		// TODO: this is a critical error to handle, since if the STH actually
		// got committed before the error we need to make very very sure we
		// don't sign an inconsistent version when we retry.
		return err
	}

	l.c.Log.Info("sequenced pool", "elapsed", time.Since(start), "entries", n-l.tree.N)

	defer close(p.done)
	p.timestamp = timestamp
	p.firstLeafIndex = l.tree.N
	l.tree = tree
	l.edgeTiles = edgeTiles

	return nil
}

// signTreeHead signs the tree and returns a checkpoint according to
// c2sp.org/checkpoint.
func signTreeHead(name string, logID [sha256.Size]byte, privKey crypto.Signer, tree treeWithTimestamp) (checkpoint []byte, err error) {
	sthBytes, err := ct.SerializeSTHSignatureInput(ct.SignedTreeHead{
		Version:        ct.V1,
		TreeSize:       uint64(tree.N),
		Timestamp:      uint64(tree.Time),
		SHA256RootHash: ct.SHA256Hash(tree.Hash),
	})
	if err != nil {
		return nil, err
	}

	// We compute the signature here and inject it in a fixed note.Signer to
	// avoid a risky serialize-deserialize loop, and to control the timestamp.

	treeHeadSignature, err := digitallySign(privKey, sthBytes)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	signer, err := tlogx.NewInjectedSigner(name, 0x05, logID[:], sig)
	if err != nil {
		return nil, err
	}
	return note.Sign(&note.Note{
		Text: tlogx.MarshalCheckpoint(tlogx.Checkpoint{
			Origin: name,
			N:      tree.N, Hash: tree.Hash,
		}),
	}, signer)
}

// digitallySign produces an encoded digitally-signed signature.
//
// It reimplements tls.CreateSignature and tls.Marshal from
// github.com/google/certificate-transparency-go/tls, in part to limit
// complexity and in part because tls.CreateSignature expects non-pointer
// {rsa,ecdsa}.PrivateKey types, which is unusual.
func digitallySign(k crypto.Signer, msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	sig, err := k.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint8(4 /* hash = sha256 */)
	switch k.Public().(type) {
	case *rsa.PublicKey:
		b.AddUint8(1 /* signature = rsa */)
	case *ecdsa.PublicKey:
		b.AddUint8(3 /* signature = ecdsa */)
	default:
		return nil, fmt.Errorf("unsupported key type %T", k.Public())
	}
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(sig)
	})
	return b.Bytes()
}

func (l *Log) hashReader(overlay map[int64]tlog.Hash) tlog.HashReaderFunc {
	return func(indexes []int64) ([]tlog.Hash, error) {
		list := make([]tlog.Hash, 0, len(indexes))
		for _, id := range indexes {
			if h, ok := overlay[id]; ok {
				list = append(list, h)
				continue
			}
			t := l.edgeTiles[tlog.TileForIndex(tileHeight, id).L]
			h, err := tlog.HashFromTile(t.Tile, t.B, id)
			if err != nil {
				return nil, err
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
	var entryType uint8
	var extensions cryptobyte.String
	if !s.ReadUint64(&timestamp) || !s.ReadUint8(&entryType) || timestamp > math.MaxInt64 {
		return nil, s, errors.New("invalid data tile")
	}
	e.Timestamp = int64(timestamp)
	switch entryType {
	case 0: // x509_entry
		if !s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.Certificate)) ||
			!s.ReadUint16LengthPrefixed(&extensions) {
			return nil, s, errors.New("invalid data tile")
		}
	case 1: // precert_entry
		e.IsPrecert = true
		if !s.CopyBytes(e.IssuerKeyHash[:]) ||
			!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.Certificate)) ||
			!s.ReadUint16LengthPrefixed(&extensions) ||
			!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.PreCertificate)) ||
			!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.PrecertSigningCert)) {
			return nil, s, errors.New("invalid data tile")
		}
	default:
		return nil, s, fmt.Errorf("invalid data tile %v: unknown type %d", tile, entryType)
	}
	var extensionType uint8
	var extensionData cryptobyte.String
	if !extensions.ReadUint8(&extensionType) || extensionType != 0 ||
		!extensions.ReadUint16LengthPrefixed(&extensionData) ||
		!readUint48(&extensionData, &e.LeafIndex) || !extensionData.Empty() ||
		!extensions.Empty() {
		return nil, s, errors.New("invalid data tile extensions")
	}
	return e, s, nil
}

// addUint40 appends a big-endian, 40-bit value to the byte string.
func addUint40(b *cryptobyte.Builder, v uint64) {
	b.AddBytes([]byte{byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// readUint40 decodes a big-endian, 40-bit value into out and advances over it.
// It reports whether the read was successful.
func readUint48(s *cryptobyte.String, out *int64) bool {
	var v []byte
	if !s.ReadBytes(&v, 5) {
		return false
	}
	*out = int64(v[0])<<32 | int64(v[1])<<24 | int64(v[2])<<16 | int64(v[3])<<8 | int64(v[4])
	return true
}
