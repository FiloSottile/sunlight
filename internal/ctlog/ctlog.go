package ctlog

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"filippo.io/litetlog/internal/tlogx"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/sync/errgroup"
)

type Log struct {
	name    string
	logID   [sha256.Size]byte
	privKey crypto.PrivateKey
	backend Backend

	// TODO: add a lock when using these outside the sequencer.
	tree        tlog.Tree
	hashes      map[int64]tlog.Hash
	partialTile []byte // the current partial level -1 tile

	// poolMu is held for the entire duration of addLeafToPool, and by
	// sequencePool while swapping the pool. This guarantees that addLeafToPool
	// will never add to a pool that already started sequencing.
	poolMu      sync.Mutex
	currentPool *pool
}

// Backend is a strongly consistent object storage.
type Backend interface {
	// Upload is expected to retry transient errors, and only return an error
	// for unrecoverable errors. When Upload returns, the object must be fully
	// persisted. Upload can be called concurrently.
	Upload(ctx context.Context, key string, data []byte) error
}

const tileHeight = 10
const tileWidth = 1 << tileHeight

type logEntry struct {
	// cert is either the x509_entry or the tbs_certificate for precerts.
	cert []byte

	isPrecert          bool
	issuerKeyHash      [32]byte
	preCertificate     []byte
	precertSigningCert []byte
}

// merkleTreeLeaf returns a RFC 6962 MerkleTreeLeaf.
func (e *logEntry) merkleTreeLeaf(timestamp int64) []byte {
	b := &cryptobyte.Builder{}
	b.AddUint8(0 /* version = v1 */)
	b.AddUint8(0 /* leaf_type = timestamped_entry */)
	e.timestampedEntry(b, timestamp)
	return b.BytesOrPanic()
}

func (e *logEntry) timestampedEntry(b *cryptobyte.Builder, timestamp int64) {
	b.AddUint64(uint64(timestamp))
	if !e.isPrecert {
		b.AddUint8(0 /* entry_type = x509_entry */)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.cert)
		})
	} else {
		b.AddUint8(1 /* entry_type = precert_entry */)
		b.AddBytes(e.issuerKeyHash[:])
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.cert)
		})
	}
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		/* extensions */
	})
}

func (e *logEntry) tileLeaf(timestamp int64) []byte {
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
	e.timestampedEntry(b, timestamp)
	if e.isPrecert {
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.preCertificate)
		})
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.precertSigningCert)
		})
	}
	return b.BytesOrPanic()
}

type pool struct {
	pendingLeaves []*logEntry

	// done is closed when the pool has been sequenced and
	// the results below are ready.
	done chan struct{}

	// firstLeafIndex is the 0-based index of pendingLeaves[0] in the tree, and
	// every following entry is sequenced contiguously.
	firstLeafIndex int64
	// timestamp is both the STH and the SCT timestamp.
	// "The timestamp MUST be at least as recent as the most recent SCT
	// timestamp in the tree." RFC 6962, Section 3.5.
	timestamp int64
}

// addLeafToPool adds leaf to the current pool, and returns a function that will
// wait until the pool is sequenced and returns the index of the leaf.
func (l *Log) addLeafToPool(leaf *logEntry) func() (id int64) {
	l.poolMu.Lock()
	defer l.poolMu.Unlock()
	p := l.currentPool
	n := len(p.pendingLeaves)
	p.pendingLeaves = append(p.pendingLeaves, leaf)
	return func() int64 {
		<-p.done
		return p.firstLeafIndex + int64(n)
	}
}

const sequenceTimeout = 5 * time.Second

func (l *Log) sequencePool() error {
	l.poolMu.Lock()
	p := l.currentPool
	l.currentPool = &pool{done: make(chan struct{})}
	l.poolMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), sequenceTimeout)
	defer cancel()
	g, gctx := errgroup.WithContext(ctx)
	defer g.Wait()

	timestamp := time.Now().UnixMilli()

	newHashes := make(map[int64]tlog.Hash)
	newTile := bytes.Clone(l.partialTile)
	hashReader := l.hashReader(newHashes)
	n := l.tree.N
	for _, leaf := range p.pendingLeaves {
		hashes, err := tlog.StoredHashes(n, leaf.merkleTreeLeaf(timestamp), hashReader)
		if err != nil {
			return err
		}
		for i, h := range hashes {
			id := tlog.StoredHashIndex(0, n) + int64(i)
			newHashes[id] = h
		}
		newTile = append(newTile, leaf.tileLeaf(timestamp)...)

		n++

		if n%tileWidth == 0 { // Data tile is full.
			tile := tlog.TileForIndex(tileHeight, tlog.StoredHashIndex(0, n-1))
			tile.L = -1
			g.Go(func() error { return l.backend.Upload(gctx, tile.Path(), newTile) })
			newTile = nil
		}
	}

	// Upload partial data tile.
	if n%tileWidth != 0 {
		tile := tlog.TileForIndex(tileHeight, tlog.StoredHashIndex(0, n-1))
		tile.L = -1
		g.Go(func() error { return l.backend.Upload(gctx, tile.Path(), newTile) })
	}

	tiles := tlog.NewTiles(tileHeight, l.tree.N, n)
	for _, tile := range tiles {
		data, err := tlog.ReadTileData(tile, hashReader)
		if err != nil {
			return err
		}
		g.Go(func() error { return l.backend.Upload(gctx, tile.Path(), data) })
	}

	if err := g.Wait(); err != nil {
		return err
	}

	rootHash, err := tlog.TreeHash(n, hashReader)
	if err != nil {
		return err
	}
	newTree := tlog.Tree{N: n, Hash: rootHash}

	checkpoint, err := l.signTreeHead(newTree, timestamp)
	if err != nil {
		return err
	}
	if err := l.backend.Upload(ctx, "sth", checkpoint); err != nil {
		// TODO: this is a critical error to handle, since if the STH actually
		// got committed before the error we need to make very very sure we
		// don't sign an inconsistent version when we retry.
		return err
	}

	p.timestamp = timestamp
	p.firstLeafIndex = l.tree.N
	l.tree = newTree
	l.partialTile = newTile
	for id, h := range newHashes {
		l.hashes[id] = h
	}
	// TODO: cull l.hashes to only the right edge tiles.
	close(p.done)

	return nil
}

// signTreeHead signs the tree and returns a checkpoint according to
// c2sp.org/checkpoint.
func (l *Log) signTreeHead(tree tlog.Tree, timestamp int64) (checkpoint []byte, err error) {
	sth := &ct.SignedTreeHead{
		Version:        ct.V1,
		TreeSize:       uint64(tree.N),
		Timestamp:      uint64(timestamp),
		SHA256RootHash: ct.SHA256Hash(tree.Hash),
	}
	sthBytes, err := ct.SerializeSTHSignatureInput(*sth)
	if err != nil {
		return nil, err
	}
	// We compute the signature here and inject it in a fixed note.Signer to
	// avoid a risky serialize-deserialize loop, and to control the timestamp.
	digitallySigned, err := tls.CreateSignature(l.privKey, tls.SHA256, sthBytes)
	if err != nil {
		return nil, err
	}
	sig, err := tls.Marshal(struct {
		Timestamp uint64
		Signature tls.DigitallySigned
	}{uint64(timestamp), digitallySigned})
	if err != nil {
		return nil, err
	}
	signer, err := tlogx.NewInjectedSigner(l.name, 0x05, l.logID[:], sig)
	if err != nil {
		return nil, err
	}
	n, err := note.Sign(&note.Note{
		Text: tlogx.MarshalCheckpoint(tlogx.Checkpoint{
			Origin: l.name,
			N:      tree.N, Hash: tree.Hash,
		}),
	}, signer)
	if err != nil {
		return nil, err
	}
	return n, nil
}

func (l *Log) hashReader(overlay map[int64]tlog.Hash) tlog.HashReaderFunc {
	return func(indexes []int64) ([]tlog.Hash, error) {
		var list []tlog.Hash
		for _, id := range indexes {
			if h, ok := l.hashes[id]; ok {
				list = append(list, h)
				continue
			}
			if h, ok := overlay[id]; ok {
				list = append(list, h)
				continue
			}
			return nil, fmt.Errorf("internal error: requested unavailable hash %d", id)
		}
		return list, nil
	}
}
