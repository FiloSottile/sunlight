package ctlog

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"filippo.io/litetlog/internal/tlogx"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type Log struct {
	name    string
	logID   [sha256.Size]byte
	privKey crypto.PrivateKey
	backend Backend

	// TODO: add a lock when using these outside the sequencer.
	tree   tlog.Tree
	hashes map[int64]tlog.Hash
	leaves map[int64][]byte

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
	Upload(key string, data []byte) error
}

const tileHeight = 10

type pool struct {
	pendingLeaves [][]byte

	// done is closed when the pool has been sequenced and
	// the results below are ready.
	done chan struct{}

	firstLeafIndex int64
	// The timestamp MUST be at least as recent as the most recent SCT timestamp
	// in the tree. RFC 6962, Section 3.5.
	sthTimestamp int64
}

// addLeafToPool adds leaf to the current pool, and returns a function that will
// wait until the pool is sequenced and returns the index of the leaf.
func (l *Log) addLeafToPool(leaf []byte) func() (id int64) {
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

func (l *Log) sequencePool() error {
	l.poolMu.Lock()
	p := l.currentPool
	l.currentPool = &pool{done: make(chan struct{})}
	l.poolMu.Unlock()

	newHashes := make(map[int64]tlog.Hash)
	hashReader := l.hashReader(newHashes)
	n := l.tree.N
	for _, leaf := range p.pendingLeaves {
		hashes, err := tlog.StoredHashes(n, leaf, hashReader)
		if err != nil {
			return err
		}
		for i, h := range hashes {
			id := tlog.StoredHashIndex(0, n) + int64(i)
			newHashes[id] = h
		}
		n++
	}

	tiles := tlog.NewTiles(tileHeight, l.tree.N, n)
	for _, tile := range tiles {
		data, err := tlog.ReadTileData(tile, hashReader)
		if err != nil {
			return err
		}

		// TODO: do these uploads in parallel.
		if err := l.backend.Upload(tile.Path(), data); err != nil {
			return err
		}
	}

	rootHash, err := tlog.TreeHash(n, hashReader)
	if err != nil {
		return err
	}
	newTree := tlog.Tree{N: n, Hash: rootHash}

	checkpoint, sthTimestamp, err := l.signTreeHead(newTree)
	if err != nil {
		return err
	}
	if err := l.backend.Upload("sth", checkpoint); err != nil {
		// TODO: this is a critical error to handle, since if the STH actually
		// got committed before the error we need to make very very sure we
		// don't sign an inconsistent version when we retry.
		return err
	}

	p.sthTimestamp = sthTimestamp
	p.firstLeafIndex = l.tree.N
	l.tree = newTree
	for id, h := range newHashes {
		l.hashes[id] = h
	}
	// TODO: cull l.hashes and l.leaves to only the right edge tiles.
	close(p.done)

	return nil
}

// signTreeHead signs the tree and returns a checkpoint according to
// c2sp.org/checkpoint.
func (l *Log) signTreeHead(tree tlog.Tree) (checkpoint []byte, timestamp int64, err error) {
	sthTimestamp := time.Now().UnixMilli()
	sth := &ct.SignedTreeHead{
		Version:        ct.V1,
		TreeSize:       uint64(tree.N),
		Timestamp:      uint64(sthTimestamp),
		SHA256RootHash: ct.SHA256Hash(tree.Hash),
	}
	sthBytes, err := ct.SerializeSTHSignatureInput(*sth)
	if err != nil {
		return nil, 0, err
	}
	// We compute the signature here and inject it in a fixed note.Signer to
	// avoid a risky serialize-deserialize loop, and to control the timestamp.
	digitallySigned, err := tls.CreateSignature(l.privKey, tls.SHA256, sthBytes)
	if err != nil {
		return nil, 0, err
	}
	sig, err := tls.Marshal(struct {
		Timestamp uint64
		Signature tls.DigitallySigned
	}{uint64(sthTimestamp), digitallySigned})
	if err != nil {
		return nil, 0, err
	}
	signer, err := tlogx.NewInjectedSigner(l.name, 0x05, l.logID[:], sig)
	if err != nil {
		return nil, 0, err
	}
	n, err := note.Sign(&note.Note{
		Text: tlogx.MarshalCheckpoint(tlogx.Checkpoint{
			Origin: l.name,
			N:      tree.N, Hash: tree.Hash,
		}),
	}, signer)
	if err != nil {
		return nil, 0, err
	}
	return n, sthTimestamp, nil
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
