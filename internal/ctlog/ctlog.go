package ctlog

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"golang.org/x/mod/sumdb/tlog"
)

type Log struct {
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

	sthTimestamp := time.Now().UnixMilli()
	sth := &ct.SignedTreeHead{
		Version:        ct.V1,
		TreeSize:       uint64(n),
		Timestamp:      uint64(sthTimestamp),
		SHA256RootHash: ct.SHA256Hash(rootHash),
		LogID:          l.logID,
	}
	sthBytes, err := ct.SerializeSTHSignatureInput(*sth)
	if err != nil {
		return err
	}
	sig, err := tls.CreateSignature(l.privKey, tls.SHA256, sthBytes)
	if err != nil {
		return err
	}
	sth.TreeHeadSignature = ct.DigitallySigned(sig)
	// TODO: upload STH.

	p.sthTimestamp = sthTimestamp
	p.firstLeafIndex = l.tree.N
	l.tree.N = n
	l.tree.Hash = rootHash
	for id, h := range newHashes {
		l.hashes[id] = h
	}
	// TODO: cull l.hashes and l.leaves to only the right edge tiles.
	close(p.done)

	return nil
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
