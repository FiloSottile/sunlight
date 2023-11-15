package cttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"

	"filippo.io/litetlog/internal/ctlog"
	"filippo.io/litetlog/internal/tlogx"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type TestLog struct {
	Log    *ctlog.Log
	Config *ctlog.Config
	t      testing.TB
}

func NewEmptyTestLog(t testing.TB) *TestLog {
	backend := NewMemoryBackend(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ECDSA key: %s", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
	config := &ctlog.Config{Name: "example.com/TestLog", Key: key, Backend: backend,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	err = ctlog.CreateLog(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	log, err := ctlog.LoadLog(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return &TestLog{t: t,
		Log:    log,
		Config: config,
	}
}

func ReloadLog(t testing.TB, tl *TestLog) *TestLog {
	log, err := ctlog.LoadLog(context.Background(), tl.Config)
	if err != nil {
		t.Fatal(err)
	}
	return &TestLog{t: t,
		Log:    log,
		Config: tl.Config,
	}
}

func (tl *TestLog) CheckLog() (sthTimestamp int64) {
	t := tl.t
	// TODO: accept an expected log size.

	sth, err := tl.Config.Backend.Fetch(context.Background(), "checkpoint")
	fatalIfErr(t, err)
	v, err := tlogx.NewRFC6962Verifier("example.com/TestLog", tl.Config.Key.Public())
	fatalIfErr(t, err)
	v.Timestamp = func(t uint64) { sthTimestamp = int64(t) }
	n, err := note.Open(sth, note.VerifierList(v))
	fatalIfErr(t, err)
	c, err := tlogx.ParseCheckpoint(n.Text)
	fatalIfErr(t, err)

	if c.Origin != "example.com/TestLog" {
		t.Errorf("origin line is %q", c.Origin)
	}
	if c.Extension != "" {
		t.Errorf("unexpected extension %q", c.Extension)
	}

	if c.N == 0 {
		if c.Hash != (tlog.Hash{}) {
			t.Error("empty log should have zero hash")
		}
		return
	}

	tree := tlog.Tree{N: c.N, Hash: c.Hash}
	var indexes []int64
	for n := int64(0); n < c.N; n++ {
		indexes = append(indexes, tlog.StoredHashIndex(0, n))
	}
	// tlog.TileHashReader checks the inclusion of every hash in the provided
	// tree, so this checks the validity of the whole Merkle tree.
	leafHashes, err := tlog.TileHashReader(tree, (*tileReader)(tl)).ReadHashes(indexes)
	fatalIfErr(t, err)

	lastTile := tlog.TileForIndex(tileHeight, tlog.StoredHashIndex(0, c.N-1))
	lastTile.L = -1
	for n := int64(0); n <= lastTile.N; n++ {
		tile := tlog.Tile{H: tileHeight, L: -1, N: n, W: tileWidth}
		if n == lastTile.N {
			tile = lastTile
		}
		b, err := tl.Config.Backend.Fetch(context.Background(), tile.Path())
		fatalIfErr(t, err)
		for i := 0; i < tile.W; i++ {
			e, rest, err := ctlog.ReadTileLeaf(b)
			if err != nil {
				t.Fatalf("invalid data tile %v", tile)
			}
			b = rest

			idx := n*tileWidth + int64(i)
			if e.LeafIndex != idx {
				t.Errorf("SCT index %d, expected %d", e.LeafIndex, idx)
			}
			if e.Timestamp > sthTimestamp {
				t.Errorf("STH timestamp %d is before record %d timestamp %d", sthTimestamp, idx, e.Timestamp)
			}
			got := tlog.RecordHash(e.MerkleTreeLeaf())
			if exp := leafHashes[idx]; got != exp {
				t.Errorf("tile leaf entry %d hashes to %v, level 0 hash is %v", idx, got, exp)
			}
		}
		if len(b) != 0 {
			t.Errorf("invalid data tile %v: trailing data", tile)
		}
	}

	return
}

const tileHeight = 10
const tileWidth = 1 << tileHeight

type tileReader TestLog

func (r *tileReader) Height() int {
	return tileHeight
}

func (r *tileReader) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	for _, t := range tiles {
		b, err := r.Config.Backend.Fetch(context.Background(), t.Path())
		if err != nil {
			return nil, err
		}
		data = append(data, b)
	}
	return data, nil
}

func (r *tileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {}

type verifier struct {
	name   string
	hash   uint32
	verify func(msg, sig []byte) bool
}

func (v *verifier) Name() string                { return v.name }
func (v *verifier) KeyHash() uint32             { return v.hash }
func (v *verifier) Verify(msg, sig []byte) bool { return v.verify(msg, sig) }

type MemoryBackend struct {
	t  testing.TB
	mu sync.Mutex
	m  map[string][]byte
}

func NewMemoryBackend(t testing.TB) *MemoryBackend {
	return &MemoryBackend{
		t: t, m: make(map[string][]byte),
	}
}

func (b *MemoryBackend) Upload(ctx context.Context, key string, data []byte) error {
	// TODO: check key format is expected.
	if len(data) == 0 {
		b.t.Errorf("uploaded key %q with empty data", key)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.m[key] = data
	return nil
}

func (b *MemoryBackend) Fetch(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.m[key]
	if !ok {
		return nil, fmt.Errorf("key %q not found", key)
	}
	return data, nil
}

func fatalIfErr(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
