package cttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"testing"

	"filippo.io/litetlog/internal/ctlog"
	"filippo.io/litetlog/internal/tlogx"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type TestLog struct {
	Log     *ctlog.Log
	Backend *MemoryBackend
	Key     *ecdsa.PrivateKey
	t       testing.TB
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
	log, err := ctlog.NewLog("example.com/TestLog", key, backend)
	if err != nil {
		t.Fatal(err)
	}
	return &TestLog{t: t,
		Log:     log,
		Backend: backend,
		Key:     key,
	}
}

func (tl *TestLog) CheckLog() (sthTimestamp uint64) {
	t := tl.t

	sth, err := tl.Backend.Fetch(context.Background(), "sth")
	fatalIfErr(t, err)
	v, err := tlogx.NewRFC6962Verifier("example.com/TestLog", tl.Key.Public())
	fatalIfErr(t, err)
	v.Timestamp = func(t uint64) { sthTimestamp = t }
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
		b, err := tl.Backend.Fetch(context.Background(), tile.Path())
		fatalIfErr(t, err)
		s := cryptobyte.String(b)
		for i := 0; i < tile.W; i++ {
			start := len(b) - len(s)
			var timestamp uint64
			var entryType uint8
			var cert, extensions []byte
			if !s.ReadUint64(&timestamp) || !s.ReadUint8(&entryType) {
				t.Fatalf("invalid data tile %v around index %d", tile, len(b)-len(s))
			}
			switch entryType {
			case 0: // x509_entry
				if !s.ReadUint24LengthPrefixed((*cryptobyte.String)(&cert)) {
					t.Fatalf("invalid data tile %v around index %d", tile, len(b)-len(s))
				}
			case 1: // precert_entry
				panic("unimplemented") // TODO
			default:
				t.Fatalf("invalid data tile %v: unknown type %d", tile, entryType)
			}
			if !s.ReadUint16LengthPrefixed((*cryptobyte.String)(&extensions)) {
				t.Fatalf("invalid data tile %v around index %d", tile, len(b)-len(s))
			}
			end := len(b) - len(s)

			idx := n*tileWidth + int64(i)
			if timestamp > sthTimestamp {
				t.Errorf("STH timestamp %d is before record %d timestamp %d", sthTimestamp, idx, timestamp)
			}
			got := tlog.RecordHash(append([]byte{0, 0}, b[start:end]...))
			if exp := leafHashes[idx]; got != exp {
				t.Errorf("tile leaf entry %d hashes to %v, level 0 hash is %v", idx, got, exp)
			}
		}
		if !s.Empty() {
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
		b, err := r.Backend.Fetch(context.Background(), t.Path())
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
