package ctlog_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"filippo.io/litetlog/internal/ctlog"
	"filippo.io/litetlog/internal/tlogx"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type TestLog struct {
	Log    *ctlog.Log
	Config *ctlog.Config
	t      testing.TB
	l      *slog.LevelVar
}

func NewEmptyTestLog(t testing.TB) *TestLog {
	backend := NewMemoryBackend(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fatalIfErr(t, err)
	k, err := x509.MarshalPKCS8PrivateKey(key)
	fatalIfErr(t, err)
	t.Logf("ECDSA key: %s", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
	logHandler, logLevel := testLogHandler(t)
	config := &ctlog.Config{
		Name:          "example.com/TestLog",
		Key:           key,
		Backend:       backend,
		Log:           slog.New(logHandler),
		Roots:         x509util.NewPEMCertPool(),
		NotAfterStart: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfterLimit: time.Date(2024, time.July, 1, 0, 0, 0, 0, time.UTC),
	}
	root, err := x509.ParseCertificate(testRoot)
	fatalIfErr(t, err)
	config.Roots.AddCert(root)
	err = ctlog.CreateLog(context.Background(), config)
	fatalIfErr(t, err)
	log, err := ctlog.LoadLog(context.Background(), config)
	fatalIfErr(t, err)
	return &TestLog{t: t,
		Log:    log,
		Config: config,
		l:      logLevel,
	}
}

func testLogHandler(t testing.TB) (slog.Handler, *slog.LevelVar) {
	level := &slog.LevelVar{}
	level.Set(slog.LevelDebug)
	h := slog.NewTextHandler(writerFunc(func(p []byte) (n int, err error) {
		t.Logf("%s", p)
		return len(p), nil
	}), &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				src := a.Value.Any().(*slog.Source)
				a.Value = slog.StringValue(fmt.Sprintf("%s:%d", filepath.Base(src.File), src.Line))
			}
			return a
		},
	})
	return h, level
}

type writerFunc func(p []byte) (n int, err error)

func (f writerFunc) Write(p []byte) (n int, err error) {
	return f(p)
}

func (tl *TestLog) Quiet() {
	tl.l.Set(slog.LevelWarn)
}

func ReloadLog(t testing.TB, tl *TestLog) *TestLog {
	log, err := ctlog.LoadLog(context.Background(), tl.Config)
	fatalIfErr(t, err)
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

func (tl *TestLog) LogClient() *client.LogClient {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rr := httptest.NewRecorder()
		tl.Log.Handler().ServeHTTP(rr, r)
		res := rr.Result()
		if res.StatusCode != http.StatusOK {
			tl.t.Logf("%s %s %d", r.Method, r.URL.Path, res.StatusCode)
			tl.t.Logf("\t%s", rr.Body.String())
		}
		for h, v := range res.Header {
			w.Header()[h] = v
		}
		w.WriteHeader(res.StatusCode)
		io.Copy(w, res.Body)
	}))
	tl.t.Cleanup(ts.Close)
	pubKey, err := x509.MarshalPKIXPublicKey(tl.Config.Key.Public())
	fatalIfErr(tl.t, err)
	lc, err := client.New(ts.URL, &http.Client{
		Timeout: 10 * time.Second,
	}, jsonclient.Options{
		Logger:       slog.NewLogLogger(tl.Config.Log.Handler(), slog.LevelInfo),
		PublicKeyDER: pubKey,
	})
	fatalIfErr(tl.t, err)
	tl.StartSequencer()
	return lc
}

func (tl *TestLog) StartSequencer() {
	ctx, cancel := context.WithCancel(context.Background())
	tl.t.Cleanup(cancel)
	go func() {
		err := tl.Log.RunSequencer(ctx, 50*time.Millisecond)
		if err != context.Canceled {
			tl.t.Errorf("RunSequencer returned an error: %v", err)
		}
	}()
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

func (b *MemoryBackend) UploadCompressible(ctx context.Context, key string, data []byte) error {
	return b.Upload(ctx, key, data)
}

func (b *MemoryBackend) Upload(ctx context.Context, key string, data []byte) error {
	// TODO: check key format is expected.
	if len(data) == 0 && key != "issuers.pem" {
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

func (b *MemoryBackend) Metrics() []prometheus.Collector { return nil }

func fatalIfErr(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
