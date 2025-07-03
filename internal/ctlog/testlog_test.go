package ctlog_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mathrand "math/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/ctlog"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/x509"
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
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fatalIfErr(t, err)
	k, err := x509.MarshalPKCS8PrivateKey(key)
	fatalIfErr(t, err)
	t.Logf("ECDSA key: %s", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	fatalIfErr(t, err)
	k, err = x509.MarshalPKCS8PrivateKey(ed25519Key)
	fatalIfErr(t, err)
	t.Logf("Ed25519 key: %s", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}))
	logHandler, logLevel := testLogHandler(t)
	config := &ctlog.Config{
		Name:          "example.com/TestLog",
		Key:           key,
		WitnessKey:    ed25519Key,
		Cache:         filepath.Join(t.TempDir(), "cache.db"),
		Backend:       NewMemoryBackend(t),
		Lock:          NewMemoryLockBackend(t),
		Log:           slog.New(logHandler),
		NotAfterStart: time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfterLimit: time.Date(2024, time.July, 1, 0, 0, 0, 0, time.UTC),
	}
	err = ctlog.CreateLog(t.Context(), config)
	fatalIfErr(t, err)
	(&TestLog{t: t, Config: config, l: logLevel}).CheckLog(0)
	log, err := ctlog.LoadLog(context.Background(), config)
	fatalIfErr(t, err)
	fatalIfErr(t, log.SetRootsFromPEM(t.Context(), pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: testRoot,
	})))
	t.Cleanup(func() { fatalIfErr(t, log.CloseCache()) })
	tl := &TestLog{t: t,
		Log:    log,
		Config: config,
		l:      logLevel,
	}
	tl.CheckLog(0)
	return tl
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
	t.Helper()
	log, err := ctlog.LoadLog(context.Background(), tl.Config)
	fatalIfErr(t, err)
	t.Cleanup(func() { fatalIfErr(t, log.CloseCache()) })
	return &TestLog{t: t,
		Log:    log,
		Config: tl.Config,
	}
}

func (tl *TestLog) CheckLog(size int64) (sthTimestamp int64) {
	t := tl.t
	t.Helper()

	sth, err := tl.Config.Backend.Fetch(context.Background(), "checkpoint")
	fatalIfErr(t, err)
	v, err := sunlight.NewRFC6962Verifier("example.com/TestLog", tl.Config.Key.Public())
	fatalIfErr(t, err)
	n, err := note.Open(sth, note.VerifierList(v))
	fatalIfErr(t, err)
	if len(n.Sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(n.Sigs))
	}
	sthTimestamp, err = sunlight.RFC6962SignatureTimestamp(n.Sigs[0])
	fatalIfErr(t, err)
	c, err := sunlight.ParseCheckpoint(n.Text)
	fatalIfErr(t, err)

	if c.Origin != "example.com/TestLog" {
		t.Errorf("origin line is %q", c.Origin)
	}
	if c.Extension != "" {
		t.Errorf("unexpected extension %q", c.Extension)
	}

	{
		logID, err := logIDFromKey(tl.Config.Key)
		fatalIfErr(t, err)
		sth, err := tl.Config.Lock.Fetch(context.Background(), logID)
		fatalIfErr(t, err)
		v, err := sunlight.NewRFC6962Verifier("example.com/TestLog", tl.Config.Key.Public())
		fatalIfErr(t, err)
		n, err := note.Open(sth.Bytes(), note.VerifierList(v))
		fatalIfErr(t, err)
		if len(n.Sigs) != 1 {
			t.Fatalf("expected 1 signature, got %d", len(n.Sigs))
		}
		sthTimestamp1, err := sunlight.RFC6962SignatureTimestamp(n.Sigs[0])
		fatalIfErr(t, err)
		c1, err := sunlight.ParseCheckpoint(n.Text)
		fatalIfErr(t, err)

		if c1.Origin != c.Origin || c1.Extension != c.Extension {
			t.Errorf("checkpoint and lock checkpoint differ")
		}
		if c1.N == c.N && c1.Hash != c.Hash {
			t.Error("checkpoint and lock checkpoint have different hash")
		}
		if sthTimestamp1 < sthTimestamp {
			t.Error("lock checkpoint is older than checkpoint")
		}
		if c1.N < c.N {
			t.Error("lock checkpoint is smaller than checkpoint")
		}
		if c1.N > c.N {
			// TODO: load pending entries and check consistency.
		}

		if size >= 0 && c1.N != size {
			t.Errorf("expected size %d, got %d", size, c.N)
		}
	}

	if c.N == 0 {
		expected := sha256.Sum256([]byte{})
		if c.Hash != expected {
			t.Error("empty log should have empty string hash")
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

	lastTile := tlog.TileForIndex(sunlight.TileHeight, tlog.StoredHashIndex(0, c.N-1))
	lastTile.L = -1
	for n := int64(0); n <= lastTile.N; n++ {
		tile := tlog.Tile{H: sunlight.TileHeight, L: -1, N: n, W: tileWidth}
		if n == lastTile.N {
			tile = lastTile
		}
		b, err := tl.Config.Backend.Fetch(context.Background(), sunlight.TilePath(tile))
		fatalIfErr(t, err)
		r, err := gzip.NewReader(bytes.NewReader(b))
		fatalIfErr(t, err)
		b, err = io.ReadAll(r)
		fatalIfErr(t, err)
		for i := 0; i < tile.W; i++ {
			e, rest, err := sunlight.ReadTileLeaf(b)
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

			if len(e.Certificate) == 0 {
				t.Errorf("empty certificate at index %d", idx)
			}
			if e.IsPrecert {
				if len(e.PreCertificate) == 0 {
					t.Errorf("empty precertificate at index %d", idx)
				}
				if e.IssuerKeyHash == [32]byte{} {
					t.Errorf("empty issuer key hash at index %d", idx)
				}
			} else {
				if e.PreCertificate != nil {
					t.Errorf("unexpected precertificate at index %d", idx)
				}
				if e.IssuerKeyHash != [32]byte{} {
					t.Errorf("unexpected issuer key hash at index %d", idx)
				}
			}
			for _, fp := range e.ChainFingerprints {
				b, err := tl.Config.Backend.Fetch(context.Background(), fmt.Sprintf("issuer/%x", fp))
				if err != nil {
					t.Errorf("issuer %x not found", fp)
				}
				if len(b) == 0 {
					t.Errorf("issuer %x is empty", fp)
				}
				if sha256.Sum256(b) != fp {
					t.Errorf("issuer %x does not hash to %x", fp, fp)
				}
			}
		}
		if len(b) != 0 {
			t.Errorf("invalid data tile %v: trailing data", tile)
		}
	}

	return
}

func logIDFromKey(key *ecdsa.PrivateKey) ([sha256.Size]byte, error) {
	pkix, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("couldn't marshal public key: %w", err)
	}
	return sha256.Sum256(pkix), nil
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

func waitFuncWrapper(t testing.TB, le *ctlog.PendingLogEntry, expectSuccess bool,
	f func(ctx context.Context) (*sunlight.LogEntry, error),
) func(ctx context.Context) (*sunlight.LogEntry, error) {
	t.Helper()
	var called bool
	fw := func(ctx context.Context) (*sunlight.LogEntry, error) {
		t.Helper()
		called = true
		se, err := f(ctx)
		if !expectSuccess {
			if err == nil {
				t.Error("expected an error")
			}
		} else if err != nil {
			t.Error(err)
		} else if !reflect.DeepEqual(se, le.AsLogEntry(se.LeafIndex, se.Timestamp)) {
			t.Error("LogEntry is different")
		}
		return se, err
	}
	t.Cleanup(func() {
		t.Helper()
		if !called {
			fw(context.Background())
		}
	})
	return fw
}

func addCertificate(t *testing.T, tl *TestLog) func(ctx context.Context) (*sunlight.LogEntry, error) {
	t.Helper()
	return addCertificateWithSeed(t, tl, mathrand.Int63()) // 2⁻³² chance of collision after 2¹⁶ entries
}

var chains = [][][]byte{
	{[]byte("A"), []byte("rootX")},
	{[]byte("B"), []byte("C"), []byte("rootX")},
	{[]byte("A"), []byte("rootY")},
	{},
}

func addCertificateWithSeed(t *testing.T, tl *TestLog, seed int64) func(ctx context.Context) (*sunlight.LogEntry, error) {
	t.Helper()
	r := mathrand.New(mathrand.NewSource(seed))
	e := &ctlog.PendingLogEntry{}
	e.Certificate = make([]byte, r.Intn(4)+8)
	r.Read(e.Certificate)
	e.Issuers = chains[r.Intn(len(chains))]
	f, _ := tl.Log.AddLeafToPool(e)
	return waitFuncWrapper(t, e, true, f)
}

func addCertificateExpectFailure(t *testing.T, tl *TestLog) {
	t.Helper()
	addCertificateExpectFailureWithSeed(t, tl, mathrand.Int63())
}

func addCertificateExpectFailureWithSeed(t *testing.T, tl *TestLog, seed int64) {
	t.Helper()
	r := mathrand.New(mathrand.NewSource(seed))
	e := &ctlog.PendingLogEntry{}
	e.Certificate = make([]byte, r.Intn(4)+8)
	r.Read(e.Certificate)
	e.Issuers = chains[r.Intn(len(chains))]
	f, _ := tl.Log.AddLeafToPool(e)
	waitFuncWrapper(t, e, false, f)
}

func addPreCertificate(t *testing.T, tl *TestLog) func(ctx context.Context) (*sunlight.LogEntry, error) {
	t.Helper()
	return addPreCertificateWithSeed(t, tl, mathrand.Int63())
}

func addPreCertificateWithSeed(t *testing.T, tl *TestLog, seed int64) func(ctx context.Context) (*sunlight.LogEntry, error) {
	t.Helper()
	r := mathrand.New(mathrand.NewSource(seed))
	e := &ctlog.PendingLogEntry{IsPrecert: true}
	e.Certificate = make([]byte, r.Intn(4)+8)
	r.Read(e.Certificate)
	e.PreCertificate = make([]byte, r.Intn(4)+1)
	r.Read(e.PreCertificate)
	r.Read(e.IssuerKeyHash[:])
	e.Issuers = chains[r.Intn(len(chains))]
	f, _ := tl.Log.AddLeafToPool(e)
	return waitFuncWrapper(t, e, true, f)
}

const tileWidth = 1 << sunlight.TileHeight

type tileReader TestLog

func (r *tileReader) Height() int {
	return sunlight.TileHeight
}

func (r *tileReader) ReadTiles(tiles []tlog.Tile) (data [][]byte, err error) {
	for _, t := range tiles {
		b, err := r.Config.Backend.Fetch(context.Background(), sunlight.TilePath(t))
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
	t   testing.TB
	mu  sync.Mutex
	m   map[string][]byte
	imm map[string]bool
	del map[string]bool

	uploads uint64

	UploadCallback func(key string, data []byte) (apply bool, err error)
}

func NewMemoryBackend(t testing.TB) *MemoryBackend {
	return &MemoryBackend{
		t: t, m: make(map[string][]byte), imm: make(map[string]bool), del: make(map[string]bool),
	}
}

func (b *MemoryBackend) Upload(ctx context.Context, key string, data []byte, opts *ctlog.UploadOptions) error {
	atomic.AddUint64(&b.uploads, 1)
	// TODO: check key format is expected.
	if len(data) == 0 && key != "_roots.pem" {
		b.t.Errorf("uploaded key %q with empty data", key)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var finalErr error
	if b.UploadCallback != nil {
		apply, err := b.UploadCallback(key, data)
		finalErr = err
		if !apply {
			return finalErr
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.imm[key] && !bytes.Equal(b.m[key], data) {
		b.t.Errorf("immutable key %q was modified", key)
	}
	if b.del[key] {
		b.t.Errorf("deleted key %q was re-uploaded", key)
	}
	b.m[key] = data
	b.imm[key] = opts.Immutable
	return finalErr
}

func failCheckpointAndNotPersist(key string, data []byte) (apply bool, err error) {
	if key == "checkpoint" {
		return false, errors.New("checkpoint upload error")
	}
	return true, nil
}

func failCheckpointButPersist(key string, data []byte) (apply bool, err error) {
	if key == "checkpoint" {
		return true, errors.New("checkpoint upload error")
	}
	return true, nil
}

func failStagingAndNotPersist(key string, data []byte) (apply bool, err error) {
	if strings.HasPrefix(key, "staging/") {
		return false, errors.New("staging upload error")
	}
	return true, nil
}

func failStagingButPersist(key string, data []byte) (apply bool, err error) {
	if strings.HasPrefix(key, "staging/") {
		return true, errors.New("staging upload error")
	}
	return true, nil
}

func failDataTileAndNotPersist(key string, data []byte) (apply bool, err error) {
	if strings.HasPrefix(key, "tile/data/") {
		return false, errors.New("data tile upload error")
	}
	return true, nil
}

func failDataTileButPersist(key string, data []byte) (apply bool, err error) {
	if strings.HasPrefix(key, "tile/data/") {
		return true, errors.New("data tile upload error")
	}
	return true, nil
}

func failTile0AndNotPersist(key string, data []byte) (apply bool, err error) {
	if strings.HasPrefix(key, "tile/0/") {
		return false, errors.New("tile 0 upload error")
	}
	return true, nil
}

func failTile0ButPersist(key string, data []byte) (apply bool, err error) {
	if strings.HasPrefix(key, "tile/0/") {
		return true, errors.New("tile 0 upload error")
	}
	return true, nil
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
	if b.del[key] {
		b.t.Errorf("deleted key %q was fetched", key)
		return nil, fmt.Errorf("key %q not found", key)
	}
	return data, nil
}

func (b *MemoryBackend) Discard(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.m[key]; !ok {
		b.t.Errorf("deleted missing key %q", key)
		return fmt.Errorf("key %q not found", key)
	}
	if b.del[key] {
		b.t.Errorf("deleted key %q was deleted again", key)
		return fmt.Errorf("key %q not found", key)
	}
	b.del[key] = true
	return nil
}

func (b *MemoryBackend) Metrics() []prometheus.Collector { return nil }

type MemoryLockBackend struct {
	t  testing.TB
	mu sync.Mutex
	m  map[[sha256.Size]byte][]byte

	ReplaceCallback func(old ctlog.LockedCheckpoint, new []byte) (apply bool, err error)
}

type memoryLockCheckpoint struct {
	logID [sha256.Size]byte
	data  []byte
}

func (c *memoryLockCheckpoint) Bytes() []byte {
	return c.data
}

func NewMemoryLockBackend(t testing.TB) *MemoryLockBackend {
	return &MemoryLockBackend{
		t: t, m: make(map[[sha256.Size]byte][]byte),
	}
}

func (b *MemoryLockBackend) Fetch(ctx context.Context, logID [sha256.Size]byte) (ctlog.LockedCheckpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.m[logID]
	if !ok {
		return nil, fmt.Errorf("log %x not found", logID)
	}
	return &memoryLockCheckpoint{logID: logID, data: data}, nil
}

func (b *MemoryLockBackend) Create(ctx context.Context, logID [sha256.Size]byte, new []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.m[logID]; ok {
		return fmt.Errorf("log %x already exists", logID)
	}
	b.m[logID] = new
	return nil
}

func (b *MemoryLockBackend) Replace(ctx context.Context, old ctlog.LockedCheckpoint, new []byte) (ctlog.LockedCheckpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var finalErr error
	if b.ReplaceCallback != nil {
		apply, err := b.ReplaceCallback(old, new)
		finalErr = err
		if !apply {
			return nil, finalErr
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if old == nil {
		b.t.Errorf("Replace called with nil old checkpoint")
		return nil, fmt.Errorf("old checkpoint is nil")
	}
	oldc := old.(*memoryLockCheckpoint)
	if current, ok := b.m[oldc.logID]; !ok {
		return nil, fmt.Errorf("log %x not found", oldc.logID)
	} else if !bytes.Equal(current, oldc.data) {
		return nil, fmt.Errorf("log %x has changed", oldc.logID)
	}
	b.m[oldc.logID] = new
	return &memoryLockCheckpoint{logID: oldc.logID, data: new}, finalErr
}

func failLockAndNotPersist(old ctlog.LockedCheckpoint, new []byte) (apply bool, err error) {
	return false, errors.New("lock replace error")
}

func failLockButPersist(old ctlog.LockedCheckpoint, new []byte) (apply bool, err error) {
	return true, errors.New("lock replace error")
}

func fatalIfErr(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
