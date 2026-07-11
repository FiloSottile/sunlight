package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/sunlight/internal/witness"
	"filippo.io/torchwood"
	"github.com/cespare/webtest"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"gopkg.in/yaml.v3"
)

//go:generate go run testdata/gen.go

// TestRateLimitErrorHeaders checks that rate limited responses lose the
// content headers set optimistically before dispatch, while allowed responses
// keep them. The webtest scripts can't cover the 429 path, because triggering
// the rate limit over HTTP would be timing-dependent.
func TestRateLimitErrorHeaders(t *testing.T) {
	h := newRateLimitHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fake tile"))
	}))
	var allowed, limited int
	for range 2 * rateLimitBurst {
		req := httptest.NewRequest("GET", "/tile/data/000", nil)
		req = req.WithContext(context.WithValue(req.Context(), clientContextKey{}, "anonymous"))
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Encoding", "gzip")
		rec.Header().Set("Cache-Control", "public, max-age=604800, immutable")
		h.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusOK:
			allowed++
			if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
				t.Errorf("allowed response Content-Encoding = %q, want gzip", got)
			}
			if got := rec.Header().Get("Cache-Control"); got == "" {
				t.Error("allowed response is missing Cache-Control")
			}
		case http.StatusTooManyRequests:
			limited++
			if got := rec.Header().Get("Content-Encoding"); got != "" {
				t.Errorf("429 response Content-Encoding = %q, want empty", got)
			}
			if got := rec.Header().Get("Cache-Control"); got != "" {
				t.Errorf("429 response Cache-Control = %q, want empty", got)
			}
			if rec.Header().Get("Retry-After") == "" {
				t.Error("429 response is missing Retry-After")
			}
		default:
			t.Errorf("unexpected status code %d", rec.Code)
		}
	}
	if allowed == 0 || limited == 0 {
		t.Errorf("got %d allowed and %d rate limited responses, want some of each", allowed, limited)
	}
}

// TestScripts builds and runs the production skylight binary against the
// testdata configuration, and executes the webtest scripts against it.
func TestScripts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping exec of skylight in short mode")
	}

	// Pick a free localhost port for the server to listen on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	yml, err := os.ReadFile("testdata/skylight.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(yml, c); err != nil {
		t.Fatal(err)
	}
	c.Listen = []string{addr}
	yml, err = yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "skylight.yaml")
	if err := os.WriteFile(configPath, yml, 0o666); err != nil {
		t.Fatal(err)
	}

	logs := &bytes.Buffer{}
	cmd := exec.Command("go", "run", ".", "-c", configPath)
	cmd.Stdout = io.Discard // JSON logs, duplicated on stderr
	cmd.Stderr = logs
	// Run go run in its own process group, so the SIGINT below reaches the
	// skylight child process too (go run doesn't forward signals sent
	// directly to it, only ones delivered to its process group).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
		cmd.Wait() // skylight always exits with a non-zero status
		if t.Failed() {
			t.Logf("skylight logs:\n%s", logs.Bytes())
		}
	})

	client := &http.Client{
		// Pass gzip-encoded responses through untouched.
		Transport: &http.Transport{DisableCompression: true},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for start := time.Now(); ; time.Sleep(50 * time.Millisecond) {
		resp, err := client.Get("http://" + addr + "/health")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Since(start) > 10*time.Second {
			t.Fatalf("server did not come up: %v", err)
		}
	}

	// webtest drives an http.Handler, so forward the requests to the server,
	// preserving the Host of the script URLs for name-based routing.
	webtest.TestHandler(t, "*_test.txt", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			req := r.Clone(r.Context())
			req.RequestURI = ""
			if req.Host == "" {
				req.Host = r.URL.Host
			}
			// Set a User-Agent with an email address unless the script case
			// sets its own, to avoid drawing down the global anonymous client
			// rate limit budget shared by all the test cases.
			if req.Header.Get("User-Agent") == "" {
				req.Header.Set("User-Agent", "skylight-webtest (test@test.invalid)")
			}
			req.URL.Scheme = "http"
			req.URL.Host = addr
			resp, err := client.Do(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		}))
}

// TestWitnessHealth exercises the /health witness and mirror checkpoint
// verification against directories built with real tiles and real cosignatures.
func TestWitnessHealth(t *testing.T) {
	const origin = "mirror.example.org/checkmirror"

	// The health check doesn't care whether the cosigners are Ed25519 or
	// ML-DSA-44, so use Ed25519.
	witnessSigner := newTestCosigner(t, "witness.example.org")
	mirrorSigner := newTestCosigner(t, "mirror.example.org")

	openRoot := func(t *testing.T, dir string) *os.Root {
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { root.Close() })
		return root
	}

	load := func(t *testing.T, wh *witnessHealth) {
		t.Helper()
		if err := wh.loadVerifiers(); err != nil {
			t.Fatalf("loadVerifiers() error = %v", err)
		}
	}

	// buildWitness writes a witness directory with a checkpoint of the given
	// size under dirHash, signed by signer, and a witness.v0.json listing the
	// witness verifier key.
	buildWitness := func(t *testing.T, dirHash string, size int64, signer note.Signer) witnessHealth {
		dir := t.TempDir()
		writeWitnessCheckpoint(t, dir, origin, dirHash, size, signer)
		writeVerifierKeys(t, filepath.Join(dir, "witness.v0.json"), witnessSigner.Verifier().String())
		wh := witnessHealth{root: openRoot(t, dir)}
		load(t, &wh)
		return wh
	}

	// buildMirror lays out a witness directory with a mirror tree of size
	// mirrorN under mirror/<dirHash>/ and a pending witness checkpoint of size
	// pendingN under <dirHash>/, along with the witness.v0.json and
	// mirror.v0.json files listing the verifier keys. It returns the health
	// check and the mirror directory.
	buildMirror := func(t *testing.T, dirHash string, mirrorN, pendingN int64) (witnessHealth, string) {
		witnessDir := t.TempDir()
		mirrorDir := filepath.Join(witnessDir, "mirror")
		writeMirrorTree(t, mirrorDir, origin, dirHash, mirrorN, mirrorSigner)
		writeWitnessCheckpoint(t, witnessDir, origin, dirHash, pendingN, witnessSigner)
		writeVerifierKeys(t, filepath.Join(witnessDir, "witness.v0.json"), witnessSigner.Verifier().String())
		writeVerifierKeys(t, filepath.Join(mirrorDir, "mirror.v0.json"), mirrorSigner.Verifier().String())
		wh := witnessHealth{
			root:        openRoot(t, mirrorDir),
			pendingRoot: openRoot(t, witnessDir),
			mirror:      true,
		}
		load(t, &wh)
		return wh, mirrorDir
	}

	t.Run("witness checkpoint", func(t *testing.T) {
		wh := buildWitness(t, witness.OriginHash(origin), 300, witnessSigner)
		got, err := wh.check(context.Background(), witness.OriginHash(origin))
		if err != nil {
			t.Fatalf("check failed: %v", err)
		}
		if got != origin {
			t.Errorf("origin = %q, want %q", got, origin)
		}
	})

	t.Run("witness bad signature", func(t *testing.T) {
		// Signed by a key the health check doesn't know.
		wh := buildWitness(t, witness.OriginHash(origin), 300, mirrorSigner)
		if _, err := wh.check(context.Background(), witness.OriginHash(origin)); err == nil ||
			!strings.Contains(err.Error(), "verify checkpoint") {
			t.Fatalf("check error = %v, want a verification failure", err)
		}
	})

	t.Run("mirror valid", func(t *testing.T) {
		// mirrorN spans two data tiles with a partial right edge, and the mirror
		// is a few entries behind the pending checkpoint.
		wh, _ := buildMirror(t, witness.OriginHash(origin), 300, 305)
		got, err := wh.check(context.Background(), witness.OriginHash(origin))
		if err != nil {
			t.Fatalf("check failed: %v", err)
		}
		if got != origin {
			t.Errorf("origin = %q, want %q", got, origin)
		}
	})

	t.Run("mirror empty", func(t *testing.T) {
		wh, _ := buildMirror(t, witness.OriginHash(origin), 0, 0)
		got, err := wh.check(context.Background(), witness.OriginHash(origin))
		if err != nil {
			t.Fatalf("check failed: %v", err)
		}
		if got != origin {
			t.Errorf("origin = %q, want %q", got, origin)
		}
	})

	t.Run("mirror ahead of pending", func(t *testing.T) {
		wh, _ := buildMirror(t, witness.OriginHash(origin), 305, 300)
		if _, err := wh.check(context.Background(), witness.OriginHash(origin)); err == nil ||
			!strings.Contains(err.Error(), "ahead of pending") {
			t.Fatalf("check error = %v, want it to mention the pending checkpoint", err)
		}
	})

	t.Run("mirror missing right-edge tile", func(t *testing.T) {
		wh, dir := buildMirror(t, witness.OriginHash(origin), 300, 305)
		// Remove the partial level-0 tile at the right edge (300 = 256 + 44).
		edge := torchwood.TilePath(tlog.Tile{H: torchwood.TileHeight, L: 0, N: 1, W: 44})
		if err := os.Remove(filepath.Join(dir, witness.OriginHash(origin), edge)); err != nil {
			t.Fatal(err)
		}
		if _, err := wh.check(context.Background(), witness.OriginHash(origin)); err == nil ||
			!strings.Contains(err.Error(), "right-edge tiles") {
			t.Fatalf("check error = %v, want it to mention the tiles", err)
		}
	})

	t.Run("origin hash mismatch", func(t *testing.T) {
		// The directory is named for a different origin than the checkpoint.
		dirHash := witness.OriginHash("other.example.org")
		wh, _ := buildMirror(t, dirHash, 300, 305)
		got, err := wh.check(context.Background(), dirHash)
		if err == nil || !strings.Contains(err.Error(), "hashes to") {
			t.Fatalf("check error = %v, want an origin hash mismatch", err)
		}
		if got != origin {
			t.Errorf("origin = %q, want %q", got, origin)
		}
	})

	t.Run("hashes skips non-hash entries", func(t *testing.T) {
		wh, dir := buildMirror(t, witness.OriginHash(origin), 300, 305)
		// A "mirror" subdirectory (as a mirror witness has) and stray files must
		// be ignored by the hash enumeration.
		writeTestFile(t, filepath.Join(dir, "mirror", "checkpoint"), []byte("decoy\n"))
		writeTestFile(t, filepath.Join(dir, "checkpoint"), []byte("decoy\n"))
		got, err := wh.hashes()
		if err != nil {
			t.Fatalf("hashes failed: %v", err)
		}
		if len(got) != 1 || got[0] != witness.OriginHash(origin) {
			t.Errorf("hashes() = %v, want [%s]", got, witness.OriginHash(origin))
		}
	})

	t.Run("missing witness.v0.json", func(t *testing.T) {
		dir := t.TempDir()
		writeWitnessCheckpoint(t, dir, origin, witness.OriginHash(origin), 300, witnessSigner)
		wh := witnessHealth{root: openRoot(t, dir)}
		if err := wh.loadVerifiers(); err == nil ||
			!strings.Contains(err.Error(), "failed to read witness.v0.json") {
			t.Fatalf("loadVerifiers() error = %v, want a witness.v0.json read failure", err)
		}
	})

	t.Run("mirror missing pending witness.v0.json", func(t *testing.T) {
		witnessDir := t.TempDir()
		mirrorDir := filepath.Join(witnessDir, "mirror")
		writeMirrorTree(t, mirrorDir, origin, witness.OriginHash(origin), 300, mirrorSigner)
		writeVerifierKeys(t, filepath.Join(mirrorDir, "mirror.v0.json"), mirrorSigner.Verifier().String())
		wh := witnessHealth{
			root:        openRoot(t, mirrorDir),
			pendingRoot: openRoot(t, witnessDir),
			mirror:      true,
		}
		if err := wh.loadVerifiers(); err == nil ||
			!strings.Contains(err.Error(), "witness.v0.json") {
			t.Fatalf("loadVerifiers() error = %v, want a witness.v0.json read failure", err)
		}
	})

	t.Run("invalid verifier key", func(t *testing.T) {
		dir := t.TempDir()
		writeVerifierKeys(t, filepath.Join(dir, "witness.v0.json"), "not a vkey")
		wh := witnessHealth{root: openRoot(t, dir)}
		if err := wh.loadVerifiers(); err == nil ||
			!strings.Contains(err.Error(), "invalid verifier key") {
			t.Fatalf("loadVerifiers() error = %v, want an invalid key failure", err)
		}
	})

	t.Run("empty verifier keys", func(t *testing.T) {
		dir := t.TempDir()
		writeVerifierKeys(t, filepath.Join(dir, "witness.v0.json"))
		wh := witnessHealth{root: openRoot(t, dir)}
		if err := wh.loadVerifiers(); err == nil ||
			!strings.Contains(err.Error(), "no verifier keys") {
			t.Fatalf("loadVerifiers() error = %v, want a no keys failure", err)
		}
	})

	t.Run("hashes reports enumeration errors", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
		wh := witnessHealth{root: root}
		if _, err := wh.hashes(); err == nil ||
			!strings.Contains(err.Error(), "failed to enumerate logs") {
			t.Fatalf("hashes error = %v, want an enumeration failure", err)
		}
	})
}

func newTestCosigner(t *testing.T, name string) *torchwood.CosignatureSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := torchwood.NewCosignatureSigner(name, priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// writeWitnessCheckpoint writes a checkpoint of the given size under dirHash,
// signed by signer. Its tree hash is not verified against tiles, so it need not
// correspond to any real tree.
func writeWitnessCheckpoint(t *testing.T, dir, origin, dirHash string, size int64, signer note.Signer) {
	t.Helper()
	treeHash := tlog.Hash(sha256.Sum256(fmt.Appendf(nil, "witness %d", size)))
	text := torchwood.Checkpoint{Origin: origin, Tree: tlog.Tree{N: size, Hash: treeHash}}.String()
	signed, err := note.Sign(&note.Note{Text: text}, signer)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, dirHash, "checkpoint"), signed)
}

// writeMirrorTree builds a tree of the given size with real tiles and writes it,
// along with a mirror checkpoint signed by signer, under dirHash/.
func writeMirrorTree(t *testing.T, dir, origin, dirHash string, size int64, signer note.Signer) {
	t.Helper()
	hashes := map[int64]tlog.Hash{}
	hr := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, x := range indexes {
			h, ok := hashes[x]
			if !ok {
				return nil, fmt.Errorf("missing stored hash %d", x)
			}
			out[i] = h
		}
		return out, nil
	})
	for i := range size {
		stored, err := tlog.StoredHashes(i, fmt.Appendf(nil, "record %d", i), hr)
		if err != nil {
			t.Fatal(err)
		}
		base := tlog.StoredHashIndex(0, i)
		for j, h := range stored {
			hashes[base+int64(j)] = h
		}
	}
	treeHash, err := tlog.TreeHash(size, hr)
	if err != nil {
		t.Fatal(err)
	}
	for _, tile := range tlog.NewTiles(torchwood.TileHeight, 0, size) {
		data, err := tlog.ReadTileData(tile, hr)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(dir, dirHash, torchwood.TilePath(tile)), data)
	}
	text := torchwood.Checkpoint{Origin: origin, Tree: tlog.Tree{N: size, Hash: treeHash}}.String()
	signed, err := note.Sign(&note.Note{Text: text}, signer)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, dirHash, "checkpoint"), signed)
}

// writeVerifierKeys writes a witness.v0.json or mirror.v0.json file listing
// the given verifier keys.
func writeVerifierKeys(t *testing.T, path string, vkeys ...string) {
	t.Helper()
	j, err := json.Marshal(map[string][]string{"verifier_keys": vkeys})
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, path, j)
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o666); err != nil {
		t.Fatal(err)
	}
}
