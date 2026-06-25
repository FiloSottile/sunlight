package witness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"filippo.io/sunlight/internal/ctlog"
	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// memLockBackend is an in-memory [ctlog.LockBackend] for tests.
type memLockBackend struct {
	mu sync.Mutex
	m  map[[sha256.Size]byte][]byte
}

type memCheckpoint struct {
	logID [sha256.Size]byte
	data  []byte
}

func (c *memCheckpoint) Bytes() []byte { return c.data }

func newMemLockBackend() *memLockBackend {
	return &memLockBackend{m: make(map[[sha256.Size]byte][]byte)}
}

func (b *memLockBackend) Fetch(ctx context.Context, logID [sha256.Size]byte) (ctlog.LockedCheckpoint, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.m[logID]
	if !ok {
		return nil, ctlog.ErrLogNotFound
	}
	return &memCheckpoint{logID: logID, data: data}, nil
}

func (b *memLockBackend) Create(ctx context.Context, logID [sha256.Size]byte, new []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.m[logID]; ok {
		return fmt.Errorf("log %x already exists", logID)
	}
	b.m[logID] = new
	return nil
}

func (b *memLockBackend) Replace(ctx context.Context, old ctlog.LockedCheckpoint, new []byte) (ctlog.LockedCheckpoint, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	oldc := old.(*memCheckpoint)
	cur, ok := b.m[oldc.logID]
	if !ok {
		return nil, fmt.Errorf("log %x not found", oldc.logID)
	}
	if !bytes.Equal(cur, oldc.data) {
		return nil, fmt.Errorf("log %x has changed", oldc.logID)
	}
	b.m[oldc.logID] = new
	return &memCheckpoint{logID: oldc.logID, data: new}, nil
}

// newTestWitness returns a Witness named example.com/witness, already configured
// to witness origin with the given log verifier key and an empty stored
// checkpoint.
func newTestWitness(t *testing.T, origin, vkey string) *Witness {
	t.Helper()
	ctx := context.Background()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	fatalIfErr(t, err)
	config := &Config{
		Name:    "example.com/witness",
		Key:     key,
		Backend: newMemLockBackend(),
		Log:     slog.New(testLogHandler(t)),
	}
	// Seed the stored config and the empty checkpoint entry, as PullLogList
	// would, so NewWitness picks up the log.
	configJSON := fmt.Appendf(nil, `{"logs":[{"origin":%q,"verifierKeys":[%q]}]}`, origin, vkey)
	fatalIfErr(t, config.Backend.Create(ctx, backendKeyForConfig(config), configJSON))
	fatalIfErr(t, config.Backend.Create(ctx, backendKeyForCheckpoint(config, origin), nil))
	w, err := NewWitness(ctx, config)
	fatalIfErr(t, err)
	return w
}

// addCheckpoint posts an add-checkpoint request body to the witness Handler and
// returns the response status code and body.
func addCheckpoint(t *testing.T, w *Witness, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/add-checkpoint", strings.NewReader(body))
	rec := httptest.NewRecorder()
	w.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// sigsumOrigin and sigsumKey are the log used by the add-checkpoint.hurl test
// vectors in torchwood, reused here. The checkpoints and consistency proofs in
// TestAddCheckpoint are signed by the corresponding (gentest) private key.
const sigsumOrigin = "sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562"
const sigsumKey = "ffdc2d4d98e4124d3feaf788c0c2f9abfd796083d1f0495437f302ec79cf100f"

func TestAddCheckpoint(t *testing.T) {
	vkey, err := note.NewEd25519VerifierKey(sigsumOrigin, mustDecodeHex(t, sigsumKey))
	fatalIfErr(t, err)
	w := newTestWitness(t, sigsumOrigin, vkey)

	tests := []struct {
		name     string
		body     string
		wantCode int
		wantBody string
	}{
		{
			name: "first cosignature at size 1",
			body: `old 0

sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562
1
KgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIom7fPZTqpxWWhyjWduBvTvGVqsokMbqTArsQilegKoFBJQjUFAmQ0+YeSPM3wfUQMFSzVnnNuWRTYrajXpNUbIQY=
`,
			wantCode: http.StatusOK,
			wantBody: "— example.com/witness",
		},
		{
			name: "invalid signature",
			body: `old 1
KgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
KgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562
3
RcCI1Nk56ZcSmIEfIn0SleqtV7uvrlXNccFx595Iwl0=

— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIom2VbtIcdFbwFAy1n7s6IkAxIY6J/GQOTuZF2ORV39d75cbAj2aQYwyJre36kezNobZs4SUUdrcawfAB8WVrx6gx=
`,
			wantCode: http.StatusForbidden,
			wantBody: "invalid signature",
		},
		{
			name: "unknown log",
			body: `old 1
KgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
KgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e563
3
RcCI1Nk56ZcSmIEfIn0SleqtV7uvrlXNccFx595Iwl0=

— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e563 UgIom2VbtIcdFbwFAy1n7s6IkAxIY6J/GQOTuZF2ORV39d75cbAj2aQYwyJre36kezNobZs4SUUdrcawfAB8WVrx6go=
`,
			wantCode: http.StatusNotFound,
			wantBody: "unknown log",
		},
		{
			name: "missing consistency proof",
			body: `old 1

sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562
3
RcCI1Nk56ZcSmIEfIn0SleqtV7uvrlXNccFx595Iwl0=

— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIom2VbtIcdFbwFAy1n7s6IkAxIY6J/GQOTuZF2ORV39d75cbAj2aQYwyJre36kezNobZs4SUUdrcawfAB8WVrx6go=
`,
			wantCode: http.StatusUnprocessableEntity,
			wantBody: "consistency proof",
		},
		{
			name: "wrong consistency proof",
			body: `old 1
KgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
KgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABA=

sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562
3
RcCI1Nk56ZcSmIEfIn0SleqtV7uvrlXNccFx595Iwl0=

— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIom2VbtIcdFbwFAy1n7s6IkAxIY6J/GQOTuZF2ORV39d75cbAj2aQYwyJre36kezNobZs4SUUdrcawfAB8WVrx6go=
`,
			wantCode: http.StatusUnprocessableEntity,
			wantBody: "consistency proof",
		},
		{
			name: "grow to size 3",
			body: `old 1
KgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
KgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562
3
RcCI1Nk56ZcSmIEfIn0SleqtV7uvrlXNccFx595Iwl0=

— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIom2VbtIcdFbwFAy1n7s6IkAxIY6J/GQOTuZF2ORV39d75cbAj2aQYwyJre36kezNobZs4SUUdrcawfAB8WVrx6go=
`,
			wantCode: http.StatusOK,
			wantBody: "— example.com/witness",
		},
		{
			name: "old size doesn't match current",
			body: `old 1
KgEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
+fUDV+k970B4I3uKrqJM4aP1lloPZP8mvr2Z4wRw2LI=
KgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562
5
QrtXrQZCCvpIgsSmOsah7HdICzMLLyDfxToMql9WTjY=

— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIomw/EOJmWi0i1FQsOj+etB7F8IccFam/jgd6wzRns4QPVmyEZtdvl1U2KEmLOZ/ASRcWJi0tW90dJWAShei7sDww=
`,
			wantCode: http.StatusConflict,
			wantBody: "3\n",
		},
		{
			name: "grow to size 5",
			body: `old 3
KgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
KgMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
wgiIFdZfYNv6WU1OllBKsWnLYIS/DBMqt8Uh/S4OukE=
KgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562
5
QrtXrQZCCvpIgsSmOsah7HdICzMLLyDfxToMql9WTjY=

— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIomw/EOJmWi0i1FQsOj+etB7F8IccFam/jgd6wzRns4QPVmyEZtdvl1U2KEmLOZ/ASRcWJi0tW90dJWAShei7sDww=
`,
			wantCode: http.StatusOK,
			wantBody: "— example.com/witness",
		},
		{
			name: "old size 0 doesn't match current",
			body: `old 0

sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562
5
QrtXrQZCCvpIgsSmOsah7HdICzMLLyDfxToMql9WTjY=

— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIomw/EOJmWi0i1FQsOj+etB7F8IccFam/jgd6wzRns4QPVmyEZtdvl1U2KEmLOZ/ASRcWJi0tW90dJWAShei7sDww=
`,
			wantCode: http.StatusConflict,
			wantBody: "5\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, body := addCheckpoint(t, w, tt.body)
			if code != tt.wantCode {
				t.Errorf("got status %d, want %d (body %q)", code, tt.wantCode, body)
			}
			if !strings.Contains(body, tt.wantBody) {
				t.Errorf("body %q does not contain %q", body, tt.wantBody)
			}
		})
	}
}

// newTestLog returns a note signer for a log and the corresponding vkey, for
// tests that need to sign their own checkpoints.
func newTestLog(t *testing.T, origin string) (note.Signer, string) {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	fatalIfErr(t, err)
	signer, err := note.NewSigner(skey)
	fatalIfErr(t, err)
	return signer, vkey
}

// treeHash returns the RFC 6962 Merkle tree hash of the given leaves.
func treeHash(t *testing.T, leaves [][]byte) tlog.Hash {
	t.Helper()
	var hashes []tlog.Hash
	r := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, x := range indexes {
			out[i] = hashes[x]
		}
		return out, nil
	})
	for i, leaf := range leaves {
		h, err := tlog.StoredHashes(int64(i), leaf, r)
		fatalIfErr(t, err)
		hashes = append(hashes, h...)
	}
	h, err := tlog.TreeHash(int64(len(leaves)), r)
	fatalIfErr(t, err)
	return h
}

// signCheckpoint produces a checkpoint note for a tree over the given leaves,
// signed by signer. extension, if non-empty, is appended as checkpoint
// extension lines and must end with a newline.
func signCheckpoint(t *testing.T, signer note.Signer, origin string, leaves [][]byte, extension string) []byte {
	t.Helper()
	text := torchwood.Checkpoint{
		Origin:    origin,
		Tree:      tlog.Tree{N: int64(len(leaves)), Hash: treeHash(t, leaves)},
		Extension: extension,
	}.String()
	signed, err := note.Sign(&note.Note{Text: text}, signer)
	fatalIfErr(t, err)
	return signed
}

// request builds an add-checkpoint request body.
func request(oldSize int64, proof []string, signedCheckpoint []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "old %d\n", oldSize)
	for _, p := range proof {
		b.WriteString(p)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.Write(signedCheckpoint)
	return b.String()
}

// TestRejectsExtensions checks that checkpoints with extension lines are
// rejected, rather than being cosigned with a signature that doesn't cover the
// extension lines.
func TestRejectsExtensions(t *testing.T) {
	origin := "example.com/log"
	logSigner, vkey := newTestLog(t, origin)
	w := newTestWitness(t, origin, vkey)

	cp := signCheckpoint(t, logSigner, origin, [][]byte{{1}, {2}, {3}}, "extra extension line\n")

	// processAddCheckpointRequest must return errExtensions without signing.
	cosig, err := w.processAddCheckpointRequest(context.Background(), []byte(request(0, nil, cp)))
	if err != errExtensions {
		t.Fatalf("got err %v, want errExtensions", err)
	}
	if cosig != nil {
		t.Errorf("got cosignature %q, want none", cosig)
	}

	// Through the Handler, it must map to a 400 Bad Request.
	code, body := addCheckpoint(t, w, request(0, nil, cp))
	if code != http.StatusBadRequest {
		t.Errorf("got status %d, want 400", code)
	}
	if !strings.Contains(body, "extension") {
		t.Errorf("response body %q does not mention extensions", body)
	}
}

// TestGrowFromSizeZero checks that a log which first cosigns an empty (size 0)
// tree can subsequently grow. The consistency proof from size 0 is empty, so no
// proof is checked.
func TestGrowFromSizeZero(t *testing.T) {
	origin := "example.com/log"
	logSigner, vkey := newTestLog(t, origin)
	w := newTestWitness(t, origin, vkey)

	// First cosign the empty tree.
	cp0 := signCheckpoint(t, logSigner, origin, nil, "")
	if code, body := addCheckpoint(t, w, request(0, nil, cp0)); code != http.StatusOK {
		t.Fatalf("cosigning size 0: got %d, body %q", code, body)
	}

	// Grow from the stored size 0 to size 5 with an empty proof.
	cp5 := signCheckpoint(t, logSigner, origin, [][]byte{{1}, {2}, {3}, {4}, {5}}, "")
	code, body := addCheckpoint(t, w, request(0, nil, cp5))
	if code != http.StatusOK {
		t.Fatalf("growing from size 0: got %d, body %q", code, body)
	}

	// The returned cosignature must verify against the submitted checkpoint and
	// cover the whole size-5 tree.
	full := append(append([]byte{}, cp5...), body...)
	n, err := note.Open(full, note.VerifierList(w.s.Verifier()))
	if err != nil {
		t.Fatalf("witness cosignature does not verify: %v", err)
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	fatalIfErr(t, err)
	if c.N != 5 {
		t.Errorf("cosigned tree size = %d, want 5", c.N)
	}
}

// TestSizeZeroRejectsProof checks that a non-empty proof is rejected when
// growing from a stored size 0, since the consistency proof from size 0 must be
// empty.
func TestSizeZeroRejectsProof(t *testing.T) {
	origin := "example.com/log"
	logSigner, vkey := newTestLog(t, origin)
	w := newTestWitness(t, origin, vkey)

	cp0 := signCheckpoint(t, logSigner, origin, nil, "")
	if code, body := addCheckpoint(t, w, request(0, nil, cp0)); code != http.StatusOK {
		t.Fatalf("cosigning size 0: got %d, body %q", code, body)
	}

	cp5 := signCheckpoint(t, logSigner, origin, [][]byte{{1}, {2}, {3}, {4}, {5}}, "")
	bogusHash := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	if code, body := addCheckpoint(t, w, request(0, []string{bogusHash}, cp5)); code != http.StatusUnprocessableEntity {
		t.Fatalf("non-empty proof from size 0: got %d, want 422 (body %q)", code, body)
	}
}

func testLogHandler(t testing.TB) slog.Handler {
	return slog.NewTextHandler(writerFunc(func(p []byte) (n int, err error) {
		t.Logf("%s", p)
		return len(p), nil
	}), &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				src := a.Value.Any().(*slog.Source)
				a.Value = slog.StringValue(fmt.Sprintf("%s:%d", filepath.Base(src.File), src.Line))
			}
			return a
		},
	})
}

type writerFunc func(p []byte) (n int, err error)

func (f writerFunc) Write(p []byte) (n int, err error) {
	return f(p)
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	fatalIfErr(t, err)
	return b
}

func fatalIfErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
