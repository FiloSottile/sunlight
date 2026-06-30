package witness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"filippo.io/mldsa"
	"filippo.io/sunlight/internal/ctlog"
	"filippo.io/torchwood"
	"github.com/prometheus/client_golang/prometheus"
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

// memBackend is an in-memory [ctlog.Backend] for tests.
type memBackend struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newMemBackend() *memBackend {
	return &memBackend{m: make(map[string][]byte)}
}

func (b *memBackend) Upload(ctx context.Context, key string, data []byte, opts *ctlog.UploadOptions) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.m[key] = bytes.Clone(data)
	return nil
}

func (b *memBackend) Fetch(ctx context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	data, ok := b.m[key]
	if !ok {
		return nil, fmt.Errorf("key %q not found", key)
	}
	return bytes.Clone(data), nil
}

func (b *memBackend) Discard(ctx context.Context, key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, key)
	return nil
}

func (b *memBackend) Metrics() []prometheus.Collector { return nil }

// newTestWitness returns a Witness named example.com/witness, already configured
// to witness origin with the given log verifier key and an empty stored
// checkpoint.
func newTestWitness(t *testing.T, origin, vkey string) *Witness {
	t.Helper()
	ctx := context.Background()
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	fatalIfErr(t, err)
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	fatalIfErr(t, err)
	config := &Config{
		Name:       "example.com/witness",
		KeyEd25519: ed25519Key,
		KeyMLDSA44: mldsaKey,
		Backend:    newMemBackend(),
		Lock:       newMemLockBackend(),
		Log:        slog.New(testLogHandler(t)),
	}
	// Seed the stored config and the empty checkpoint entry, as PullLogList
	// would, so NewWitness picks up the log.
	configJSON := fmt.Appendf(nil, `{"logs":[{"origin":%q,"verifierKeys":[%q]}]}`, origin, vkey)
	fatalIfErr(t, config.Lock.Create(ctx, backendKeyForConfig(config), configJSON))
	fatalIfErr(t, config.Lock.Create(ctx, backendKeyForCheckpoint(config, origin), nil))
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
		{
			name: "syntactically invalid note",
			body: `old 5

sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562
5
QrtXrQZCCvpIgsSmOsah7HdICzMLLyDfxToMql9WTjY=
`,
			wantCode: http.StatusBadRequest,
			wantBody: "invalid input",
		},
		{
			name: "invalid checkpoint body",
			body: `old 5

sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562
five
KgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

— sigsum.org/v1/tree/4d6d8825a6bb689d459628312889dfbb0bcd41b5211d9e1ce768b0ff0309e562 UgIom4JTC2MerrFcJ5xDcWHzRPVB6zzGBIw4OFqcKDflqjH4q4xY5vMxUxyczvdIlEwFYf7ivQU4KoWan2bLmzLx0go=
`,
			wantCode: http.StatusBadRequest,
			wantBody: "invalid checkpoint",
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
			if tt.wantCode == http.StatusOK {
				// A successful cosignature must be uploaded to the Backend at
				// <origin hash>/checkpoint, byte-identical to the checkpoint
				// held by the lock backend.
				key := OriginHash(sigsumOrigin) + "/checkpoint"
				got, err := w.c.Backend.Fetch(context.Background(), key)
				fatalIfErr(t, err)
				lock, err := w.c.Lock.Fetch(context.Background(), backendKeyForCheckpoint(w.c, sigsumOrigin))
				fatalIfErr(t, err)
				if !bytes.Equal(got, lock.Bytes()) {
					t.Errorf("backend checkpoint does not match locked checkpoint:\n backend: %q\n locked:  %q", got, lock.Bytes())
				}
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

// signTree signs a checkpoint for an arbitrary tree (size and root hash),
// allowing tests to construct otherwise-invalid checkpoints, such as a
// size-zero tree with a non-empty root.
func signTree(t *testing.T, signer note.Signer, origin string, tree tlog.Tree) []byte {
	t.Helper()
	text := torchwood.Checkpoint{Origin: origin, Tree: tree}.String()
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
	n, err := note.Open(full, note.VerifierList(w.s1.Verifier()))
	if err != nil {
		t.Fatalf("witness cosignature does not verify: %v", err)
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	fatalIfErr(t, err)
	if c.N != 5 {
		t.Errorf("cosigned tree size = %d, want 5", c.N)
	}
}

// TestResponseIsOnlyWitnessCosignature checks that the add-checkpoint response
// carries only the witness's own cosignature, not the log's signature, which the
// witness verifies and stores alongside its own but must not echo back.
func TestResponseIsOnlyWitnessCosignature(t *testing.T) {
	origin := "example.com/log"
	logSigner, vkey := newTestLog(t, origin)
	w := newTestWitness(t, origin, vkey)

	cp := signCheckpoint(t, logSigner, origin, [][]byte{{1}, {2}, {3}}, "")
	code, body := addCheckpoint(t, w, request(0, nil, cp))
	if code != http.StatusOK {
		t.Fatalf("cosigning: got %d, body %q", code, body)
	}

	if n := strings.Count(body, "— "); n != 2 {
		t.Errorf("response has %d signature lines, want 2 (only the witness's): %q", n, body)
	}
	if !strings.Contains(body, "— "+w.s1.Verifier().Name()+" ") {
		t.Errorf("response does not contain the witness's cosignature: %q", body)
	}
	if strings.Contains(body, "— "+origin+" ") {
		t.Errorf("response echoes the log's signature: %q", body)
	}

	full := append(append([]byte{}, cp...), body...)
	n, err := note.Open(full, note.VerifierList(w.s1.Verifier(), w.s2.Verifier()))
	fatalIfErr(t, err)
	var s1Found, s2Found bool
	for _, sig := range n.Sigs {
		switch sig.Hash {
		case w.s1.Verifier().KeyHash():
			s1Found = true
		case w.s2.Verifier().KeyHash():
			s2Found = true
		}
	}
	if !s1Found {
		t.Error("missing Ed25519 witness cosignature")
	}
	if !s2Found {
		t.Error("missing ML-DSA-44 witness cosignature")
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

// TestSizeZeroRequiresEmptyRoot checks that the witness refuses to cosign a
// size-zero checkpoint whose root is not the empty tree hash (the hash of the
// empty string, RFC 6962 Section 2.1), both on the first submission for a log
// and when a size-zero checkpoint is already stored. Otherwise a log could get
// two different checkpoints cosigned at size zero. https://c2sp.org/tlog-witness
func TestSizeZeroRequiresEmptyRoot(t *testing.T) {
	origin := "example.com/log"
	logSigner, vkey := newTestLog(t, origin)

	// A validly log-signed size-zero checkpoint with a non-empty root.
	var bogusRoot tlog.Hash
	bogusRoot[0] = 1
	bogus := signTree(t, logSigner, origin, tlog.Tree{N: 0, Hash: bogusRoot})

	t.Run("first submission", func(t *testing.T) {
		w := newTestWitness(t, origin, vkey)
		if code, body := addCheckpoint(t, w, request(0, nil, bogus)); code != http.StatusUnprocessableEntity {
			t.Fatalf("bogus size-0 root as first submission: got %d, want 422 (body %q)", code, body)
		}
	})

	t.Run("with stored size 0", func(t *testing.T) {
		w := newTestWitness(t, origin, vkey)
		// First cosign the genuine empty tree, leaving a stored size-0 checkpoint.
		cp0 := signCheckpoint(t, logSigner, origin, nil, "")
		if code, body := addCheckpoint(t, w, request(0, nil, cp0)); code != http.StatusOK {
			t.Fatalf("cosigning size 0: got %d, body %q", code, body)
		}
		// A second size-0 checkpoint with a different root must be rejected, not
		// cosigned as a second valid view of the log at size zero.
		if code, body := addCheckpoint(t, w, request(0, nil, bogus)); code != http.StatusUnprocessableEntity {
			t.Fatalf("bogus size-0 root over stored size 0: got %d, want 422 (body %q)", code, body)
		}
	})
}

// forgeWitnessSigLine builds a signature line keyed to the witness's own name
// and key hash but carrying a signature that cannot verify, as an attacker would
// append to a submitted checkpoint. The witness's own verifier is not in the set
// used at ingress (only the log's is), so note.Open treats this line as
// unverified there; but it matches the witness's (name, key hash) if the
// stored note is later re-opened with the witness's verifier.
func forgeWitnessSigLine(t *testing.T, w *Witness) string {
	t.Helper()
	v := w.s1.Verifier()
	var blob [4 + ed25519.SignatureSize]byte
	binary.BigEndian.PutUint32(blob[:4], v.KeyHash())
	// blob[4:] is left as zeros: a signature that cannot verify.
	return "— " + v.Name() + " " + base64.StdEncoding.EncodeToString(blob[:])
}

// TestForgedWitnessSigLineDoesNotPoisonState is a regression test for
// ANT-2026-SAPGR4D6. An attacker who appends a bogus signature line keyed to the
// witness's own name and key hash to an otherwise valid checkpoint must not be
// able to wedge the witness. The forged line is unverified at ingress, but if it
// were persisted verbatim it would make every later add-checkpoint request for
// that log fail when the stored note is re-opened with the witness's verifier.
func TestForgedWitnessSigLineDoesNotPoisonState(t *testing.T) {
	origin := "example.com/log"
	logSigner, vkey := newTestLog(t, origin)
	w := newTestWitness(t, origin, vkey)

	// A valid log-signed size-0 checkpoint, with a forged witness-keyed
	// signature line appended by the attacker.
	cp0 := signCheckpoint(t, logSigner, origin, nil, "")
	poisoned := append(append([]byte{}, cp0...), []byte(forgeWitnessSigLine(t, w)+"\n")...)

	// Ingress verifies only the log's signature, so the forged line is treated
	// as unverified and the request is accepted and cosigned.
	if code, body := addCheckpoint(t, w, request(0, nil, poisoned)); code != http.StatusOK {
		t.Fatalf("cosigning checkpoint with forged witness line: got %d, want 200 (body %q)", code, body)
	}

	// The witness must have stored only the signatures it verified plus its own,
	// so a subsequent legitimate request still succeeds. Before the fix the stored
	// note carried the forged line and this failed with 500.
	cp5 := signCheckpoint(t, logSigner, origin, [][]byte{{1}, {2}, {3}, {4}, {5}}, "")
	if code, body := addCheckpoint(t, w, request(0, nil, cp5)); code != http.StatusOK {
		t.Fatalf("growing after submit with forged witness line: got %d, want 200 (body %q)", code, body)
	}

	// The stored checkpoint must open under the witness's own verifier (so later
	// requests can re-open it) and must still carry a valid log signature (so the
	// witness can prove the checkpoint it cosigned was genuinely log-signed). The
	// forged line must be gone.
	lc, ok := w.checkpointForOrigin(origin)
	if !ok {
		t.Fatal("no stored checkpoint for origin")
	}
	stored := lc.Bytes()
	if _, err := note.Open(stored, note.VerifierList(w.s1.Verifier())); err != nil {
		t.Errorf("stored checkpoint does not open with witness verifier: %v", err)
	}
	logVerifier, err := note.NewVerifier(vkey)
	fatalIfErr(t, err)
	if _, err := note.Open(stored, note.VerifierList(logVerifier)); err != nil {
		t.Errorf("stored checkpoint does not retain a valid log signature: %v", err)
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
