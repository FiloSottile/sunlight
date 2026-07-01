package witness

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"filippo.io/mldsa"
	"filippo.io/sunlight/internal/ctlog"
	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// newTestMirrorWitness returns a Witness named example.com/witness with a
// mirror named example.com/mirror, already configured to mirror the given
// logs with empty stored checkpoints.
func newTestMirrorWitness(t *testing.T, logs ...*testMirrorLog) *Witness {
	t.Helper()
	ctx := context.Background()
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	fatalIfErr(t, err)
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	fatalIfErr(t, err)
	mirrorKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	fatalIfErr(t, err)
	config := &Config{
		Name:       "example.com/witness",
		KeyEd25519: ed25519Key,
		KeyMLDSA44: mldsaKey,
		MirrorName: "example.com/mirror",
		KeyMirror:  mirrorKey,
		Backend:    newMemBackend(),
		Lock:       newMemLockBackend(),
		Log:        slog.New(testLogHandler(t)),
	}
	states := make([]string, 0, len(logs))
	for _, l := range logs {
		states = append(states, fmt.Sprintf(`%q:{"Verifiers":[%q],"Mirror":true}`, l.origin, l.vkey))
	}
	configJSON := fmt.Appendf(nil, `{"log_meta":{%s}}`, strings.Join(states, ","))
	fatalIfErr(t, config.Lock.Create(ctx, backendKeyForConfig(config), configJSON))
	for _, l := range logs {
		fatalIfErr(t, config.Lock.Create(ctx, backendKeyForCheckpoint(config, l.origin), nil))
		fatalIfErr(t, config.Lock.Create(ctx, backendKeyForMirrorCheckpoint(config, l.origin), nil))
	}
	// Check the serving invariant on every mirror checkpoint signing,
	// including by witnesses restarted with restartWitness.
	mirrorKeys := make(map[[sha256.Size]byte]string)
	for _, l := range logs {
		mirrorKeys[backendKeyForMirrorCheckpoint(config, l.origin)] = l.origin
	}
	config.Lock = &mirrorCommitCheckingLock{LockBackend: config.Lock, t: t,
		backend: config.Backend, mirrorKeys: mirrorKeys}
	w, err := NewWitness(ctx, config)
	fatalIfErr(t, err)
	return w
}

// mirrorCommitCheckingLock wraps the test LockBackend to check, every time a
// mirror checkpoint is about to be persisted, that the tree it signs is fully
// servable from the data backend.
type mirrorCommitCheckingLock struct {
	ctlog.LockBackend
	t          *testing.T
	backend    ctlog.Backend
	mirrorKeys map[[sha256.Size]byte]string
}

func (l *mirrorCommitCheckingLock) Replace(ctx context.Context, old ctlog.LockedCheckpoint, new []byte) (ctlog.LockedCheckpoint, error) {
	if origin, ok := l.mirrorKeys[old.(*memCheckpoint).logID]; ok {
		text, _, found := bytes.Cut(new, []byte("\n\n"))
		if !found {
			l.t.Errorf("mirror checkpoint for %s being persisted is not a note:\n%s", origin, new)
		} else if c, err := torchwood.ParseCheckpoint(string(text) + "\n"); err != nil {
			l.t.Errorf("mirror checkpoint for %s being persisted does not parse: %v", origin, err)
		} else if c.Origin != origin {
			l.t.Errorf("mirror checkpoint being persisted has origin %q, want %q", c.Origin, origin)
		} else {
			checkMirrorTilesAvailable(l.t, l.backend, origin, c.N)
		}
	}
	return l.LockBackend.Replace(ctx, old, new)
}

// checkMirrorTilesAvailable checks the tlog-tiles serving invariant of the
// mirror copy of a log at the given tree size: every hash and data tile
// implied by the size must be fetchable, either at its exact width or, for
// partial tiles, as the corresponding full tile that clients fall back to.
//
// A mirror checkpoint must never be signed for a tree that is not fully
// servable.
func checkMirrorTilesAvailable(t *testing.T, b ctlog.Backend, origin string, size int64) {
	t.Helper()
	ctx := context.Background()
	prefix := "mirror/" + OriginHash(origin) + "/"
	fetch := func(tile tlog.Tile) error {
		_, err := b.Fetch(ctx, prefix+torchwood.TilePath(tile))
		if err != nil && tile.W < 256 {
			tile.W = 256
			_, err = b.Fetch(ctx, prefix+torchwood.TilePath(tile))
		}
		return err
	}
	for _, tile := range tlog.NewTiles(torchwood.TileHeight, 0, size) {
		if err := fetch(tile); err != nil {
			t.Errorf("mirror checkpoint signed at size %d without hash tile %v: %v", size, tile, err)
		}
	}
	for i := int64(0); i*256 < size; i++ {
		tile := tlog.Tile{H: torchwood.TileHeight, L: -1, N: i, W: int(min(256, size-i*256))}
		if err := fetch(tile); err != nil {
			t.Errorf("mirror checkpoint signed at size %d without data tile %v: %v", size, tile, err)
		}
	}
}

// testMirrorLog is an in-memory tlog with a note signing key.
type testMirrorLog struct {
	origin  string
	signer  note.Signer
	vkey    string
	tree    *torchwood.HashReaderOverlay
	entries [][]byte
}

func newTestMirrorLog(t *testing.T, origin string) *testMirrorLog {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	fatalIfErr(t, err)
	signer, err := note.NewSigner(skey)
	fatalIfErr(t, err)
	return &testMirrorLog{
		origin: origin, signer: signer, vkey: vkey,
		tree: torchwood.NewHashReaderOverlay(0, nil),
	}
}

func (l *testMirrorLog) grow(t *testing.T, n int) {
	t.Helper()
	for range n {
		e := fmt.Appendf(nil, "this is entry %d of %s", len(l.entries), l.origin)
		l.entries = append(l.entries, e)
		fatalIfErr(t, l.tree.AppendRecordHash(tlog.RecordHash(e)))
	}
}

func (l *testMirrorLog) treeHash(t *testing.T, size int64) tlog.Hash {
	t.Helper()
	h, err := tlog.TreeHash(size, l.tree)
	fatalIfErr(t, err)
	return h
}

func (l *testMirrorLog) checkpoint(t *testing.T, size int64) string {
	t.Helper()
	n, err := note.Sign(&note.Note{Text: torchwood.Checkpoint{
		Origin: l.origin, Tree: tlog.Tree{N: size, Hash: l.treeHash(t, size)},
	}.String()}, l.signer)
	fatalIfErr(t, err)
	return string(n)
}

// addCheckpointBody builds an add-checkpoint request body proving consistency
// from oldSize to newSize.
func (l *testMirrorLog) addCheckpointBody(t *testing.T, oldSize, newSize int64) string {
	t.Helper()
	body := fmt.Sprintf("old %d\n", oldSize)
	if oldSize > 0 {
		proof, err := tlog.ProveTree(newSize, oldSize, l.tree)
		fatalIfErr(t, err)
		for _, h := range proof {
			body += h.String() + "\n"
		}
	}
	return body + "\n" + l.checkpoint(t, newSize)
}

// addEntriesBody builds an add-entries request body for [start, end) with the
// canonical package sequence, proving against the tree at size treeSize. If
// maxPackages is greater than zero, only the first maxPackages packages are
// included, as a deliberate prefix upload.
func (l *testMirrorLog) addEntriesBody(t *testing.T, start, end, treeSize int64, ticket []byte, maxPackages int) []byte {
	t.Helper()
	var b []byte
	b = binary.BigEndian.AppendUint16(b, uint16(len(l.origin)))
	b = append(b, l.origin...)
	b = binary.BigEndian.AppendUint64(b, uint64(start))
	b = binary.BigEndian.AppendUint64(b, uint64(end))
	b = binary.BigEndian.AppendUint16(b, uint16(len(ticket)))
	b = append(b, ticket...)
	if start == end {
		return b
	}
	roundedStart := start - start%256
	roundedEnd := (end + 255) / 256 * 256
	numPackages := (roundedEnd - roundedStart) / 256
	if maxPackages > 0 {
		numPackages = min(numPackages, int64(maxPackages))
	}
	for i := range numPackages {
		ts := roundedStart + i*256
		ps := max(start, ts)
		pe := min(end, ts+256)
		for _, e := range l.entries[ps:pe] {
			b = binary.BigEndian.AppendUint16(b, uint16(len(e)))
			b = append(b, e...)
		}
		proof, err := torchwood.ProveSubtree(treeSize, ts, pe, l.tree)
		fatalIfErr(t, err)
		b = append(b, byte(len(proof)))
		for _, h := range proof {
			b = append(b, h[:]...)
		}
	}
	return b
}

func postAddEntries(t *testing.T, w *Witness, body []byte) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/add-entries", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	w.Handler().ServeHTTP(rec, req)
	checkAddEntriesResponse(t, rec)
	return rec.Code, rec.Body.String()
}

func postAddEntriesGzip(t *testing.T, w *Witness, body []byte) (int, string) {
	t.Helper()
	buf := &bytes.Buffer{}
	gz := gzip.NewWriter(buf)
	_, err := gz.Write(body)
	fatalIfErr(t, err)
	fatalIfErr(t, gz.Close())
	req := httptest.NewRequest("POST", "/add-entries", buf)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "gzip")
	rec := httptest.NewRecorder()
	w.Handler().ServeHTTP(rec, req)
	checkAddEntriesResponse(t, rec)
	return rec.Code, rec.Body.String()
}

// checkAddEntriesResponse asserts invariants of every add-entries response:
// the Accept-Encoding header advertising compression support, and the
// mirror-info content type on "409 Conflict" and "202 Accepted" responses.
func checkAddEntriesResponse(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("Accept-Encoding"); !strings.Contains(got, "gzip") {
		t.Errorf("add-entries response Accept-Encoding %q does not include gzip", got)
	}
	if rec.Code == http.StatusConflict || rec.Code == http.StatusAccepted {
		if got := rec.Header().Get("Content-Type"); got != "text/x.tlog.mirror-info" {
			t.Errorf("mirror-info response has Content-Type %q", got)
		}
	}
}

// parseMirrorInfo parses the three lines of a text/x.tlog.mirror-info response
// body, as returned with "409 Conflict" and "202 Accepted" responses.
func parseMirrorInfo(t *testing.T, body string) (pending, next int64, ticket []byte) {
	t.Helper()
	lines := strings.Split(body, "\n")
	if len(lines) != 4 || lines[3] != "" {
		t.Fatalf("malformed mirror-info body %q", body)
	}
	pending, err := strconv.ParseInt(lines[0], 10, 64)
	fatalIfErr(t, err)
	next, err = strconv.ParseInt(lines[1], 10, 64)
	fatalIfErr(t, err)
	ticket, err = base64.StdEncoding.DecodeString(lines[2])
	fatalIfErr(t, err)
	// A next entry ahead of the pending size would have the client retry with
	// upload_start greater than upload_end.
	if next > pending {
		t.Errorf("mirror-info next entry %d is ahead of the pending size %d", next, pending)
	}
	return pending, next, ticket
}

// checkMirrorSigs verifies that body, a successful add-entries response,
// consists only of mirror cosignature lines, and that they verify over the
// log's checkpoint at the given tree size.
func checkMirrorSigs(t *testing.T, w *Witness, log *testMirrorLog, size int64, body string) {
	t.Helper()
	if body == "" {
		t.Fatal("empty add-entries success response body")
	}
	var lines int
	for line := range strings.Lines(body) {
		if !strings.HasPrefix(line, "— example.com/mirror ") {
			t.Errorf("unexpected line in add-entries response: %q", line)
		}
		lines++
	}
	text := torchwood.Checkpoint{
		Origin: log.origin, Tree: tlog.Tree{N: size, Hash: log.treeHash(t, size)},
	}.String()
	n, err := note.Open([]byte(text+"\n"+body), note.VerifierList(w.sm.Verifier()))
	if err != nil {
		t.Errorf("mirror cosignature does not verify over the checkpoint at size %d: %v\nbody: %q", size, err, body)
	} else if len(n.Sigs) != lines {
		// Every line must be a verified signature: note.Open succeeds even if
		// some signatures are from unknown keys, as long as one verifies.
		t.Errorf("%d signature lines, but %d verified mirror cosignatures\nbody: %q", lines, len(n.Sigs), body)
	}
}

// checkMirrorTree checks the mirror's public state for the log against the
// source: the mirror checkpoint carries the log's signature and the mirror's
// cosignature over the tree of the given size, and the hash and data tiles
// match the log's. A partial tile may be missing if it was superseded by a
// full tile, which clients are expected to use instead.
func checkMirrorTree(t *testing.T, w *Witness, log *testMirrorLog, size int64) {
	t.Helper()
	ctx := context.Background()
	prefix := "mirror/" + OriginHash(log.origin) + "/"

	checkpoint, err := w.c.Backend.Fetch(ctx, prefix+"checkpoint")
	fatalIfErr(t, err)
	logVerifier, err := note.NewVerifier(log.vkey)
	fatalIfErr(t, err)
	n, err := note.Open(checkpoint, note.VerifierList(logVerifier, w.sm.Verifier()))
	if err != nil {
		t.Fatalf("can't open mirror checkpoint: %v\n%s", err, checkpoint)
	}
	var logSig, mirrorSig bool
	for _, sig := range n.Sigs {
		switch sig.Hash {
		case logVerifier.KeyHash():
			logSig = true
		case w.sm.Verifier().KeyHash():
			mirrorSig = true
		}
	}
	if !logSig {
		t.Errorf("mirror checkpoint is missing the log signature:\n%s", checkpoint)
	}
	if !mirrorSig {
		t.Errorf("mirror checkpoint is missing the mirror cosignature:\n%s", checkpoint)
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	fatalIfErr(t, err)
	if c.N != size || c.Hash != log.treeHash(t, size) {
		t.Errorf("mirror checkpoint does not match the log at size %d:\n%s", size, checkpoint)
	}

	fetchTile := func(tile tlog.Tile) []byte {
		t.Helper()
		data, err := w.c.Backend.Fetch(ctx, prefix+torchwood.TilePath(tile))
		if err != nil && tile.W < 256 {
			tile.W = 256
			data, err = w.c.Backend.Fetch(ctx, prefix+torchwood.TilePath(tile))
		}
		if err != nil {
			t.Fatalf("missing tile %v: %v", tile, err)
		}
		return data
	}

	for _, tile := range tlog.NewTiles(torchwood.TileHeight, 0, size) {
		want, err := tlog.ReadTileData(tile, log.tree)
		fatalIfErr(t, err)
		data := fetchTile(tile)
		if len(data) < len(want) || !bytes.Equal(data[:len(want)], want) {
			t.Errorf("hash tile %v does not match the log", tile)
		}
	}

	for i := int64(0); i*256 < size; i++ {
		tile := tlog.Tile{H: torchwood.TileHeight, L: -1, N: i, W: int(min(256, size-i*256))}
		gz, err := gzip.NewReader(bytes.NewReader(fetchTile(tile)))
		fatalIfErr(t, err)
		data, err := io.ReadAll(gz)
		fatalIfErr(t, err)
		for j := range int64(tile.W) {
			var entry []byte
			entry, data, err = torchwood.ReadTileEntry(data)
			fatalIfErr(t, err)
			if !bytes.Equal(entry, log.entries[i*256+j]) {
				t.Errorf("entry %d in data tile %d does not match the log", i*256+j, i)
			}
		}
	}
}

func TestMirrorEndToEnd(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)

	// Grow the log to 600 entries and witness the checkpoint. The witness
	// signs the pending checkpoint, but the mirror cosigner must not.
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}
	if strings.Contains(body, "— example.com/mirror") {
		t.Errorf("add-checkpoint response contains a mirror cosignature: %q", body)
	}

	// The published pending checkpoint retains the log's signature, and
	// carries no mirror cosignature either.
	pendingCheckpoint, err := w.c.Backend.Fetch(context.Background(), OriginHash(log.origin)+"/checkpoint")
	fatalIfErr(t, err)
	logVerifier, err := note.NewVerifier(log.vkey)
	fatalIfErr(t, err)
	if _, err := note.Open(pendingCheckpoint, note.VerifierList(logVerifier)); err != nil {
		t.Errorf("pending checkpoint does not retain the log signature: %v\n%s", err, pendingCheckpoint)
	}
	if strings.Contains(string(pendingCheckpoint), "— example.com/mirror") {
		t.Errorf("pending checkpoint carries a mirror cosignature:\n%s", pendingCheckpoint)
	}

	// Upload all 600 entries in one request.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [0, 600): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 600, body)
	checkMirrorTree(t, w, log, 600)

	// A no-op submission should refresh the mirror signature.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 600, 600, 600, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("no-op add-entries: got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 600, body)

	// Grow the log to 1200 entries, witness, and upload the rest.
	log.grow(t, 600)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 600, 1200))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 600->1200: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 600, 1200, 1200, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [600, 1200): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 1200, body)
	checkMirrorTree(t, w, log, 1200)
}

func TestMirrorBadProof(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 300)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 300))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}

	// A corrupted entry makes the reconstructed subtree hash mismatch the
	// proof, and nothing is saved.
	b := log.addEntriesBody(t, 0, 300, 300, nil, 0)
	headerLen := 2 + len(log.origin) + 8 + 8 + 2
	b[headerLen+2] ^= 1 // corrupt the first byte of the first entry
	code, body = postAddEntries(t, w, b)
	if code != http.StatusUnprocessableEntity {
		t.Errorf("bad entry: got %d, want 422 (body %q)", code, body)
	}

	// A corrupted proof hash in the second package is also a 422, but the
	// first package was verified and saved before processing ended.
	b = log.addEntriesBody(t, 0, 300, 300, nil, 0)
	b[len(b)-1] ^= 1 // corrupt the last proof hash
	code, body = postAddEntries(t, w, b)
	if code != http.StatusUnprocessableEntity {
		t.Errorf("bad proof: got %d, want 422 (body %q)", code, body)
	}

	// The first package's progress was retained, and no mirror checkpoint
	// was published.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [0, 0): got %d, want 409 (body %q)", code, body)
	}
	pending, next, _ := parseMirrorInfo(t, body)
	if pending != 300 || next != 256 {
		t.Errorf("got pending %d and next %d, want 300 and 256", pending, next)
	}
	if _, err := w.c.Backend.Fetch(context.Background(), "mirror/"+OriginHash(log.origin)+"/checkpoint"); err == nil {
		t.Errorf("mirror checkpoint published after failed uploads")
	}
}

// TestMirrorPrefix exercises deliberate and truncated prefix uploads, per the
// 400 and "202 Accepted" flows of c2sp.org/tlog-mirror.
func TestMirrorPrefix(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}

	// A body that ends before the first package is a 400.
	full := log.addEntriesBody(t, 0, 600, 600, nil, 0)
	headerLen := 2 + len(log.origin) + 8 + 8 + 2
	code, body = postAddEntries(t, w, full[:headerLen])
	if code != http.StatusBadRequest {
		t.Errorf("empty prefix: got %d, want 400 (body %q)", code, body)
	}

	// So is one that ends in the middle of the first package.
	code, body = postAddEntries(t, w, full[:headerLen+10])
	if code != http.StatusBadRequest {
		t.Errorf("truncated first package: got %d, want 400 (body %q)", code, body)
	}

	// And one that ends at the first package's num_hashes byte, or in the
	// middle of its proof hashes.
	proof1, err := torchwood.ProveSubtree(600, 0, 256, log.tree)
	fatalIfErr(t, err)
	b := log.addEntriesBody(t, 0, 600, 600, nil, 1)
	entriesEnd := len(b) - 1 - 32*len(proof1)
	for _, cut := range []int{entriesEnd, entriesEnd + 1 + 16} {
		code, body = postAddEntries(t, w, b[:cut])
		if code != http.StatusBadRequest {
			t.Errorf("truncated first package at %d: got %d, want 400 (body %q)", cut, code, body)
		}
	}

	// A one-package upload followed by a truncated package commits the
	// complete package, discards the partial bytes, and returns a 202.
	b = log.addEntriesBody(t, 0, 600, 600, nil, 1)
	b = append(b, 0x00, 0x64, 0x01, 0x02, 0x03) // a truncated second package
	code, body = postAddEntries(t, w, b)
	if code != http.StatusAccepted {
		t.Fatalf("truncated second package: got %d, want 202 (body %q)", code, body)
	}
	pending, next, _ := parseMirrorInfo(t, body)
	if pending != 600 || next != 256 {
		t.Errorf("got pending %d and next %d, want 600 and 256", pending, next)
	}

	// The same, with the second package truncated at its num_hashes byte or
	// in the middle of its proof hashes.
	proof2, err := torchwood.ProveSubtree(600, 256, 512, log.tree)
	fatalIfErr(t, err)
	b = log.addEntriesBody(t, 0, 600, 600, nil, 2)
	entriesEnd = len(b) - 1 - 32*len(proof2)
	for _, cut := range []int{entriesEnd, entriesEnd + 1 + 16} {
		code, body = postAddEntries(t, w, b[:cut])
		if code != http.StatusAccepted {
			t.Fatalf("truncated second package at %d: got %d, want 202 (body %q)", cut, code, body)
		}
		pending, next, _ = parseMirrorInfo(t, body)
		if pending != 600 || next != 256 {
			t.Errorf("got pending %d and next %d, want 600 and 256", pending, next)
		}
	}

	// A deliberate one-package prefix advances the next entry.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 256, 600, 600, nil, 1))
	if code != http.StatusAccepted {
		t.Fatalf("prefix [256, 512): got %d, want 202 (body %q)", code, body)
	}
	pending, next, _ = parseMirrorInfo(t, body)
	if pending != 600 || next != 512 {
		t.Errorf("got pending %d and next %d, want 600 and 512", pending, next)
	}

	// The last request completes the upload.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 512, 600, 600, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [512, 600): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 600, body)
	checkMirrorTree(t, w, log, 600)
}

// TestMirrorTicket exercises recovering a previous pending checkpoint from the
// ticket after the pending checkpoint has moved on.
func TestMirrorTicket(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}

	// Upload a two-package prefix, obtaining a ticket for checkpoint 600.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 2))
	if code != http.StatusAccepted {
		t.Fatalf("prefix [0, 512): got %d, want 202 (body %q)", code, body)
	}
	pending, next, ticket := parseMirrorInfo(t, body)
	if pending != 600 || next != 512 {
		t.Errorf("got pending %d and next %d, want 600 and 512", pending, next)
	}

	// The pending checkpoint moves on before the client can finish.
	log.grow(t, 600)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 600, 1200))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 600->1200: got %d, body %q", code, body)
	}

	// Without a ticket, upload_end 600 is not a known checkpoint anymore.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 512, 600, 600, nil, 0))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [512, 600) without ticket: got %d, want 409 (body %q)", code, body)
	}
	pending, next, _ = parseMirrorInfo(t, body)
	if pending != 1200 || next != 512 {
		t.Errorf("got pending %d and next %d, want 1200 and 512", pending, next)
	}

	// With the ticket, the upload completes, and the mirror checkpoint is
	// updated to 600 even if the pending checkpoint is at 1200.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 512, 600, 600, ticket, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [512, 600) with ticket: got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 600, body)
	checkMirrorTree(t, w, log, 600)

	// Catching up to the pending checkpoint still works.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 600, 1200, 1200, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [600, 1200): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 1200, body)
	checkMirrorTree(t, w, log, 1200)
}

// TestMirrorLargeLog uploads a log that crosses the 65 536-entry level 1 tile
// boundary twice, so that a level 2 tile is first produced and then read back
// from the backend, in gzip-compressed prefix requests.
func TestMirrorLargeLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)

	const size = 2*65536 + 300
	log.grow(t, size)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, size))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}

	// Upload in prefixes of 32 packages, following the 202 responses, per the
	// client guidance in c2sp.org/tlog-mirror.
	const chunk = 32
	next := int64(0)
	for {
		b := log.addEntriesBody(t, next, size, size, nil, chunk)
		code, body := postAddEntriesGzip(t, w, b)
		if next+chunk*256 >= size {
			if code != http.StatusOK {
				t.Fatalf("add-entries [%d, %d): got %d, body %q", next, size, code, body)
			}
			checkMirrorSigs(t, w, log, size, body)
			break
		}
		if code != http.StatusAccepted {
			t.Fatalf("add-entries [%d, %d): got %d, want 202 (body %q)", next, size, code, body)
		}
		pending, n, _ := parseMirrorInfo(t, body)
		if pending != size {
			t.Errorf("got pending %d, want %d", pending, size)
		}
		if n != next+chunk*256 {
			t.Errorf("got next %d, want %d", n, next+chunk*256)
		}
		next = n
	}

	// Check that the level 2 tile produced when the second level 1 tile
	// completed matches the log's own hashes.
	tile := tlog.Tile{H: torchwood.TileHeight, L: 2, N: 0, W: 2}
	key := "mirror/" + OriginHash(log.origin) + "/" + torchwood.TilePath(tile)
	data, err := w.c.Backend.Fetch(context.Background(), key)
	fatalIfErr(t, err)
	want, err := log.tree.ReadHashes([]int64{
		tlog.StoredHashIndex(16, 0), tlog.StoredHashIndex(16, 1)})
	fatalIfErr(t, err)
	if !bytes.Equal(data, append(want[0][:], want[1][:]...)) {
		t.Errorf("level 2 tile %q does not match the log's hashes", key)
	}

	checkMirrorTree(t, w, log, size)
}

// TestMirrorFreshSignature exercises the add-entries special case that returns
// fresh mirror cosignatures when upload_start and upload_end are both the
// mirror checkpoint size, even with the pending checkpoint and the next entry
// ahead of the mirror checkpoint.
func TestMirrorFreshSignature(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [0, 600): got %d, body %q", code, body)
	}

	// Move the pending checkpoint to 1200 and the next entry to 768, both
	// ahead of the mirror checkpoint at 600.
	log.grow(t, 600)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 600, 1200))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 600->1200: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 600, 1200, 1200, nil, 1))
	if code != http.StatusAccepted {
		t.Fatalf("prefix [600, 768): got %d, want 202 (body %q)", code, body)
	}
	pending, next, _ := parseMirrorInfo(t, body)
	if pending != 1200 || next != 768 {
		t.Errorf("got pending %d and next %d, want 1200 and 768", pending, next)
	}

	// A request for [600, 600) returns fresh signatures on the mirror
	// checkpoint, even if 600 is behind the next entry and no longer a
	// retained pending checkpoint value.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 600, 600, 600, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [600, 600): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 600, body)

	// The mirror checkpoint did not move.
	checkMirrorTree(t, w, log, 600)
}

// TestMirrorFreshSignatureTimestamp checks that refreshed cosignatures carry
// the current time, not a replay of the stored signature's timestamp, since
// clients use cosignature timestamps to establish checkpoint freshness.
func TestMirrorFreshSignatureTimestamp(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log := newTestMirrorLog(t, "example.com/testlog")
		w := newTestMirrorWitness(t, log)
		log.grow(t, 600)
		code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
		if code != http.StatusOK {
			t.Fatalf("add-checkpoint: got %d, body %q", code, body)
		}
		code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 0))
		if code != http.StatusOK {
			t.Fatalf("add-entries [0, 600): got %d, body %q", code, body)
		}
		checkMirrorSigs(t, w, log, 600, body)
		before := mirrorSigTimestamp(t, w, log, 600, body)

		time.Sleep(time.Hour)

		code, body = postAddEntries(t, w, log.addEntriesBody(t, 600, 600, 600, nil, 0))
		if code != http.StatusOK {
			t.Fatalf("add-entries [600, 600): got %d, body %q", code, body)
		}
		checkMirrorSigs(t, w, log, 600, body)
		if got := mirrorSigTimestamp(t, w, log, 600, body); got != before+3600 {
			t.Errorf("refreshed cosignature timestamp = %d, want %d", got, before+3600)
		}

		// The published mirror checkpoint carries the fresh cosignature too.
		checkpoint, err := w.c.Backend.Fetch(context.Background(), "mirror/"+OriginHash(log.origin)+"/checkpoint")
		fatalIfErr(t, err)
		n, err := note.Open(checkpoint, note.VerifierList(w.sm.Verifier()))
		fatalIfErr(t, err)
		ts, err := torchwood.CosignatureTimestamp(n.Sigs[0])
		fatalIfErr(t, err)
		if ts != before+3600 {
			t.Errorf("published cosignature timestamp = %d, want %d", ts, before+3600)
		}
	})
}

// mirrorSigTimestamp returns the timestamp of the mirror cosignature in body,
// a successful add-entries response for the checkpoint at the given size.
func mirrorSigTimestamp(t *testing.T, w *Witness, log *testMirrorLog, size int64, body string) int64 {
	t.Helper()
	text := torchwood.Checkpoint{
		Origin: log.origin, Tree: tlog.Tree{N: size, Hash: log.treeHash(t, size)},
	}.String()
	n, err := note.Open([]byte(text+"\n"+body), note.VerifierList(w.sm.Verifier()))
	fatalIfErr(t, err)
	ts, err := torchwood.CosignatureTimestamp(n.Sigs[0])
	fatalIfErr(t, err)
	return ts
}

// TestMirrorCommitBehindNextEntry exercises committing the mirror checkpoint
// to a past pending checkpoint that is behind the next entry, recovering
// progress stranded by interrupted or concurrent uploads.
func TestMirrorCommitBehindNextEntry(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [0, 600): got %d, body %q", code, body)
	}

	// Witness checkpoint 900 and obtain a ticket for it from a 409.
	log.grow(t, 300)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 600, 900))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 600->900: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [0, 0): got %d, want 409 (body %q)", code, body)
	}
	pending, next, ticket := parseMirrorInfo(t, body)
	if pending != 900 || next != 600 {
		t.Errorf("got pending %d and next %d, want 900 and 600", pending, next)
	}

	// The pending checkpoint moves to 1200, and a prefix upload advances the
	// next entry to 1024, past the 900 checkpoint.
	log.grow(t, 300)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 900, 1200))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 900->1200: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 600, 1200, 1200, nil, 2))
	if code != http.StatusAccepted {
		t.Fatalf("prefix [600, 1024): got %d, want 202 (body %q)", code, body)
	}
	pending, next, _ = parseMirrorInfo(t, body)
	if pending != 1200 || next != 1024 {
		t.Errorf("got pending %d and next %d, want 1200 and 1024", pending, next)
	}

	// upload_end 900 is behind the next entry, but the ticket makes it a known
	// pending checkpoint value, and the mirror checkpoint advances to it.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 900, 900, 900, ticket, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [900, 900) with ticket: got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 900, body)
	checkMirrorTree(t, w, log, 900)

	// Entries below the next entry can be uploaded again; the mirror skips
	// them and refreshes the signature.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 768, 900, 900, ticket, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [768, 900) with ticket: got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 900, body)
}

// TestMirrorCommitFarBehindNextEntry checks that the upload window is measured
// against upload_end, not the next entry alone: per c2sp.org/tlog-mirror,
// excess_entries = min(upload_end, next_entry) - upload_start, so a
// commit-only request for a past pending checkpoint uploads nothing and is
// valid however far the next entry has advanced past it.
func TestMirrorCommitFarBehindNextEntry(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 300)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 300))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}

	// Obtain a ticket for the pending checkpoint at 300 from a 409.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [0, 0): got %d, want 409 (body %q)", code, body)
	}
	_, _, ticket := parseMirrorInfo(t, body)

	// The pending checkpoint moves on, and a prefix upload advances the next
	// entry to 8704, far past the 300 checkpoint and any excess_entries window.
	const size = 35 * 256
	log.grow(t, size-300)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 300, size))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 300->%d: got %d, body %q", size, code, body)
	}
	code, body = postAddEntriesGzip(t, w, log.addEntriesBody(t, 0, size, size, nil, 34))
	if code != http.StatusAccepted {
		t.Fatalf("prefix [0, 8704): got %d, want 202 (body %q)", code, body)
	}
	pending, next, _ := parseMirrorInfo(t, body)
	if pending != size || next != 34*256 {
		t.Errorf("got pending %d and next %d, want %d and %d", pending, next, size, 34*256)
	}

	// upload_start = upload_end = 300 uploads no entries, so it is within any
	// excess_entries bound, and the mirror checkpoint advances to 300.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 300, 300, 300, ticket, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [300, 300) with ticket: got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 300, body)
	checkMirrorTree(t, w, log, 300)
}

// TestMirrorDiscovery exercises the zero upload_start and upload_end requests
// clients use to obtain the mirror state before their first upload.
func TestMirrorDiscovery(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)

	// An unknown origin is a 404.
	other := newTestMirrorLog(t, "example.com/unknown")
	code, body := postAddEntries(t, w, other.addEntriesBody(t, 0, 0, 0, nil, 0))
	if code != http.StatusNotFound {
		t.Errorf("unknown origin: got %d, want 404 (body %q)", code, body)
	}

	// Before the first add-checkpoint, there is no pending checkpoint to
	// return in a mirror-info body, so the log is a 404.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
	if code != http.StatusNotFound {
		t.Errorf("no pending checkpoint: got %d, want 404 (body %q)", code, body)
	}

	log.grow(t, 600)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}

	// With a pending checkpoint but nothing mirrored yet, a [0, 0) request is
	// a 409 with the mirror state, not a signature on a synthesized empty
	// checkpoint.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [0, 0): got %d, want 409 (body %q)", code, body)
	}
	pending, next, _ := parseMirrorInfo(t, body)
	if pending != 600 || next != 0 {
		t.Errorf("got pending %d and next %d, want 600 and 0", pending, next)
	}
	if _, err := w.c.Backend.Fetch(context.Background(), "mirror/"+OriginHash(log.origin)+"/checkpoint"); err == nil {
		t.Errorf("mirror checkpoint published before any entries were committed")
	}

	// upload_start can't be ahead of the next entry.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 256, 600, 600, nil, 0))
	if code != http.StatusConflict {
		t.Errorf("add-entries [256, 600): got %d, want 409 (body %q)", code, body)
	}

	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [0, 600): got %d, body %q", code, body)
	}

	// After the mirror checkpoint advances, a [0, 0) request is a 409 again.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [0, 0): got %d, want 409 (body %q)", code, body)
	}
	pending, next, _ = parseMirrorInfo(t, body)
	if pending != 600 || next != 600 {
		t.Errorf("got pending %d and next %d, want 600 and 600", pending, next)
	}
}

// TestMirrorCommitRace exercises a mirror checkpoint update racing the final
// commit of an add-entries request: the commit must not rewind the mirror
// checkpoint, and the raced request gets a 409 with the current state. If the
// concurrent update is to the same size, the raced request still succeeds.
func TestMirrorCommitRace(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [0, 600): got %d, body %q", code, body)
	}
	log.grow(t, 600)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 600, 1200))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 600->1200: got %d, body %q", code, body)
	}
	t.Cleanup(func() { testingOnlyBeforeAddEntriesCommit = nil })

	// While a [600, 600) request is between package processing and commit, a
	// concurrent client uploads the rest of the log, moving the mirror
	// checkpoint to 1200 and making the commit at 600 a rewind.
	testingOnlyBeforeAddEntriesCommit = func() {
		testingOnlyBeforeAddEntriesCommit = nil // don't recurse
		code, body := postAddEntries(t, w, log.addEntriesBody(t, 600, 1200, 1200, nil, 0))
		if code != http.StatusOK {
			t.Fatalf("concurrent add-entries [600, 1200): got %d, body %q", code, body)
		}
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 600, 600, 600, nil, 0))
	if code != http.StatusConflict {
		t.Fatalf("raced add-entries [600, 600): got %d, want 409 (body %q)", code, body)
	}
	pending, next, _ := parseMirrorInfo(t, body)
	if pending != 1200 || next != 1200 {
		t.Errorf("got pending %d and next %d, want 1200 and 1200", pending, next)
	}
	checkMirrorTree(t, w, log, 1200)

	// A concurrent update to the same size makes the commit a no-op, but the
	// raced request is still a success with fresh signatures.
	log.grow(t, 600)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 1200, 1800))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 1200->1800: got %d, body %q", code, body)
	}
	testingOnlyBeforeAddEntriesCommit = func() {
		testingOnlyBeforeAddEntriesCommit = nil // don't recurse
		code, body := postAddEntries(t, w, log.addEntriesBody(t, 1200, 1800, 1800, nil, 0))
		if code != http.StatusOK {
			t.Fatalf("concurrent add-entries [1200, 1800): got %d, body %q", code, body)
		}
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 1200, 1800, 1800, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("raced add-entries [1200, 1800): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 1800, body)
	checkMirrorTree(t, w, log, 1800)
}

// TestMirrorPendingCheckpointRace exercises an add-checkpoint request racing
// an add-entries request: the pending checkpoint moving forward does not
// affect the commit of an upload against the previous pending checkpoint.
func TestMirrorPendingCheckpointRace(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}
	t.Cleanup(func() { testingOnlyBeforeAddEntriesCommit = nil })

	// While a [0, 600) upload is between package processing and commit, the
	// pending checkpoint moves to 1200.
	testingOnlyBeforeAddEntriesCommit = func() {
		testingOnlyBeforeAddEntriesCommit = nil // don't recurse
		log.grow(t, 600)
		code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 600, 1200))
		if code != http.StatusOK {
			t.Fatalf("concurrent add-checkpoint 600->1200: got %d, body %q", code, body)
		}
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("raced add-entries [0, 600): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 600, body)
	checkMirrorTree(t, w, log, 600)

	// The upload continues to the new pending checkpoint.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 600, 1200, 1200, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [600, 1200): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 1200, body)
	checkMirrorTree(t, w, log, 1200)
}

// TestMirrorCommitRaceBehindUploadEnd exercises a concurrent mirror checkpoint
// update that lands behind the raced request's upload_end: the raced commit
// is not a conflict, and still moves the mirror checkpoint up to upload_end.
func TestMirrorCommitRaceBehindUploadEnd(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [0, 600): got %d, body %q", code, body)
	}

	// Witness checkpoint 900 and obtain a ticket for it from a 409.
	log.grow(t, 300)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 600, 900))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 600->900: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [0, 0): got %d, want 409 (body %q)", code, body)
	}
	_, _, ticket := parseMirrorInfo(t, body)

	log.grow(t, 300)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 900, 1200))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 900->1200: got %d, body %q", code, body)
	}
	t.Cleanup(func() { testingOnlyBeforeAddEntriesCommit = nil })

	// While a [600, 1200) upload is between package processing and commit, a
	// concurrent client commits the mirror checkpoint to 900 with the ticket.
	testingOnlyBeforeAddEntriesCommit = func() {
		testingOnlyBeforeAddEntriesCommit = nil // don't recurse
		code, body := postAddEntries(t, w, log.addEntriesBody(t, 900, 900, 900, ticket, 0))
		if code != http.StatusOK {
			t.Fatalf("concurrent add-entries [900, 900): got %d, body %q", code, body)
		}
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 600, 1200, 1200, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("raced add-entries [600, 1200): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 1200, body)
	checkMirrorTree(t, w, log, 1200)
}

// TestMirrorPackageRace exercises a concurrent client uploading and committing
// the whole interval while a request is still processing its first package:
// the raced request completes its first tile from the backend with the
// advanced next entry, skips the already saved entries, and its commit is a
// no-op that still returns signatures.
func TestMirrorPackageRace(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [0, 600): got %d, body %q", code, body)
	}
	log.grow(t, 600)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 600, 1200))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 600->1200: got %d, body %q", code, body)
	}
	t.Cleanup(func() { testingOnlyBeforeAddEntriesPackage = nil })

	testingOnlyBeforeAddEntriesPackage = func(start int64) {
		testingOnlyBeforeAddEntriesPackage = nil // don't recurse
		code, body := postAddEntries(t, w, log.addEntriesBody(t, 600, 1200, 1200, nil, 0))
		if code != http.StatusOK {
			t.Fatalf("concurrent add-entries [600, 1200): got %d, body %q", code, body)
		}
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 600, 1200, 1200, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("raced add-entries [600, 1200): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 1200, body)
	checkMirrorTree(t, w, log, 1200)
}

// TestMirrorInterleavedUploads exercises two overlapping uploads interleaving
// package by package: each processes some entries the other already saved, and
// the log converges without losing either client's progress.
func TestMirrorInterleavedUploads(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}
	t.Cleanup(func() { testingOnlyBeforeAddEntriesPackage = nil })

	// While a full [0, 600) upload is between its first and second package, a
	// concurrent client uploads a two-package prefix of the same interval,
	// re-verifying the first package and saving the second one first.
	testingOnlyBeforeAddEntriesPackage = func(start int64) {
		if start != 256 {
			return
		}
		testingOnlyBeforeAddEntriesPackage = nil // don't recurse
		code, body := postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 2))
		if code != http.StatusAccepted {
			t.Fatalf("concurrent prefix [0, 512): got %d, want 202 (body %q)", code, body)
		}
		pending, next, _ := parseMirrorInfo(t, body)
		if pending != 600 || next != 512 {
			t.Errorf("got pending %d and next %d, want 600 and 512", pending, next)
		}
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("raced add-entries [0, 600): got %d, body %q", code, body)
	}
	if testingOnlyBeforeAddEntriesPackage != nil {
		t.Error("the concurrent prefix upload never ran")
	}
	checkMirrorSigs(t, w, log, 600, body)
	checkMirrorTree(t, w, log, 600)
}

// TestMirrorUploadStartWindow checks that an upload_start too far below the
// next entry is rejected, bounding how much already-uploaded data the mirror
// re-verifies, while an upload_start within the window is accepted.
func TestMirrorUploadStartWindow(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	const window = 8 * 256 // the excess_entries limit of the witness
	const size = 35 * 256  // 8960, larger than the window
	log.grow(t, size)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, size))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}
	code, body = postAddEntriesGzip(t, w, log.addEntriesBody(t, 0, size, size, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [0, %d): got %d, body %q", size, code, body)
	}

	// upload_start 0 makes excess_entries much larger than the window.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, size, size, nil, 1))
	if code != http.StatusConflict {
		t.Errorf("add-entries [0, %d): got %d, want 409 (body %q)", size, code, body)
	}

	// So does, by a single entry, an upload_start just outside the window.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, size-window-1, size, size, nil, 1))
	if code != http.StatusConflict {
		t.Errorf("add-entries [%d, %d): got %d, want 409 (body %q)", size-window-1, size, code, body)
	}

	// upload_start exactly window entries below the next entry is accepted.
	code, body = postAddEntriesGzip(t, w, log.addEntriesBody(t, size-window, size, size, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [%d, %d): got %d, body %q", size-window, size, code, body)
	}
	checkMirrorSigs(t, w, log, size, body)
	checkMirrorTree(t, w, log, size)
}

// TestMirrorAddEntriesRequestErrors exercises malformed add-entries requests,
// which are rejected before any entry package is processed.
func TestMirrorAddEntriesRequestErrors(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}
	valid := log.addEntriesBody(t, 0, 600, 600, nil, 0)
	headerLen := 2 + len(log.origin) + 8 + 8 + 2

	// header builds an add-entries request header with arbitrary values.
	header := func(origin string, start, end uint64, ticket []byte) []byte {
		var b []byte
		b = binary.BigEndian.AppendUint16(b, uint16(len(origin)))
		b = append(b, origin...)
		b = binary.BigEndian.AppendUint64(b, start)
		b = binary.BigEndian.AppendUint64(b, end)
		b = binary.BigEndian.AppendUint16(b, uint16(len(ticket)))
		b = append(b, ticket...)
		return b
	}

	t.Run("wrong content type", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/add-entries", bytes.NewReader(valid))
		req.Header.Set("Content-Type", "text/plain")
		rec := httptest.NewRecorder()
		w.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("got %d, want 415 (body %q)", rec.Code, rec.Body.String())
		}
	})

	t.Run("invalid gzip", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/add-entries", bytes.NewReader(valid))
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Encoding", "gzip")
		rec := httptest.NewRecorder()
		w.Handler().ServeHTTP(rec, req)
		checkAddEntriesResponse(t, rec)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("got %d, want 400 (body %q)", rec.Code, rec.Body.String())
		}
	})

	t.Run("truncated header", func(t *testing.T) {
		for cut := range headerLen {
			code, body := postAddEntries(t, w, valid[:cut])
			if code != http.StatusBadRequest {
				t.Errorf("cut at %d: got %d, want 400 (body %q)", cut, code, body)
			}
		}
	})

	t.Run("missing declared ticket", func(t *testing.T) {
		b := header(log.origin, 0, 600, []byte("ticket"))
		code, body := postAddEntries(t, w, b[:len(b)-3])
		if code != http.StatusBadRequest {
			t.Errorf("got %d, want 400 (body %q)", code, body)
		}
	})

	t.Run("empty origin", func(t *testing.T) {
		code, body := postAddEntries(t, w, header("", 0, 600, nil))
		if code != http.StatusBadRequest {
			t.Errorf("got %d, want 400 (body %q)", code, body)
		}
	})

	t.Run("end before start", func(t *testing.T) {
		code, body := postAddEntries(t, w, header(log.origin, 600, 300, nil))
		if code != http.StatusBadRequest {
			t.Errorf("got %d, want 400 (body %q)", code, body)
		}
	})

	t.Run("start overflows int64", func(t *testing.T) {
		code, body := postAddEntries(t, w, header(log.origin, 1<<63, 1<<63, nil))
		if code != http.StatusBadRequest {
			t.Errorf("got %d, want 400 (body %q)", code, body)
		}
	})

	t.Run("end overflows int64", func(t *testing.T) {
		code, body := postAddEntries(t, w, header(log.origin, 0, 1<<63, nil))
		if code != http.StatusBadRequest {
			t.Errorf("got %d, want 400 (body %q)", code, body)
		}
	})

	t.Run("too many proof hashes", func(t *testing.T) {
		proof, err := torchwood.ProveSubtree(600, 0, 256, log.tree)
		fatalIfErr(t, err)
		b := log.addEntriesBody(t, 0, 600, 600, nil, 1)
		b = b[:len(b)-len(proof)*32-1]
		b = append(b, 64) // num_hashes over the limit of 63
		code, body := postAddEntries(t, w, b)
		if code != http.StatusBadRequest {
			t.Errorf("got %d, want 400 (body %q)", code, body)
		}
	})

	// None of the malformed requests saved any state, and a valid upload
	// still works.
	code, body = postAddEntries(t, w, valid)
	if code != http.StatusOK {
		t.Fatalf("add-entries [0, 600): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 600, body)
	checkMirrorTree(t, w, log, 600)
}

// TestMirrorAddEntriesDeadline exercises a client stalling mid-request under
// the server-wide timeouts of cmd/sunlight, which are tuned for small bodies
// and must be overridden by the add-entries handler: the request is processed
// as truncated when the add-entries read deadline expires, not when the
// server-wide timeouts would have fired, and the response must still be
// delivered after the read deadline.
func TestMirrorAddEntriesDeadline(t *testing.T) {
	setup := func(t *testing.T) (*Witness, *testMirrorLog) {
		log := newTestMirrorLog(t, "example.com/testlog")
		w := newTestMirrorWitness(t, log)
		log.grow(t, 600)
		code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
		if code != http.StatusOK {
			t.Fatalf("add-checkpoint: got %d, body %q", code, body)
		}
		return w, log
	}

	// A client that stalls before completing the first package gets a
	// "400 Bad Request" once the read deadline expires.
	t.Run("FirstPackage", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w, log := setup(t)
			full := log.addEntriesBody(t, 0, 600, 600, nil, 0)
			headerLen := 2 + len(log.origin) + 8 + 8 + 2
			resp := stallAddEntries(t, w, len(full), full[:headerLen+10])
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("got %d, want 400", resp.StatusCode)
			}
		})
	})

	// A client that stalls after the first package gets a "202 Accepted"
	// with its progress once the read deadline expires.
	t.Run("SecondPackage", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			w, log := setup(t)
			full := log.addEntriesBody(t, 0, 600, 600, nil, 0)
			prefix := log.addEntriesBody(t, 0, 600, 600, nil, 1)
			resp := stallAddEntries(t, w, len(full), prefix)
			if resp.StatusCode != http.StatusAccepted {
				t.Errorf("got %d, want 202 (%v)", resp.StatusCode, resp.Header)
			}
			if got := resp.Header.Get("Content-Type"); got != "text/x.tlog.mirror-info" {
				t.Errorf("got Content-Type %q, want text/x.tlog.mirror-info", got)
			}
			body, err := io.ReadAll(resp.Body)
			fatalIfErr(t, err)
			pending, next, _ := parseMirrorInfo(t, string(body))
			if pending != 600 || next != 256 {
				t.Errorf("got pending %d and next %d, want 600 and 256", pending, next)
			}
		})
	})
}

// stallAddEntries serves a single add-entries request over an in-memory
// connection with the server-wide timeouts of cmd/sunlight, sending only a
// prefix of a request body of declared full length, and then stalling like a
// silent client. It returns the response, which the server must produce
// exactly when the add-entries read deadline expires.
//
// It must be called within a synctest bubble.
func stallAddEntries(t *testing.T, w *Witness, fullLen int, prefix []byte) *http.Response {
	t.Helper()
	srvConn, cliConn := net.Pipe()
	t.Cleanup(func() { cliConn.Close() })
	srv := &http.Server{
		Handler:      w.Handler(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	go srv.Serve(newOneConnListener(srvConn))
	t.Cleanup(func() { srv.Close() })

	start := time.Now()
	head := fmt.Sprintf("POST /add-entries HTTP/1.1\r\nHost: witness.example\r\n"+
		"Content-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", fullLen)
	if _, err := cliConn.Write([]byte(head)); err != nil {
		t.Fatal(err)
	}
	if _, err := cliConn.Write(prefix); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(cliConn), nil)
	if err != nil {
		t.Fatalf("reading response after %v: %v", time.Since(start), err)
	}
	if elapsed := time.Since(start); elapsed != addEntriesTimeout {
		t.Errorf("response arrived after %v, want %v", elapsed, addEntriesTimeout)
	}
	return resp
}

// oneConnListener is a net.Listener that yields a single connection, and then
// blocks until it is closed.
type oneConnListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newOneConnListener(c net.Conn) *oneConnListener {
	ch := make(chan net.Conn, 1)
	ch <- c
	return &oneConnListener{addr: c.LocalAddr(), ch: ch, done: make(chan struct{})}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.addr }

// TestMirrorNotMirrored checks that add-entries is rejected with a 403 for
// logs that are witnessed but not mirrored.
func TestMirrorNotMirrored(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")

	t.Run("no mirror configured", func(t *testing.T) {
		w := newTestWitness(t, log.origin, log.vkey)
		code, body := postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
		if code != http.StatusForbidden {
			t.Errorf("got %d, want 403 (body %q)", code, body)
		}
	})

	t.Run("witness-only log", func(t *testing.T) {
		ctx := context.Background()
		_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
		fatalIfErr(t, err)
		mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
		fatalIfErr(t, err)
		mirrorKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
		fatalIfErr(t, err)
		config := &Config{
			Name:       "example.com/witness",
			KeyEd25519: ed25519Key,
			KeyMLDSA44: mldsaKey,
			MirrorName: "example.com/mirror",
			KeyMirror:  mirrorKey,
			Backend:    newMemBackend(),
			Lock:       newMemLockBackend(),
			Log:        slog.New(testLogHandler(t)),
		}
		configJSON := fmt.Appendf(nil, `{"log_meta":{%q:{"Verifiers":[%q]}}}`, log.origin, log.vkey)
		fatalIfErr(t, config.Lock.Create(ctx, backendKeyForConfig(config), configJSON))
		fatalIfErr(t, config.Lock.Create(ctx, backendKeyForCheckpoint(config, log.origin), nil))
		w, err := NewWitness(ctx, config)
		fatalIfErr(t, err)
		code, body := postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
		if code != http.StatusForbidden {
			t.Errorf("got %d, want 403 (body %q)", code, body)
		}
	})
}

// TestMirrorTicketAuthentication checks that the mirror rejects tampered,
// truncated, and cross-log tickets, per the c2sp.org/tlog-mirror requirement
// that the mirror authenticates any information it derives from a ticket.
func TestMirrorTicketAuthentication(t *testing.T) {
	logA := newTestMirrorLog(t, "example.com/loga")
	logB := newTestMirrorLog(t, "example.com/logb")
	w := newTestMirrorWitness(t, logA, logB)
	tickets := make(map[*testMirrorLog][]byte)
	for _, log := range []*testMirrorLog{logA, logB} {
		log.grow(t, 600)
		code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
		if code != http.StatusOK {
			t.Fatalf("add-checkpoint: got %d, body %q", code, body)
		}

		// Upload a two-package prefix, obtaining a ticket for checkpoint 600.
		code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 2))
		if code != http.StatusAccepted {
			t.Fatalf("prefix [0, 512): got %d, want 202 (body %q)", code, body)
		}
		_, _, ticket := parseMirrorInfo(t, body)
		tickets[log] = ticket

		// The pending checkpoint moves on, so completing the upload at 600
		// requires the ticket.
		log.grow(t, 600)
		code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 600, 1200))
		if code != http.StatusOK {
			t.Fatalf("add-checkpoint 600->1200: got %d, body %q", code, body)
		}
	}

	// A bit-flipped ticket is rejected.
	bad := bytes.Clone(tickets[logA])
	bad[len(bad)/2] ^= 1
	code, body := postAddEntries(t, w, logA.addEntriesBody(t, 512, 600, 600, bad, 0))
	if code != http.StatusConflict {
		t.Fatalf("tampered ticket: got %d, want 409 (body %q)", code, body)
	}
	pending, next, _ := parseMirrorInfo(t, body)
	if pending != 1200 || next != 512 {
		t.Errorf("got pending %d and next %d, want 1200 and 512", pending, next)
	}

	// So is a ticket too short to even contain a nonce.
	code, body = postAddEntries(t, w, logA.addEntriesBody(t, 512, 600, 600, []byte("short"), 0))
	if code != http.StatusConflict {
		t.Fatalf("short ticket: got %d, want 409 (body %q)", code, body)
	}

	// A valid ticket for one log doesn't work for another.
	code, body = postAddEntries(t, w, logB.addEntriesBody(t, 512, 600, 600, tickets[logA], 0))
	if code != http.StatusConflict {
		t.Fatalf("cross-log ticket: got %d, want 409 (body %q)", code, body)
	}

	// The untampered tickets, on their own logs, complete the uploads.
	for _, log := range []*testMirrorLog{logA, logB} {
		code, body = postAddEntries(t, w, log.addEntriesBody(t, 512, 600, 600, tickets[log], 0))
		if code != http.StatusOK {
			t.Fatalf("add-entries [512, 600) with ticket: got %d, body %q", code, body)
		}
		checkMirrorSigs(t, w, log, 600, body)
		checkMirrorTree(t, w, log, 600)
	}
}

// TestMirrorTicketRewind checks that an authentic ticket for a past pending
// checkpoint cannot rewind the mirror: per c2sp.org/tlog-mirror, an upload_end
// less than the mirror checkpoint's tree size is a 409, whether or not the
// ticket resolves it.
func TestMirrorTicketRewind(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 300)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 300))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}

	// Obtain a ticket for the pending checkpoint at 300 from a 409.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [0, 0): got %d, want 409 (body %q)", code, body)
	}
	_, _, ticket := parseMirrorInfo(t, body)

	// The mirror checkpoint advances to 600.
	log.grow(t, 300)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 300, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 300->600: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [0, 600): got %d, body %q", code, body)
	}

	// Replaying the ticket to commit at 300 is a rewind, and a 409 pointing at
	// the current state.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 300, 300, 300, ticket, 0))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [300, 300) with stale ticket: got %d, want 409 (body %q)", code, body)
	}
	pending, next, _ := parseMirrorInfo(t, body)
	if pending != 600 || next != 600 {
		t.Errorf("got pending %d and next %d, want 600 and 600", pending, next)
	}

	// The mirror checkpoint did not move.
	checkMirrorTree(t, w, log, 600)
}

// TestMirrorTicketResumption exercises a ticket-based upload that is
// interrupted again: the "202 Accepted" mirror-info reflects the resolved
// upload_end rather than the current pending checkpoint, and carries a fresh
// ticket for it, so the client can keep making progress without livelocking.
func TestMirrorTicketResumption(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 1))
	if code != http.StatusAccepted {
		t.Fatalf("prefix [0, 256): got %d, want 202 (body %q)", code, body)
	}
	pending, next, ticket := parseMirrorInfo(t, body)
	if pending != 600 || next != 256 {
		t.Errorf("got pending %d and next %d, want 600 and 256", pending, next)
	}

	// The pending checkpoint moves on before the client can finish.
	log.grow(t, 600)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 600, 1200))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 600->1200: got %d, body %q", code, body)
	}

	// A resumed upload interrupted again gets a mirror-info for the ticket's
	// checkpoint at 600, not the pending checkpoint at 1200, and a new ticket.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 256, 600, 600, ticket, 1))
	if code != http.StatusAccepted {
		t.Fatalf("prefix [256, 512) with ticket: got %d, want 202 (body %q)", code, body)
	}
	pending, next, ticket = parseMirrorInfo(t, body)
	if pending != 600 || next != 512 {
		t.Errorf("got pending %d and next %d, want 600 and 512", pending, next)
	}

	// The reissued ticket completes the upload.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 512, 600, 600, ticket, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [512, 600) with ticket: got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 600, body)
	checkMirrorTree(t, w, log, 600)
}

// TestMirrorTicketStartConflict checks that a 409 for an out-of-window
// upload_start reports a ticket-resolved upload_end in the mirror-info body,
// rather than the current pending checkpoint, so the client can retry without
// recomputing subtree consistency proofs.
func TestMirrorTicketStartConflict(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}

	// Upload a two-package prefix, obtaining a ticket for checkpoint 600.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 2))
	if code != http.StatusAccepted {
		t.Fatalf("prefix [0, 512): got %d, want 202 (body %q)", code, body)
	}
	pending, next, ticket := parseMirrorInfo(t, body)
	if pending != 600 || next != 512 {
		t.Errorf("got pending %d and next %d, want 600 and 512", pending, next)
	}

	// The pending checkpoint moves on before the client can finish.
	log.grow(t, 600)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 600, 1200))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 600->1200: got %d, body %q", code, body)
	}

	// upload_start 600 is ahead of the next entry, a 409, but the ticket still
	// resolves upload_end, so the mirror-info reports 600, not 1200.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 600, 600, 600, ticket, 0))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [600, 600) with ticket: got %d, want 409 (body %q)", code, body)
	}
	pending, next, ticket = parseMirrorInfo(t, body)
	if pending != 600 || next != 512 {
		t.Errorf("got pending %d and next %d, want 600 and 512", pending, next)
	}

	// The reissued ticket completes the upload at 600.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 512, 600, 600, ticket, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [512, 600) with ticket: got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 600, body)
	checkMirrorTree(t, w, log, 600)
}

// TestMirrorTicketStartConflictOvertaken checks the counterpart of
// TestMirrorTicketStartConflict: when the next entry has advanced past the
// ticket-resolved upload_end, all its entries are already uploaded, so the 409
// mirror-info redirects the client to the current pending checkpoint instead
// (a next entry ahead of the reported size would have the client retry with
// upload_start greater than upload_end).
func TestMirrorTicketStartConflictOvertaken(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	const oldSize = 16 * 256 // 4096, larger than the excess_entries window
	log.grow(t, oldSize)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, oldSize))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}

	// Obtain a ticket for the pending checkpoint at 4096 from a 409.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [0, 0): got %d, want 409 (body %q)", code, body)
	}
	_, _, ticket := parseMirrorInfo(t, body)

	// The pending checkpoint moves on, and a prefix upload advances the next
	// entry to 8704, past the ticket's checkpoint.
	const size = 35 * 256 // 8960
	log.grow(t, size-oldSize)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, oldSize, size))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint %d->%d: got %d, body %q", oldSize, size, code, body)
	}
	code, body = postAddEntriesGzip(t, w, log.addEntriesBody(t, 0, size, size, nil, 34))
	if code != http.StatusAccepted {
		t.Fatalf("prefix [0, 8704): got %d, want 202 (body %q)", code, body)
	}

	// upload_start 0 is out of the excess_entries window, and the next entry
	// is past the ticket's checkpoint at 4096, so the mirror-info reports the
	// pending checkpoint at 8960.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, oldSize, oldSize, ticket, 1))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [0, %d) with ticket: got %d, want 409 (body %q)", oldSize, code, body)
	}
	pending, next, _ := parseMirrorInfo(t, body)
	if pending != size || next != 34*256 {
		t.Errorf("got pending %d and next %d, want %d and %d", pending, next, size, 34*256)
	}
}

// TestMirrorTruncatedUploadAdvancedNextEntry checks that the "202 Accepted"
// mirror-info of an interrupted upload reports the mirror's next entry, which
// a concurrent upload may have advanced past the interruption point.
func TestMirrorTruncatedUploadAdvancedNextEntry(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}
	t.Cleanup(func() { testingOnlyBeforeAddEntriesPackage = nil })

	// While a truncated [0, 600) upload is between its first and second
	// packages, a concurrent client uploads a two-package prefix, advancing
	// the next entry to 512, past the truncation point at 256.
	testingOnlyBeforeAddEntriesPackage = func(start int64) {
		if start != 256 {
			return
		}
		testingOnlyBeforeAddEntriesPackage = nil // don't recurse
		code, body := postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 2))
		if code != http.StatusAccepted {
			t.Fatalf("concurrent prefix [0, 512): got %d, want 202 (body %q)", code, body)
		}
	}
	b := log.addEntriesBody(t, 0, 600, 600, nil, 2)
	code, body = postAddEntries(t, w, b[:len(b)-40])
	if code != http.StatusAccepted {
		t.Fatalf("truncated add-entries: got %d, want 202 (body %q)", code, body)
	}
	if testingOnlyBeforeAddEntriesPackage != nil {
		t.Error("the concurrent prefix upload never ran")
	}
	pending, next, _ := parseMirrorInfo(t, body)
	if pending != 600 || next != 512 {
		t.Errorf("got pending %d and next %d, want 600 and 512", pending, next)
	}

	// The upload completes from the advertised next entry.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 512, 600, 600, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [512, 600): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 600, body)
	checkMirrorTree(t, w, log, 600)
}

// TestMirrorTicketUploadOvertaken checks that when concurrent uploads towards
// a newer pending checkpoint advance the next entry past a ticket-resolved
// upload_end, the "202 Accepted" mirror-info redirects the client to the
// current pending checkpoint and the true next entry, rather than advertising
// a next entry ahead of upload_end (which would have the client retry with
// upload_start greater than upload_end).
func TestMirrorTicketUploadOvertaken(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}

	// Upload a two-package prefix, obtaining a ticket for checkpoint 600.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 2))
	if code != http.StatusAccepted {
		t.Fatalf("prefix [0, 512): got %d, want 202 (body %q)", code, body)
	}
	pending, next, ticket := parseMirrorInfo(t, body)
	if pending != 600 || next != 512 {
		t.Errorf("got pending %d and next %d, want 600 and 512", pending, next)
	}

	// The pending checkpoint moves on before the client can finish.
	log.grow(t, 600)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 600, 1200))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 600->1200: got %d, body %q", code, body)
	}
	t.Cleanup(func() { testingOnlyBeforeAddEntriesPackage = nil })

	// While a truncated ticket upload towards 600 is between its packages, a
	// concurrent client uploads towards 1200, advancing the next entry to
	// 1024, past the ticket's checkpoint.
	testingOnlyBeforeAddEntriesPackage = func(start int64) {
		if start != 512 {
			return
		}
		testingOnlyBeforeAddEntriesPackage = nil // don't recurse
		code, body := postAddEntries(t, w, log.addEntriesBody(t, 512, 1200, 1200, nil, 2))
		if code != http.StatusAccepted {
			t.Fatalf("concurrent prefix [512, 1024): got %d, want 202 (body %q)", code, body)
		}
		pending, next, _ := parseMirrorInfo(t, body)
		if pending != 1200 || next != 1024 {
			t.Errorf("got pending %d and next %d, want 1200 and 1024", pending, next)
		}
	}
	b := log.addEntriesBody(t, 256, 600, 600, ticket, 0)
	code, body = postAddEntries(t, w, b[:len(b)-40])
	if code != http.StatusAccepted {
		t.Fatalf("truncated add-entries: got %d, want 202 (body %q)", code, body)
	}
	if testingOnlyBeforeAddEntriesPackage != nil {
		t.Error("the concurrent prefix upload never ran")
	}
	pending, next, ticket = parseMirrorInfo(t, body)
	if pending != 1200 || next != 1024 {
		t.Errorf("got pending %d and next %d, want 1200 and 1024", pending, next)
	}

	// The client continues towards the current pending checkpoint.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 1024, 1200, 1200, ticket, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [1024, 1200): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 1200, body)
	checkMirrorTree(t, w, log, 1200)
}

// restartWitness simulates a witness restart: a new Witness on the same
// backends, losing all in-memory state, including the next entry values
// (which reset to the mirror checkpoint sizes) and the ticket AEAD key.
func restartWitness(t *testing.T, w *Witness) *Witness {
	t.Helper()
	w2, err := NewWitness(context.Background(), w.c)
	fatalIfErr(t, err)
	return w2
}

// TestMirrorRestartResumeMidTile exercises resuming an upload after a restart
// while the mirror checkpoint is mid-tile, committed with a ticket at a cut
// that no entry package ended at: the containing entries were uploaded as a
// full tile. The mirror must be able to complete the first package of the
// resumed upload from the backend.
//
// Per c2sp.org/tlog-mirror, clients retry with upload_start set to the
// advertised next entry, so a persistent error on this request is a livelock.
func TestMirrorRestartResumeMidTile(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 900)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 900))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}

	// Obtain a ticket for the pending checkpoint at 900 from a 409.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [0, 0): got %d, want 409 (body %q)", code, body)
	}
	_, _, ticket := parseMirrorInfo(t, body)

	// The pending checkpoint moves to 1200, and a prefix upload advances the
	// next entry to 1024, committing entries [768, 1024) as full tiles.
	log.grow(t, 300)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 900, 1200))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 900->1200: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 1200, 1200, nil, 4))
	if code != http.StatusAccepted {
		t.Fatalf("prefix [0, 1024): got %d, want 202 (body %q)", code, body)
	}
	pending, next, _ := parseMirrorInfo(t, body)
	if pending != 1200 || next != 1024 {
		t.Errorf("got pending %d and next %d, want 1200 and 1024", pending, next)
	}

	// The mirror checkpoint commits mid-tile at 900 with the ticket. No entry
	// package ended at the 900 cut, but the tree at 900 must be fully
	// servable.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 900, 900, 900, ticket, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [900, 900) with ticket: got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 900, body)
	checkMirrorTree(t, w, log, 900)

	// After a restart, the next entry resets to the mirror checkpoint at 900,
	// and a client resumes from there. The first package covers [768, 1024)
	// and must be completed from the backend.
	w = restartWitness(t, w)
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 900, 1200, 1200, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [900, 1200) after restart: got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 1200, body)
	checkMirrorTree(t, w, log, 1200)
}

// TestMirrorRestartResumeMidTilePartialOnly is like
// TestMirrorRestartResumeMidTile, but the upload that advanced the next entry
// had upload_end 1000 and was interrupted before its commit, so the tile
// containing the mirror checkpoint cut [768, 900) exists in the backend
// neither as a full tile nor as the width-132 partial: only as the width-232
// partial [768, 1000). The mirror must still complete the first package of
// the resumed upload from the entries it has.
func TestMirrorRestartResumeMidTilePartialOnly(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 900)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 900))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}

	// Obtain a ticket for the pending checkpoint at 900 from a 409.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [0, 0): got %d, want 409 (body %q)", code, body)
	}
	_, _, ticket := parseMirrorInfo(t, body)

	// The pending checkpoint moves to 1000. An upload of [0, 1000) crashes
	// after all its packages are processed but before the commit, leaving the
	// next entry at 1000 and entries [768, 1000) in the backend only as the
	// partial data tile of width 232.
	log.grow(t, 100)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 900, 1000))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 900->1000: got %d, body %q", code, body)
	}
	t.Cleanup(func() { testingOnlyBeforeAddEntriesCommit = nil })
	testingOnlyBeforeAddEntriesCommit = func() {
		testingOnlyBeforeAddEntriesCommit = nil
		panic("simulated crash between packages and commit")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected a simulated crash")
			}
		}()
		postAddEntries(t, w, log.addEntriesBody(t, 0, 1000, 1000, nil, 0))
	}()

	// The mirror checkpoint commits mid-tile at 900 with the ticket. The tree
	// at 900 must be fully servable, which requires producing the cut tiles
	// [768, 900): the interrupted upload only produced the [768, 1000) ones.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 900, 900, 900, ticket, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [900, 900) with ticket: got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 900, body)
	checkMirrorTree(t, w, log, 900)

	// After a restart, the next entry resets to the mirror checkpoint at 900,
	// and a client resumes from there towards the new pending checkpoint. The
	// first package covers [768, 1024) and must be completed from the backend.
	w = restartWitness(t, w)
	log.grow(t, 200)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 1000, 1200))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 1000->1200: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 900, 1200, 1200, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [900, 1200) after restart: got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 1200, body)
	checkMirrorTree(t, w, log, 1200)
}

// TestMirrorTicketAfterRestart checks that a ticket issued before a restart
// degrades to a 409 with the current mirror state, rather than an error: the
// ticket encryption key is not persisted, so the restarted witness cannot
// recover the past pending checkpoint from the ticket.
func TestMirrorTicketAfterRestart(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	log.grow(t, 600)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 600))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}

	// Upload a two-package prefix, obtaining a ticket for checkpoint 600.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 600, 600, nil, 2))
	if code != http.StatusAccepted {
		t.Fatalf("prefix [0, 512): got %d, want 202 (body %q)", code, body)
	}
	_, _, ticket := parseMirrorInfo(t, body)

	// The pending checkpoint moves on, so completing the upload at 600
	// requires the ticket.
	log.grow(t, 600)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 600, 1200))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 600->1200: got %d, body %q", code, body)
	}

	// After a restart, the ticket no longer decrypts, and the next entry reset
	// to the still-empty mirror checkpoint, so the mirror-info points at the
	// current pending checkpoint and next entry zero.
	w = restartWitness(t, w)
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 512, 600, 600, ticket, 0))
	if code != http.StatusConflict {
		t.Fatalf("add-entries [512, 600) with stale ticket: got %d, want 409 (body %q)", code, body)
	}
	pending, next, _ := parseMirrorInfo(t, body)
	if pending != 1200 || next != 0 {
		t.Errorf("got pending %d and next %d, want 1200 and 0", pending, next)
	}

	// The client restarts the upload from the advertised state.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 1200, 1200, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [0, 1200): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 1200, body)
	checkMirrorTree(t, w, log, 1200)
}

// TestMirrorEmptyLog mirrors a log whose pending checkpoint is the empty
// tree: a [0, 0) upload commits and cosigns the size-zero mirror checkpoint,
// and the mirror can then grow from it.
func TestMirrorEmptyLog(t *testing.T) {
	log := newTestMirrorLog(t, "example.com/testlog")
	w := newTestMirrorWitness(t, log)
	code, body := addCheckpoint(t, w, log.addCheckpointBody(t, 0, 0))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint: got %d, body %q", code, body)
	}

	// The first [0, 0) request commits the empty mirror checkpoint.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [0, 0): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 0, body)
	checkMirrorTree(t, w, log, 0)

	// Subsequent [0, 0) requests refresh the signature.
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 0, 0, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("repeated add-entries [0, 0): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 0, body)

	// The mirror grows from the empty checkpoint.
	log.grow(t, 300)
	code, body = addCheckpoint(t, w, log.addCheckpointBody(t, 0, 300))
	if code != http.StatusOK {
		t.Fatalf("add-checkpoint 0->300: got %d, body %q", code, body)
	}
	code, body = postAddEntries(t, w, log.addEntriesBody(t, 0, 300, 300, nil, 0))
	if code != http.StatusOK {
		t.Fatalf("add-entries [0, 300): got %d, body %q", code, body)
	}
	checkMirrorSigs(t, w, log, 300, body)
	checkMirrorTree(t, w, log, 300)
}
