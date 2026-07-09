package witness

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"filippo.io/mldsa"
	"filippo.io/sunlight/internal/ctlog"
	"filippo.io/sunlight/internal/xaes256gcm"
	"filippo.io/torchwood"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type Config struct {
	Name       string
	KeyEd25519 ed25519.PrivateKey
	KeyMLDSA44 *mldsa.PrivateKey

	MirrorName string
	KeyMirror  *mldsa.PrivateKey

	Backend ctlog.Backend
	Lock    ctlog.LockBackend
	Log     *slog.Logger
}

// backendKeyForCheckpoint computes the LockBackend key for the given log origin.
//
// It is domain separated from all uses of LockBackend by the ctlog package, and
// by other Witness instances.
func backendKeyForCheckpoint(config *Config, origin string) [sha256.Size]byte {
	h := sha256.New()

	// Domain separation from [ctlog.logIDFromKey] and other uses of LockBackend.
	h.Write(asn1.NullBytes)
	h.Write([]byte("witness log\n"))

	// Let multiple witnesses share the same LockBackend without affecting each
	// other's state. This is the opposite of what we want for logs we operate,
	// where we are in charge of preventing split-views, but witnesses have each
	// their own view of the state of each log they witness.
	//
	// Use the key instead of the name to prevent multiple witnesses from being
	// erroneously configured with the same key. Using just the Ed25519 public
	// key is sufficient to avoid collisions even if Ed25519 was broken, and
	// avoids a migration.
	h.Write(config.KeyEd25519.Public().(ed25519.PublicKey))

	h.Write([]byte(origin))
	return [32]byte(h.Sum(nil))
}

// backendKeyForMirrorCheckpoint computes the LockBackend key for the given log
// origin's mirror checkpoint.
func backendKeyForMirrorCheckpoint(config *Config, origin string) [sha256.Size]byte {
	h := sha256.New()

	h.Write(asn1.NullBytes)
	h.Write([]byte("mirror log\n"))

	h.Write(config.KeyEd25519.Public().(ed25519.PublicKey))

	h.Write([]byte(origin))
	return [32]byte(h.Sum(nil))
}

// backendKeyForConfig computes the LockBackend key for the witness
// configuration.
func backendKeyForConfig(config *Config) [sha256.Size]byte {
	h := sha256.New()

	h.Write(asn1.NullBytes)
	h.Write([]byte("witness config\n"))

	h.Write(config.KeyEd25519.Public().(ed25519.PublicKey))

	return [32]byte(h.Sum(nil))
}

// OriginHash returns the lowercase hex-encoded SHA-256 of the log origin, which
// identifies the log in the witness monitoring URL space per
// c2sp.org/tlog-witness:
//
//	GET <monitoring prefix>/<origin hash>/checkpoint
func OriginHash(origin string) string {
	h := sha256.Sum256([]byte(origin))
	return hex.EncodeToString(h[:])
}

type Witness struct {
	c          *Config
	s1, s2     *torchwood.CosignatureSigner // Ed25519 and ML-DSA-44 witness signers
	sm         *torchwood.CosignatureSigner // ML-DSA-44 mirror signer
	ticketAEAD cipher.AEAD
	m          metrics

	// logs and meta are indexed by log origin. They must be accessed and
	// updated under logsMu. A copy of meta is stored in LockBackend as
	// [storedConfig]. Logs are updated additively by [Witness.PullLogList],
	// and entries of logs must never be removed or replaced.
	logsMu sync.RWMutex
	meta   map[string]logMeta
	logs   map[string]*logState
}

func (w *Witness) stateForOrigin(origin string) (*logState, bool) {
	w.logsMu.RLock()
	defer w.logsMu.RUnlock()
	c, ok := w.logs[origin]
	return c, ok
}

func (w *Witness) metaForOrigin(origin string) (logMeta, bool) {
	w.logsMu.RLock()
	defer w.logsMu.RUnlock()
	m, ok := w.meta[origin]
	return m, ok
}

func (w *Witness) verifiersForOrigin(origin string) (note.Verifiers, bool) {
	l, ok := w.metaForOrigin(origin)
	if !ok {
		return nil, false
	}
	verifiers := make([]note.Verifier, 0, len(l.Verifiers))
	for _, v := range l.Verifiers {
		verifiers = append(verifiers, v)
	}
	return note.VerifierList(verifiers...), true
}

func (w *Witness) originIsMirrored(origin string) bool {
	l, ok := w.metaForOrigin(origin)
	if !ok {
		return false
	}
	return l.Mirror
}

func (w *Witness) nextEntryForOrigin(origin string) (int64, error) {
	l, ok := w.stateForOrigin(origin)
	if !ok {
		return 0, errUnknownLog
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.nextEntry == -1 {
		return 0, fmtErrorf("internal error: mirror checkpoint not fetched yet")
	}
	return l.nextEntry, nil
}

func (w *Witness) Logs() (all, mirrored []string) {
	w.logsMu.RLock()
	defer w.logsMu.RUnlock()
	for origin, l := range w.meta {
		if l.Mirror {
			mirrored = append(mirrored, origin)
		}
		all = append(all, origin)
	}
	slices.Sort(all)
	slices.Sort(mirrored)
	return all, mirrored
}

// logMeta is (de)serialized to/from JSON in LockBackend as [storedConfig].Logs.
type logMeta struct {
	Verifiers []serializableVerifier

	// If Mirror is true, this log can use the c2sp.org/tlog-mirror endpoints.
	// [logState.checkpoint] is the pending checkpoint, signed by the witness
	// cosigners, while [logState.mirrorCheckpoint] is the mirror checkpoint.
	//
	// As explained in c2sp.org/tlog-mirror, there is no strong locking between
	// the pending and mirror checkpoints, aside from the latter always being
	// behind the former.
	Mirror bool
}

type logState struct {
	mu     sync.Mutex
	origin string

	// checkpoint should be accessed using [logState.checkpointLocked].
	checkpoint ctlog.LockedCheckpoint // can be nil if not fetched yet

	// nextEntry and mirrorCheckpoint should be accessed using
	// [logState.mirrorCheckpointLocked].
	nextEntry        int64                  // can be -1 if mirrorCheckpoint is nil
	mirrorCheckpoint ctlog.LockedCheckpoint // can be nil if not fetched yet
}

func newLogState(origin string) *logState {
	return &logState{origin: origin, nextEntry: -1}
}

type serializableVerifier struct {
	vkey string
	note.Verifier
}

func (s serializableVerifier) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.vkey)
}

func (s *serializableVerifier) UnmarshalJSON(data []byte) error {
	var vkey string
	if err := json.Unmarshal(data, &vkey); err != nil {
		return err
	}
	v, err := newLogVerifier(vkey)
	if err != nil {
		return err
	}
	s.vkey = vkey
	s.Verifier = v
	return nil
}

type storedConfig struct {
	// The key "logs" is reserved by the pre-mirror config format.
	Logs map[string]logMeta `json:"log_meta"`
}

type parsedCheckpoint struct {
	torchwood.Checkpoint
	// Bytes are the raw checkpoint bytes, as stored in the LockBackend,
	// including the witness and log signatures. It may be nil if the checkpoint
	// for the empty tree was synthesized by the witness.
	Bytes []byte
	// UnverifiedSigs are the unverified signatures parsed from the stored
	// checkpoint note, presumably the log's signature.
	UnverifiedSigs []note.Signature
}

// checkpointLocked returns the current checkpoint for the log, fetching it from
// the LockBackend if necessary. It must be called with the logState mutex held.
//
// If the checkpoint is empty, returns a zero-size tree with the empty tree hash.
func (l *logState) checkpointLocked(ctx context.Context, w *Witness) (*parsedCheckpoint, error) {
	if l.checkpoint == nil {
		// The checkpoint must exist because it is created (empty) when the log is
		// added to the witness config.
		lock, err := w.c.Lock.Fetch(ctx, backendKeyForCheckpoint(w.c, l.origin))
		if err != nil {
			return nil, fmtErrorf("internal error: couldn't fetch checkpoint for known log")
		}
		l.checkpoint = lock
	}
	return w.openCheckpoint(l.origin, l.checkpoint, note.VerifierList(w.s1.Verifier(), w.s2.Verifier()))
}

// mirrorCheckpointLocked works like checkpointLocked, but for the mirror
// checkpoint. It must be called with the logState mutex held.
//
// It also populates l.nextEntry with the tree size if the mirror checkpoint had
// not been fetched before, and returns nextEntry. This loses uncommitted
// progress on witness restart, but avoids tracking additional state.
func (l *logState) mirrorCheckpointLocked(ctx context.Context, w *Witness) (*parsedCheckpoint, int64, error) {
	if l.mirrorCheckpoint == nil {
		lock, err := w.c.Lock.Fetch(ctx, backendKeyForMirrorCheckpoint(w.c, l.origin))
		if err != nil {
			return nil, 0, fmtErrorf("internal error: couldn't fetch mirror checkpoint for known log")
		}
		l.mirrorCheckpoint = lock
	}
	p, err := w.openCheckpoint(l.origin, l.mirrorCheckpoint, note.VerifierList(w.sm.Verifier()))
	if err != nil {
		return nil, 0, err
	}
	w.m.MirrorSize.WithLabelValues(l.origin).Set(float64(p.N))
	if l.nextEntry == -1 {
		l.nextEntry = p.N
		w.m.MirrorNextEntry.WithLabelValues(l.origin).Set(float64(p.N))
	}
	return p, l.nextEntry, nil
}

// openCheckpoint parses and verifies a stored checkpoint, returning the
// checkpoint and its unverified signatures. If the checkpoint is empty, it
// returns a zero-size tree with the empty tree hash.
//
// Note that verification here is not a security control: a malicious lock
// backend could simply empty out the checkpoint, or roll it back.
func (w *Witness) openCheckpoint(origin string, lock ctlog.LockedCheckpoint, v note.Verifiers) (*parsedCheckpoint, error) {
	checkpoint := lock.Bytes()
	if len(checkpoint) == 0 {
		return &parsedCheckpoint{
			Checkpoint: torchwood.Checkpoint{
				Origin: origin,
				Tree:   tlog.Tree{N: 0, Hash: emptyTreeHash},
			},
		}, nil
	}

	n, err := note.Open(checkpoint, v)
	if err != nil {
		return nil, fmtErrorf("internal error: can't open stored checkpoint")
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return nil, fmtErrorf("internal error: can't parse stored checkpoint")
	}
	if c.Origin != origin {
		return nil, fmtErrorf("internal error: incoherent stored checkpoint")
	}
	return &parsedCheckpoint{
		Checkpoint:     c,
		Bytes:          lock.Bytes(),
		UnverifiedSigs: n.UnverifiedSigs,
	}, nil
}

func NewWitness(ctx context.Context, config *Config) (*Witness, error) {
	s1, err := torchwood.NewCosignatureSigner(config.Name, config.KeyEd25519)
	if err != nil {
		return nil, fmt.Errorf("couldn't create Ed25519 signer: %w", err)
	}
	s2, err := torchwood.NewCosignatureSigner(config.Name, config.KeyMLDSA44)
	if err != nil {
		return nil, fmt.Errorf("couldn't create ML-DSA-44 signer: %w", err)
	}

	w := &Witness{c: config, s1: s1, s2: s2, m: initMetrics()}

	if config.MirrorName != "" {
		if config.MirrorName == config.Name {
			// This is also relied upon by [splitSignatures] callers.
			return nil, fmt.Errorf("mirror name must be different from witness name")
		}
		if len(config.MirrorName) > 255 {
			return nil, fmt.Errorf("mirror name too long: %d bytes (max 255)", len(config.MirrorName))
		}
		sm, err := torchwood.NewCosignatureSigner(config.MirrorName, config.KeyMirror)
		if err != nil {
			return nil, fmt.Errorf("couldn't create mirror ML-DSA-44 signer: %w", err)
		}
		w.sm = sm
	}
	ticketKey := make([]byte, xaes256gcm.KeySize)
	rand.Read(ticketKey)
	w.ticketAEAD, err = xaes256gcm.New(ticketKey)
	if err != nil {
		return nil, fmt.Errorf("couldn't create ticket AEAD: %w", err)
	}

	configJSON, err := config.Lock.Fetch(ctx, backendKeyForConfig(config))
	if errors.Is(err, ctlog.ErrLogNotFound) {
		config.Log.WarnContext(ctx, "witness config not found in backend; creating new empty config")
		if err := config.Lock.Create(ctx, backendKeyForConfig(config), []byte("{}")); err != nil {
			return nil, fmt.Errorf("couldn't create witness config in backend: %w", err)
		}
		configJSON, err = config.Lock.Fetch(ctx, backendKeyForConfig(config))
	}
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch witness config from backend: %w", err)
	}
	var stored storedConfig
	if err := json.Unmarshal(configJSON.Bytes(), &stored); err != nil {
		return nil, fmt.Errorf("couldn't parse stored witness config: %w", err)
	}

	w.meta = stored.Logs
	if w.meta == nil {
		w.meta = make(map[string]logMeta)
	}

	w.logs = make(map[string]*logState, len(stored.Logs))
	for origin := range stored.Logs {
		w.logs[origin] = newLogState(origin)
	}

	w.m.KnownLogs.Set(float64(len(stored.Logs)))
	w.m.MirroredLogs.Set(float64(countMirrored(w.meta)))
	config.Log.InfoContext(ctx, "starting witness", "name", config.Name, "logs", len(stored.Logs))
	return w, nil
}

func (w *Witness) VerifierKeys() []string {
	return []string{w.s1.Verifier().String(), w.s2.Verifier().String()}
}

func (w *Witness) MirrorVerifierKey() (string, bool) {
	if w.sm == nil {
		return "", false
	}
	return w.sm.Verifier().String(), true
}

func countMirrored(meta map[string]logMeta) int {
	var mirrored int
	for _, l := range meta {
		if l.Mirror {
			mirrored++
		}
	}
	return mirrored
}

func (w *Witness) PullLogList(ctx context.Context, url string, mirror bool) (err error) {
	defer func() {
		if err != nil {
			w.m.ListPullErrors.WithLabelValues(url).Inc()
		} else {
			w.m.ListPullTime.WithLabelValues(url).SetToCurrentTime()
		}
	}()

	if mirror && w.sm == nil {
		return fmt.Errorf("mirror log list provided but mirror is not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var body []byte
	switch {
	case strings.HasPrefix(url, "https://"):
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return fmt.Errorf("failed to create log list request: %w", err)
		}
		req.Header.Set("User-Agent", "+https://filippo.io/sunlight")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to fetch log list: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to fetch log list: %s", resp.Status)
		}
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read log list response: %w", err)
		}
	case strings.Contains(url, "://"):
		return fmt.Errorf("unsupported log list scheme (must be HTTPS): %q", url)
	default:
		var err error
		body, err = os.ReadFile(url)
		if err != nil {
			return fmt.Errorf("failed to read log list file: %w", err)
		}
	}
	logs, err := parseLogList(body)
	if err != nil {
		return fmt.Errorf("failed to parse log list: %w", err)
	}

	w.logsMu.Lock()
	newMeta := maps.Clone(w.meta)
	w.logsMu.Unlock()
	for origin, vkey := range logs {
		if origin == w.c.Name || (w.c.MirrorName != "" && origin == w.c.MirrorName) {
			return fmt.Errorf("log origin %q collides with the witness or mirror cosigner name", origin)
		}

		// If the log is already known, check that the key didn't change,
		// potentially upgrade to a mirror, and skip.
		if l, ok := newMeta[origin]; ok {
			if !slices.ContainsFunc(l.Verifiers, func(v serializableVerifier) bool {
				return v.vkey == vkey
			}) {
				return fmt.Errorf("log %q is listed with vkey %q, but is already configured with a different key", origin, vkey)
			}
			if mirror && !l.Mirror {
				createErr := w.c.Lock.Create(ctx, backendKeyForMirrorCheckpoint(w.c, origin), nil)
				if _, err := w.c.Lock.Fetch(ctx, backendKeyForMirrorCheckpoint(w.c, origin)); err != nil {
					return fmt.Errorf("couldn't fetch empty mirror checkpoint for log %q: %w (Create() error: %q)", origin, err, createErr)
				}
				l.Mirror = true
				newMeta[origin] = l
			}
			continue
		}

		v, err := newLogVerifier(vkey)
		if err != nil {
			return fmt.Errorf("couldn't parse vkey %q for log %q: %w", vkey, origin, err)
		}
		w.c.Log.InfoContext(ctx, "adding new log to witness config", "origin", origin, "vkey", vkey,
			"mirror", mirror, "list", url)

		// Create() might fail if the log was previously configured and removed,
		// or if a previous PullLogList crashed before persisting the new config.
		createErr := w.c.Lock.Create(ctx, backendKeyForCheckpoint(w.c, origin), nil)
		if _, err := w.c.Lock.Fetch(ctx, backendKeyForCheckpoint(w.c, origin)); err != nil {
			return fmt.Errorf("couldn't fetch empty checkpoint for new log %q: %w (Create() error: %q)", origin, err, createErr)
		}

		if mirror {
			createErr := w.c.Lock.Create(ctx, backendKeyForMirrorCheckpoint(w.c, origin), nil)
			if _, err := w.c.Lock.Fetch(ctx, backendKeyForMirrorCheckpoint(w.c, origin)); err != nil {
				return fmt.Errorf("couldn't fetch empty mirror checkpoint for new log %q: %w (Create() error: %q)", origin, err, createErr)
			}
		}

		newMeta[origin] = logMeta{
			Verifiers: []serializableVerifier{{vkey: vkey, Verifier: v}},
			Mirror:    mirror,
		}
	}

	// We don't actually need the compare-and-swap semantics to update the
	// config, a config rollback would not cause a checkpoint rollback.
	oldConfig, err := w.c.Lock.Fetch(ctx, backendKeyForConfig(w.c))
	if err != nil {
		return fmt.Errorf("couldn't fetch existing witness config from backend: %w", err)
	}
	stored := &storedConfig{Logs: newMeta}
	newConfig, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("couldn't marshal updated witness config: %w", err)
	}
	if _, err := w.c.Lock.Replace(ctx, oldConfig, newConfig); err != nil {
		return fmt.Errorf("couldn't store updated witness config: %w", err)
	}

	w.logsMu.Lock()
	defer w.logsMu.Unlock()
	for origin := range newMeta {
		if _, ok := w.logs[origin]; !ok {
			w.logs[origin] = newLogState(origin)
		}
	}
	w.meta = newMeta
	w.m.KnownLogs.Set(float64(len(newMeta)))
	w.m.MirroredLogs.Set(float64(countMirrored(newMeta)))
	return nil
}

func (w *Witness) Handler() http.Handler {
	addCheckpointLabels := prometheus.Labels{"endpoint": "add-checkpoint"}
	addCheckpoint := http.Handler(http.HandlerFunc(w.serveAddCheckpoint))
	addCheckpoint = promhttp.InstrumentHandlerCounter(w.m.ReqCount.MustCurryWith(addCheckpointLabels), addCheckpoint)
	addCheckpoint = promhttp.InstrumentHandlerDuration(w.m.ReqDuration.MustCurryWith(addCheckpointLabels), addCheckpoint)
	addCheckpoint = promhttp.InstrumentHandlerInFlight(w.m.ReqInFlight.With(addCheckpointLabels), addCheckpoint)
	addCheckpoint = http.MaxBytesHandler(addCheckpoint, 128*1024)

	signSubtreeLabels := prometheus.Labels{"endpoint": "sign-subtree"}
	signSubtree := http.Handler(http.HandlerFunc(w.serveSignSubtree))
	signSubtree = promhttp.InstrumentHandlerCounter(w.m.ReqCount.MustCurryWith(signSubtreeLabels), signSubtree)
	signSubtree = promhttp.InstrumentHandlerDuration(w.m.ReqDuration.MustCurryWith(signSubtreeLabels), signSubtree)
	signSubtree = promhttp.InstrumentHandlerInFlight(w.m.ReqInFlight.With(signSubtreeLabels), signSubtree)
	signSubtree = http.MaxBytesHandler(signSubtree, 128*1024)

	addEntriesLabels := prometheus.Labels{"endpoint": "add-entries"}
	addEntries := http.Handler(http.HandlerFunc(w.serveAddEntries))
	addEntries = promhttp.InstrumentHandlerCounter(w.m.ReqCount.MustCurryWith(addEntriesLabels), addEntries)
	addEntries = promhttp.InstrumentHandlerDuration(w.m.ReqDuration.MustCurryWith(addEntriesLabels), addEntries)
	addEntries = promhttp.InstrumentHandlerRequestSize(w.m.ReqSize.MustCurryWith(addEntriesLabels), addEntries)
	addEntries = promhttp.InstrumentHandlerInFlight(w.m.ReqInFlight.With(addEntriesLabels), addEntries)
	// One worst-case entry package is 256 * 64 KiB plus the proof.
	addEntries = http.MaxBytesHandler(addEntries, 20*1024*1024)

	mux := http.NewServeMux()
	mux.Handle("POST /add-checkpoint", addCheckpoint)
	mux.Handle("OPTIONS /add-checkpoint", addCheckpoint)
	mux.Handle("POST /sign-subtree", signSubtree)
	mux.Handle("OPTIONS /sign-subtree", signSubtree)
	mux.Handle("POST /add-entries", addEntries)
	return mux
}

type conflictError struct {
	known int64
}

func (*conflictError) Error() string { return "known tree size doesn't match provided old size" }

type mirrorConflictError struct {
	pending int64
	next    int64
	ticket  []byte
}

func (*mirrorConflictError) Error() string {
	return "mirror log state doesn't match provided start/end"
}

var errUnknownLog = fmtErrorf("unknown log")
var errInvalidSignature = fmtErrorf("invalid signature")
var errBadRequest = fmtErrorf("invalid input")
var errBadCheckpoint = fmtErrorf("invalid checkpoint")
var errExtensions = fmtErrorf("invalid checkpoint: extension lines are not supported")
var errProof = fmtErrorf("bad consistency proof")
var errNotMirrored = fmtErrorf("log is not mirrored")
var errNoPendingCheckpoint = fmtErrorf("no pending checkpoint for log")
var errInvalidProof = fmtErrorf("invalid proof")
var errMissingBody = fmtErrorf("missing or truncated request body")

// emptyTreeHash is the root hash of a tree of size zero: the hash of the empty
// string, per RFC 6962, Section 2.1.
var emptyTreeHash, _ = tlog.TreeHash(0, nil)

var optsHashTile = &ctlog.UploadOptions{Immutable: true}
var optsDataTile = &ctlog.UploadOptions{Compressed: true, Immutable: true}
var optsCheckpoint = &ctlog.UploadOptions{ContentType: "text/plain; charset=utf-8"}

func (w *Witness) serveAddCheckpoint(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		rw.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		rw.WriteHeader(http.StatusNoContent)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.c.Log.DebugContext(r.Context(), "error reading request body", "error", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	cosig, err := w.processAddCheckpointRequest(r.Context(), body)
	if err, ok := err.(*conflictError); ok {
		rw.Header().Set("Content-Type", "text/x.tlog.size")
		rw.WriteHeader(http.StatusConflict)
		fmt.Fprintf(rw, "%d\n", err.known)
		return
	}
	switch err {
	case errUnknownLog:
		http.Error(rw, err.Error(), http.StatusNotFound)
		return
	case errInvalidSignature:
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	case errBadRequest, errBadCheckpoint, errExtensions:
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	case errProof:
		http.Error(rw, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := rw.Write(cosig); err != nil {
		w.c.Log.DebugContext(r.Context(), "error writing response", "error", err)
	}
}

func (w *Witness) processAddCheckpointRequest(ctx context.Context, body []byte) (cosig []byte, err error) {
	labels := prometheus.Labels{"error": "", "origin": "", "progress": ""}
	defer func() {
		if err != nil {
			labels["error"] = errorLabel(err)
		}
		w.m.AddCheckpointCount.With(labels).Inc()
	}()
	body, noteBytes, ok := bytes.Cut(body, []byte("\n\n"))
	if !ok {
		return nil, errBadRequest
	}
	lines := strings.Split(string(body), "\n")
	if len(lines) < 1 {
		return nil, errBadRequest
	}
	size, ok := strings.CutPrefix(lines[0], "old ")
	if !ok {
		return nil, errBadRequest
	}
	oldSize, err := strconv.ParseInt(size, 10, 64)
	if err != nil || oldSize < 0 || size != strconv.FormatInt(oldSize, 10) {
		return nil, errBadRequest
	}
	proof := make(tlog.TreeProof, len(lines[1:]))
	for i, h := range lines[1:] {
		proof[i], err = tlog.ParseHash(h)
		if err != nil {
			return nil, errBadRequest
		}
	}
	origin, _, _ := strings.Cut(string(noteBytes), "\n")
	v, ok := w.verifiersForOrigin(origin)
	if !ok {
		return nil, errUnknownLog
	}
	labels["origin"] = origin
	n, err := note.Open(noteBytes, v)
	switch err.(type) {
	case *note.UnverifiedNoteError, *note.InvalidSignatureError:
		return nil, errInvalidSignature
	}
	if err != nil {
		return nil, errBadRequest
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return nil, errBadCheckpoint
	}
	if origin != c.Origin {
		return nil, fmtErrorf("internal error: incoherent parsing")
	}
	if c.Extension != "" {
		return nil, errExtensions
	}
	labels["progress"] = "false"
	if c.N > oldSize {
		labels["progress"] = "true"
	}
	return w.updateCheckpoint(ctx, c.Origin, oldSize, c.N, c.Hash, proof, n)
}

func (w *Witness) updateCheckpoint(ctx context.Context, origin string,
	oldSize, newSize int64, newHash tlog.Hash, proof tlog.TreeProof,
	submitted *note.Note) ([]byte, error) {

	l, ok := w.stateForOrigin(origin)
	if !ok {
		return nil, fmtErrorf("internal error: lock not found for known log")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if oldSize > newSize {
		return nil, errBadRequest
	}
	if newSize == 0 && newHash != emptyTreeHash {
		return nil, errProof
	}
	known, err := l.checkpointLocked(ctx, w)
	if err != nil {
		return nil, err
	}
	if known.N != oldSize {
		return nil, &conflictError{known.N}
	}
	if oldSize != 0 {
		if err := tlog.CheckTree(proof, newSize, newHash, known.N, known.Hash); err != nil {
			return nil, errProof
		}
	} else {
		if len(proof) != 0 {
			return nil, errProof
		}
	}

	// To avoid parser alignment issues, sign a re-encoding of what we interpreted.
	// If everything is working correctly, it will also be a valid signature on the
	// original note. If not, this fails safe.
	// https://bsky.app/profile/filippo.abyssdomain.expert/post/3lezjsf6wc2os
	// Include the log's signature that we verified, but not any unverified
	// signatures, which might be maliciously crafted to collide with our signature.
	signed, err := note.Sign(&note.Note{Text: torchwood.Checkpoint{
		Origin: origin, Tree: tlog.Tree{N: newSize, Hash: newHash},
	}.String(), Sigs: submitted.Sigs}, w.s1, w.s2)
	if err != nil {
		// Don't return the error here and below, to avoid leaking the signature
		// before the backend compare-and-swap succeeds, which is the ultimate
		// check against concurrent signers and locking bugs.
		return nil, fmtErrorf("internal error: failed to sign note")
	}
	sigs, err := splitSignatures(signed, w.s1.Verifier().Name())
	if err != nil {
		return nil, fmtErrorf("internal error: produced invalid note")
	}

	// It is utterly impossible for l.checkpoint to be different from known,
	// because we hold the logState mutex and no other goroutine can update it.
	// Still, defend against the worst possible bug and avoid weakening the
	// compare-and-swap semantics.
	if !bytes.Equal(l.checkpoint.Bytes(), known.Bytes) {
		return nil, fmtErrorf("internal error: checkpoint changed while holding lock")
	}
	newLock, err := w.c.Lock.Replace(ctx, l.checkpoint, signed)
	if err != nil {
		// We don't know if it was persisted, let it be re-fetched at the next update.
		l.checkpoint = nil
		return nil, fmtErrorf("internal error: failed to store new checkpoint")
	}
	l.checkpoint = newLock

	backendKey := OriginHash(origin) + "/checkpoint"
	if err := w.c.Backend.Upload(ctx, backendKey, signed, optsCheckpoint); err != nil {
		// Uploading the checkpoint to the public bucket failed, but we already
		// persisted it to the LockBackend, so witnessing can continue.
		//
		// We should take care not to expose the signature on the checkpoint to
		// the outside world, because it would not be visible to monitors.
		//
		// Clients can hit the 409 path to get the signature again.
		return nil, fmtErrorf("internal error: failed to upload new checkpoint to backend: %w", err)
	}

	w.m.LogSize.WithLabelValues(origin).Set(float64(newSize))

	return sigs, nil
}

func (w *Witness) serveSignSubtree(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		rw.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		rw.WriteHeader(http.StatusNoContent)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.c.Log.DebugContext(r.Context(), "error reading request body", "error", err)
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	cosig, err := w.processSignSubtreeRequest(r.Context(), body)
	switch err {
	case errUnknownLog:
		http.Error(rw, err.Error(), http.StatusNotFound)
		return
	case errInvalidSignature:
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	case errBadRequest, errBadCheckpoint, errExtensions:
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	case errProof:
		http.Error(rw, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := rw.Write(cosig); err != nil {
		w.c.Log.DebugContext(r.Context(), "error writing response", "error", err)
	}
}

func (w *Witness) processSignSubtreeRequest(ctx context.Context, body []byte) (cosig []byte, err error) {
	labels := prometheus.Labels{"error": "", "origin": ""}
	defer func() {
		if err != nil {
			labels["error"] = errorLabel(err)
		}
		w.m.SignSubtreeCount.With(labels).Inc()
	}()
	body, noteBytes, ok := bytes.Cut(body, []byte("\n\n"))
	if !ok {
		return nil, errBadRequest
	}
	lines := strings.Split(string(body), "\n")
	if len(lines) < 2 {
		return nil, errBadRequest
	}
	startEnd, ok := strings.CutPrefix(lines[0], "subtree ")
	if !ok {
		return nil, errBadRequest
	}
	startString, endString, ok := strings.Cut(startEnd, " ")
	if !ok {
		return nil, errBadRequest
	}
	start, err := strconv.ParseInt(startString, 10, 64)
	if err != nil || start < 0 || startString != strconv.FormatInt(start, 10) {
		return nil, errBadRequest
	}
	end, err := strconv.ParseInt(endString, 10, 64)
	if err != nil || end < 0 || endString != strconv.FormatInt(end, 10) {
		return nil, errBadRequest
	}
	if !torchwood.ValidSubtree(start, end) {
		return nil, errBadRequest
	}
	subtreeHash, err := tlog.ParseHash(lines[1])
	if err != nil {
		return nil, errBadRequest
	}
	proof := make(torchwood.SubtreeProof, len(lines[2:]))
	for i, h := range lines[2:] {
		proof[i], err = tlog.ParseHash(h)
		if err != nil {
			return nil, errBadRequest
		}
	}
	origin, _, _ := strings.Cut(string(noteBytes), "\n")

	if _, ok := w.metaForOrigin(origin); !ok {
		return nil, errUnknownLog
	}
	labels["origin"] = origin

	verifiers := []note.Verifier{w.s2.Verifier()}
	if w.sm != nil {
		verifiers = append(verifiers, w.sm.Verifier())
	}
	n, err := note.Open(noteBytes, note.VerifierList(verifiers...))
	switch err.(type) {
	case *note.UnverifiedNoteError, *note.InvalidSignatureError:
		return nil, errInvalidSignature
	}
	if err != nil {
		return nil, errBadRequest
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return nil, errBadCheckpoint
	}
	if origin != c.Origin {
		return nil, fmtErrorf("internal error: incoherent parsing")
	}
	if c.Extension != "" {
		return nil, errExtensions
	}
	if c.N < end {
		return nil, errBadRequest
	}

	if torchwood.CheckSubtree(proof, c.N, c.Hash, start, end, subtreeHash) != nil {
		return nil, errProof
	}

	var signers []*torchwood.CosignatureSigner
	for _, sig := range n.Sigs {
		if w.s2.Name() == sig.Name && w.s2.KeyHash() == sig.Hash {
			signers = append(signers, w.s2)
		}
		if w.sm != nil && w.sm.Name() == sig.Name && w.sm.KeyHash() == sig.Hash {
			signers = append(signers, w.sm)
		}
	}
	var sigs []byte
	for _, s := range signers {
		// Safety check, for each signer we are about to use, we re-verify the
		// signature on the re-serialized checkpoint using only its verifier.
		noteSigs, err := splitSignatures(noteBytes, s.Name())
		if err != nil {
			return nil, fmtErrorf("internal error: failed to split signatures for signer %q", s.Name())
		}
		n := []byte(c.String())
		n = append(n, []byte("\n")...)
		n = append(n, noteSigs...)
		if _, err := note.Open(n, note.VerifierList(s.Verifier())); err != nil {
			return nil, fmtErrorf("internal error: failed to re-verify signature for signer %q", s.Name())
		}

		sig, err := s.SignSubtree(c.Origin, start, end, subtreeHash)
		if err != nil {
			return nil, fmtErrorf("internal error: failed to sign subtree for signer %q", s.Name())
		}
		sigs = append(sigs, sig...)
	}
	return sigs, nil
}

func splitSignatures(note []byte, name string) ([]byte, error) {
	sigSplit := []byte("\n\n")
	split := bytes.LastIndex(note, sigSplit)
	if split < 0 {
		return nil, errors.New("invalid note")
	}
	var sigs []byte
	sigPrefix := []byte("— " + name + " ")
	for _, line := range bytes.SplitAfter(note[split+2:], []byte("\n")) {
		if bytes.HasPrefix(line, sigPrefix) {
			sigs = append(sigs, line...)
		}
	}
	return sigs, nil
}

// testingOnlyBeforeAddEntriesCommit, if not nil, is called by serveAddEntries
// after all entry packages are processed and before the final commit, with no
// locks held. It lets tests interleave a concurrent request between the two
// phases.
var testingOnlyBeforeAddEntriesCommit func()

// testingOnlyBeforeAddEntriesPackage, if not nil, is called by
// processAddEntriesPackages before each entry package is read and processed,
// with the index of the first entry of the package, and with no locks held. It
// lets tests interleave a concurrent request between two packages.
var testingOnlyBeforeAddEntriesPackage func(start int64)

const addEntriesTimeout = 5 * time.Minute

func (w *Witness) serveAddEntries(rw http.ResponseWriter, r *http.Request) {
	labels := prometheus.Labels{"error": "", "origin": ""}
	defer func() {
		w.m.AddEntriesCount.With(labels).Inc()
	}()
	httpError := func(error string, code int) {
		labels["error"] = error
		http.Error(rw, error, code)
	}

	if r.Header.Get("Content-Type") != "application/octet-stream" {
		httpError("invalid content type", http.StatusUnsupportedMediaType)
		return
	}

	// Override the server-wide read and write timeouts for the long add-entries
	// upload. Leave margin to write the "202 Accepted" response on a read timeout.
	rc := http.NewResponseController(rw)
	if err := rc.SetReadDeadline(time.Now().Add(addEntriesTimeout)); err != nil {
		w.c.Log.DebugContext(r.Context(), "failed to set read deadline", "error", err)
	}
	if err := rc.SetWriteDeadline(time.Now().Add(addEntriesTimeout + 15*time.Second)); err != nil {
		w.c.Log.DebugContext(r.Context(), "failed to set write deadline", "error", err)
	}
	ctx, cancel := context.WithTimeout(r.Context(), addEntriesTimeout)
	defer cancel()

	rw.Header().Set("Accept-Encoding", "gzip")
	body := r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			httpError("failed to create gzip reader", http.StatusBadRequest)
			return
		}
		defer gz.Close()
		body = gz
	}

	origin, err := readUint16LengthPrefixed(body)
	if err != nil || len(origin) == 0 {
		httpError("failed to read origin", http.StatusBadRequest)
		return
	}
	uploadStart, err := readUint64(body)
	if err != nil {
		httpError("failed to read upload start", http.StatusBadRequest)
		return
	}
	uploadEnd, err := readUint64(body)
	if err != nil {
		httpError("failed to read upload end", http.StatusBadRequest)
		return
	}
	if uploadEnd < uploadStart {
		httpError("upload end must be >= upload start", http.StatusBadRequest)
		return
	}
	ticket, err := readUint16LengthPrefixed(body)
	if err != nil {
		httpError("failed to read ticket", http.StatusBadRequest)
		return
	}

	pending, err := w.processAddEntriesMetadata(ctx, string(origin), uploadStart, uploadEnd, ticket)
	if err != errUnknownLog {
		// Known origins are a bounded label set, unknown ones are not.
		labels["origin"] = string(origin)
	}
	if err != nil {
		labels["error"] = errorLabel(err)
	}
	switch err {
	case errUnknownLog:
		http.Error(rw, err.Error(), http.StatusNotFound)
		return
	case errNoPendingCheckpoint:
		http.Error(rw, err.Error(), http.StatusUnprocessableEntity)
		return
	case errNotMirrored:
		http.Error(rw, err.Error(), http.StatusForbidden)
		return
	}
	var mirrorConflict *mirrorConflictError
	if errors.As(err, &mirrorConflict) {
		httpErrorMirrorInfo(rw, mirrorConflict, http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	err = w.processAddEntriesPackages(ctx, body, uploadStart, uploadEnd, pending)
	if err != nil {
		labels["error"] = errorLabel(err)
	}
	switch err {
	case errMissingBody, errBadRequest:
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	case errInvalidProof:
		http.Error(rw, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if errors.As(err, &mirrorConflict) {
		httpErrorMirrorInfo(rw, mirrorConflict, http.StatusAccepted)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if testingOnlyBeforeAddEntriesCommit != nil {
		testingOnlyBeforeAddEntriesCommit()
	}

	sigs, err := w.processAddEntriesCommit(ctx, pending)
	if err != nil {
		labels["error"] = errorLabel(err)
	}
	if errors.As(err, &mirrorConflict) {
		httpErrorMirrorInfo(rw, mirrorConflict, http.StatusConflict)
		return
	}
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, err := rw.Write(sigs); err != nil {
		w.c.Log.DebugContext(ctx, "error writing response", "error", err)
	}
}

func httpErrorMirrorInfo(rw http.ResponseWriter, mirrorConflict *mirrorConflictError, code int) {
	rw.Header().Set("Content-Type", "text/x.tlog.mirror-info")
	rw.WriteHeader(code)
	fmt.Fprintf(rw, "%d\n", mirrorConflict.pending)
	fmt.Fprintf(rw, "%d\n", mirrorConflict.next)
	fmt.Fprintf(rw, "%s\n", base64.StdEncoding.EncodeToString(mirrorConflict.ticket))
}

func (w *Witness) processAddEntriesMetadata(ctx context.Context, origin string, uploadStart, uploadEnd int64, ticket []byte) (*parsedCheckpoint, error) {
	l, ok := w.stateForOrigin(origin)
	if !ok {
		return nil, errUnknownLog
	}
	if !w.originIsMirrored(origin) || w.sm == nil {
		return nil, errNotMirrored
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	pendingCheckpoint, err := l.checkpointLocked(ctx, w)
	if err != nil {
		return nil, fmtErrorf("internal error: couldn't fetch checkpoint for known log")
	}
	if len(pendingCheckpoint.Bytes) == 0 {
		return nil, errNoPendingCheckpoint
	}
	mirrorCheckpoint, nextEntry, err := l.mirrorCheckpointLocked(ctx, w)
	if err != nil {
		return nil, fmtErrorf("internal error: couldn't fetch mirror checkpoint for known log")
	}

	if mirrorCheckpoint.N > pendingCheckpoint.N {
		return nil, fmtErrorf("internal error: mirror checkpoint is ahead of pending checkpoint")
	}
	if mirrorCheckpoint.N > nextEntry {
		return nil, fmtErrorf("internal error: mirror checkpoint is ahead of next entry")
	}
	if nextEntry > pendingCheckpoint.N {
		return nil, fmtErrorf("internal error: next entry is ahead of pending checkpoint")
	}

	if uploadEnd < mirrorCheckpoint.N {
		return nil, w.mirrorConflict(pendingCheckpoint, nextEntry)
	}

	var resolved *parsedCheckpoint
	switch {
	case uploadEnd == pendingCheckpoint.N:
		resolved = pendingCheckpoint
	case len(mirrorCheckpoint.Bytes) != 0 && uploadEnd == mirrorCheckpoint.N:
		resolved = mirrorCheckpoint
	case len(ticket) != 0:
		ticketCheckpoint, err := w.verifyTicket(origin, ticket)
		if err == nil && uploadEnd == ticketCheckpoint.N {
			resolved = ticketCheckpoint
		}
	}
	if resolved == nil {
		return nil, w.mirrorConflict(pendingCheckpoint, nextEntry)
	}

	excessEntries := min(uploadEnd, nextEntry) - uploadStart
	if uploadStart > nextEntry || excessEntries > 8*256 {
		if nextEntry <= uploadEnd {
			// upload_end was valid and has entries left to upload, so return it
			// in the mirror-info, letting the client retry without recomputing
			// subtree consistency proofs.
			return nil, w.mirrorConflict(resolved, nextEntry)
		}
		// All entries up to upload_end are already uploaded, so point the
		// client at the current pending checkpoint.
		return nil, w.mirrorConflict(pendingCheckpoint, nextEntry)
	}

	return resolved, nil
}

func (w *Witness) mirrorConflict(pending *parsedCheckpoint, nextEntry int64) error {
	// Encrypt the pending checkpoint, which we *might* not want to disclose, if
	// the backend upload failed and the monitors can't see it.
	nonce := make([]byte, xaes256gcm.NonceSize,
		xaes256gcm.NonceSize+len(pending.Bytes)+xaes256gcm.Overhead)
	rand.Read(nonce)
	ad := make([]byte, 0, 1+len(w.c.MirrorName)+len(pending.Origin))
	ad = append(ad, byte(len(w.c.MirrorName)))
	ad = append(ad, w.c.MirrorName...)
	ad = append(ad, []byte(pending.Origin)...)
	ticket := w.ticketAEAD.Seal(nonce, nonce, pending.Bytes, ad)

	return &mirrorConflictError{pending: pending.N, next: nextEntry, ticket: ticket}
}

func (w *Witness) mirrorConflictNext(ctx context.Context, resolved *parsedCheckpoint) error {
	l, ok := w.stateForOrigin(resolved.Origin)
	if !ok {
		return fmtErrorf("internal error: lock not found for known log")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.nextEntry == -1 {
		return fmtErrorf("internal error: mirror checkpoint not fetched yet")
	}
	if l.nextEntry <= resolved.N {
		// The client can continue the upload with the proofs it computed.
		return w.mirrorConflict(resolved, l.nextEntry)
	}
	// The next entry moved past the checkpoint the client was using, send a
	// fresh pending checkpoint.
	pending, err := l.checkpointLocked(ctx, w)
	if err != nil {
		return fmtErrorf("internal error: couldn't fetch checkpoint for known log")
	}
	return w.mirrorConflict(pending, l.nextEntry)
}

func (w *Witness) verifyTicket(origin string, ticket []byte) (*parsedCheckpoint, error) {
	if len(ticket) < xaes256gcm.NonceSize {
		return nil, errors.New("invalid ticket: too short")
	}
	nonce := ticket[:xaes256gcm.NonceSize]
	ciphertext := ticket[xaes256gcm.NonceSize:]
	ad := make([]byte, 0, 1+len(w.c.MirrorName)+len(origin))
	ad = append(ad, byte(len(w.c.MirrorName)))
	ad = append(ad, w.c.MirrorName...)
	ad = append(ad, []byte(origin)...)
	checkpointBytes, err := w.ticketAEAD.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, errors.New("invalid ticket: decryption failed")
	}

	// We could have stripped our own signatures from the checkpoint, but then
	// we'd rely on XAES-256-GCM to prevent split-views, which would be a new
	// critical dependency. Instead, re-verify the ML-DSA-44 signature.
	n, err := note.Open(checkpointBytes, note.VerifierList(w.s2.Verifier()))
	if err != nil {
		return nil, errors.New("internal error: can't open ticket checkpoint")
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return nil, errors.New("internal error: can't parse ticket checkpoint")
	}
	if c.Origin != origin {
		return nil, errors.New("internal error: incoherent ticket checkpoint")
	}
	// Drop our Ed25519 signature. The ML-DSA-44 one is already in n.Sigs.
	n.UnverifiedSigs = slices.DeleteFunc(n.UnverifiedSigs, func(s note.Signature) bool {
		return s.Name == w.s1.Name() && s.Hash == w.s1.Verifier().KeyHash()
	})
	return &parsedCheckpoint{
		Checkpoint:     c,
		Bytes:          checkpointBytes,
		UnverifiedSigs: n.UnverifiedSigs,
	}, nil
}

func (w *Witness) processAddEntriesPackages(ctx context.Context, r io.Reader, uploadStart, uploadEnd int64, pending *parsedCheckpoint) error {
	if uploadEnd != pending.N {
		return fmtErrorf("internal error: upload end does not match pending checkpoint size: %d != %d", uploadEnd, pending.N)
	}

	if uploadStart == uploadEnd {
		return nil
	}

	roundedStart := uploadStart - (uploadStart % 256)
	roundedEnd := (uploadEnd + 255) / 256 * 256
	numPackages := (roundedEnd - roundedStart) / 256

	// Use the [0, roundedStart) tree as the base of an overlay, so we can
	// easily add entries sequentially.
	//
	// Hashes in the [0, roundedStart) tree are served from the backend without
	// authentication. This is ok because they are used only to compute tilesCache to
	// commit back to the backend, where the backend could obviously change
	// them. (We wouldn't have a tree root to authenticate them against anyway.)
	tilesCache := make(map[tlog.Tile][]byte)
	hashReader := torchwood.NewHashReaderOverlay(roundedStart,
		tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
			hashes := make([]tlog.Hash, 0, len(indexes))
			for _, id := range indexes {
				t := tlog.TileForIndex(torchwood.TileHeight, id)
				// Widen the tile to its width in the [0, roundedStart) tree,
				// which we can expect to exist in the backend.
				roundedStartAtLevel := roundedStart >> (t.H * t.L)
				t.W = int(min(roundedStartAtLevel-(t.N<<t.H), 256))
				data, ok := tilesCache[t]
				if !ok {
					key := "mirror/" + OriginHash(pending.Origin) + "/" + torchwood.TilePath(t)
					var err error
					data, err = w.c.Backend.Fetch(ctx, key)
					if err != nil {
						return nil, fmt.Errorf("failed to fetch tile %q: %w", key, err)
					}
					tilesCache[t] = data
				}
				h, err := tlog.HashFromTile(t, data, id)
				if err != nil {
					return nil, fmt.Errorf("failed to read hash %d from tile: %w", id, err)
				}
				hashes = append(hashes, h)
			}
			return hashes, nil
		}),
	)

	for i := range numPackages {
		tileStart := roundedStart + i*256
		start := max(uploadStart, tileStart)
		end := min(uploadEnd, tileStart+256)

		if testingOnlyBeforeAddEntriesPackage != nil {
			testingOnlyBeforeAddEntriesPackage(start)
		}

		var entries [][]byte
		entryBytes := w.m.MirrorEntryBytes.WithLabelValues(pending.Origin)
		for range end - start {
			entry, err := readUint16LengthPrefixed(r)
			if err != nil {
				if i == 0 {
					return errMissingBody
				} else {
					return w.mirrorConflictNext(ctx, pending)
				}
			}
			entryBytes.Observe(float64(len(entry)))
			entries = append(entries, entry)
		}

		numHashes, err := readUint8(r)
		if err != nil {
			if i == 0 {
				return errMissingBody
			} else {
				return w.mirrorConflictNext(ctx, pending)
			}
		}
		if numHashes > 63 {
			return errBadRequest
		}

		var proof []tlog.Hash
		for range numHashes {
			var hash tlog.Hash
			if _, err := io.ReadFull(r, hash[:]); err != nil {
				if i == 0 {
					return errMissingBody
				} else {
					return w.mirrorConflictNext(ctx, pending)
				}
			}
			proof = append(proof, hash)
		}

		if err := w.processAddEntriesPackage(ctx, hashReader, entries, proof, tileStart, end, pending); err != nil {
			return err
		}
	}

	return nil
}

func (w *Witness) processAddEntriesPackage(ctx context.Context, hashReader *torchwood.HashReaderOverlay, entries [][]byte, proof torchwood.SubtreeProof, tileStart, end int64, pending *parsedCheckpoint) error {
	if len(entries) < int(end-tileStart) {
		var err error
		entries, err = w.completeTileFromBackend(ctx, pending.Origin, entries, tileStart, end)
		if err != nil {
			return fmtErrorf("failed to complete tile from backend: %w", err)
		}
	}

	for _, entry := range entries {
		if err := hashReader.AppendRecordHash(tlog.RecordHash(entry)); err != nil {
			return fmtErrorf("failed to append record hash: %w", err)
		}
	}
	subtreeHash, err := torchwood.SubtreeHash(tileStart, end, hashReader)
	if err != nil {
		return fmtErrorf("failed to produce subtree hash: %w", err)
	}
	if err := torchwood.CheckSubtree(proof, pending.N, pending.Hash,
		tileStart, end, subtreeHash); err != nil {
		return errInvalidProof
	}

	newTiles := tlog.NewTiles(torchwood.TileHeight, tileStart, end)
	for _, tile := range newTiles {
		if tile.L == 0 {
			dataTile := tile
			dataTile.L = -1
			if dataTile.N != tileStart/256 || dataTile.W != len(entries) {
				return fmtErrorf("internal error: data tile does not match expected tile start and width: %v, %d, %d", dataTile, tileStart/256, len(entries))
			}
			var data []byte
			for _, entry := range entries {
				data, err = torchwood.AppendTileEntry(data, entry)
				if err != nil {
					return fmtErrorf("failed to append tile entry: %w", err)
				}
			}
			backendKey := "mirror/" + OriginHash(pending.Origin) + "/" + torchwood.TilePath(dataTile)
			w.m.MirrorDataTileSize.WithLabelValues(pending.Origin).Observe(float64(len(data)))
			// Known issue: full data tiles are uploaded as immutable (see
			// optsDataTile), so a backend that enforces immutability rejects
			// re-uploading one with different bytes. We recompress the entries
			// on every add-entries, so if a crash-retry that re-uploads a full
			// tile straddles a change to the compression output (e.g. a Go
			// toolchain upgrade altering flate), the immutable comparison fails
			// and the upload errors until the tile is manually deleted.
			data, err = compress(data)
			if err != nil {
				return fmtErrorf("failed to compress data tile: %w", err)
			}
			w.m.MirrorDataTileGzipSize.WithLabelValues(pending.Origin).Observe(float64(len(data)))
			if err := w.c.Backend.Upload(ctx, backendKey, data, optsDataTile); err != nil {
				return fmtErrorf("failed to upload data tile %q: %w", backendKey, err)
			}
			w.m.MirrorTiles.WithLabelValues(pending.Origin, "false").Inc()
		}
		data, err := tlog.ReadTileData(tile, hashReader)
		if err != nil {
			return fmtErrorf("failed to read tile data: %w", err)
		}
		backendKey := "mirror/" + OriginHash(pending.Origin) + "/" + torchwood.TilePath(tile)
		if err := w.c.Backend.Upload(ctx, backendKey, data, optsHashTile); err != nil {
			return fmtErrorf("failed to upload tile %q: %w", backendKey, err)
		}
		w.m.MirrorTiles.WithLabelValues(pending.Origin, "false").Inc()
	}

	l, ok := w.stateForOrigin(pending.Origin)
	if !ok {
		return fmtErrorf("internal error: lock not found for known log")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if end > l.nextEntry {
		w.m.MirrorEntries.WithLabelValues(pending.Origin).Add(float64(end - l.nextEntry))
		w.m.MirrorNextEntry.WithLabelValues(pending.Origin).Set(float64(end))
		l.nextEntry = end
	}

	return nil
}

// completeTileFromBackend fetches leading entries from the backend to complete
// a tile when the client has an upload_start that is not 256-aligned.
//
// The returned entries will be authenticated along with the client-submitted
// ones.
func (w *Witness) completeTileFromBackend(ctx context.Context, origin string, entries [][]byte, tileStart, end int64) ([][]byte, error) {
	tile := tlog.Tile{
		H: torchwood.TileHeight,
		L: -1, // data tile
		N: tileStart / 256,
		W: 256,
	}

	// We need the nextEntry to know which tile is available in the backend: if
	// it's at least tileStart+256, we can fetch the full tile, otherwise we
	// need to fetch the partial tile implied by nextEntry.
	//
	// The tile implied by the next entry is always available in the backend: it
	// was uploaded either by the entry package that ended at the next entry, or
	// by [Witness.ensureCutTiles] when a mid-tile mirror checkpoint was
	// committed (which the next entry resets to on restart).
	nextEntry, err := w.nextEntryForOrigin(origin)
	if err != nil {
		return nil, fmtErrorf("failed to get next entry for origin %q: %w", origin, err)
	}
	if nextEntry <= tileStart {
		return nil, fmtErrorf("internal error: next entry is not after tile start: %d <= %d", nextEntry, tileStart)
	}
	if nextEntry < tileStart+256 {
		tile.W = int(nextEntry - tileStart)
	}

	backendKey := "mirror/" + OriginHash(origin) + "/" + torchwood.TilePath(tile)
	data, err := fetchAndDecompress(ctx, w.c.Backend, backendKey)
	if err != nil {
		return nil, fmtErrorf("failed to fetch and decompress tile %q: %w", backendKey, err)
	}

	need := int(end-tileStart) - len(entries)
	allEntries := make([][]byte, 0, need+len(entries))
	for range need {
		var entry []byte
		entry, data, err = torchwood.ReadTileEntry(data)
		if err != nil {
			return nil, fmtErrorf("failed to read entry from tile %q: %w", backendKey, err)
		}
		allEntries = append(allEntries, entry)
	}
	allEntries = append(allEntries, entries...)
	return allEntries, nil
}

func (w *Witness) processAddEntriesCommit(ctx context.Context, pending *parsedCheckpoint) ([]byte, error) {
	l, ok := w.stateForOrigin(pending.Origin)
	if !ok {
		return nil, fmtErrorf("internal error: lock not found for known log")
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	mirrorCheckpoint, nextEntry, err := l.mirrorCheckpointLocked(ctx, w)
	if err != nil {
		return nil, fmtErrorf("internal error: couldn't fetch mirror checkpoint for known log")
	}
	if nextEntry < pending.N {
		return nil, fmtErrorf("internal error: next entry is behind upload end")
	}
	if pending.Origin != mirrorCheckpoint.Origin || pending.Origin != l.origin {
		return nil, fmtErrorf("internal error: incoherent mirror checkpoint")
	}
	if pending.N < mirrorCheckpoint.N {
		newPending, err := l.checkpointLocked(ctx, w)
		if err != nil {
			return nil, fmtErrorf("internal error: couldn't fetch checkpoint for known log")
		}
		return nil, w.mirrorConflict(newPending, nextEntry)
	}

	if err := w.ensureCutTiles(ctx, pending, nextEntry); err != nil {
		return nil, fmtErrorf("internal error: failed to ensure checkpoint cut tiles: %w", err)
	}

	// Same as [Witness.updateCheckpoint], sign a re-encoding of what we
	// interpreted, to avoid parser alignment issues, and attach the log's
	// signatures.
	signed, err := note.Sign(&note.Note{Text: pending.String(), Sigs: pending.UnverifiedSigs}, w.sm)
	if err != nil {
		// Same as [Witness.updateCheckpoint], avoid leaking the signature until
		// we persisted the checkpoint.
		return nil, fmtErrorf("internal error: failed to sign note")
	}
	sigs, err := splitSignatures(signed, w.sm.Verifier().Name())
	if err != nil {
		return nil, fmtErrorf("internal error: produced invalid note")
	}

	// Here we partially defeat the compare-and-swap semantics of the
	// LockBackend, but it's always ok to sign a mirror checkpoint of size
	// next_entry, which we checked above.
	newLock, err := w.c.Lock.Replace(ctx, l.mirrorCheckpoint, signed)
	if err != nil {
		// We don't know if it was persisted, let it be re-fetched at the next update.
		l.mirrorCheckpoint = nil
		return nil, fmtErrorf("internal error: failed to store new checkpoint")
	}
	l.mirrorCheckpoint = newLock
	w.m.MirrorSize.WithLabelValues(pending.Origin).Set(float64(pending.N))

	backendKey := "mirror/" + OriginHash(pending.Origin) + "/checkpoint"
	if err := w.c.Backend.Upload(ctx, backendKey, signed, optsCheckpoint); err != nil {
		return nil, fmtErrorf("internal error: failed to upload new checkpoint to backend: %w", err)
	}

	return sigs, nil
}

// ensureCutTiles makes sure the partial hash and data tiles cut at pending.N
// are available in the backend before the mirror checkpoint is signed, so the
// tree of size pending.N is fully servable per c2sp.org/tlog-tiles, and so
// [Witness.completeTileFromBackend] can fetch the cut tile after a restart
// resets the next entry to the mirror checkpoint.
func (w *Witness) ensureCutTiles(ctx context.Context, pending *parsedCheckpoint, nextEntry int64) error {
	cutW := int(pending.N % 256)
	if cutW == 0 {
		return nil
	}
	tileStart := pending.N - int64(cutW)
	hashTile := tlog.Tile{H: torchwood.TileHeight, L: 0, N: tileStart / 256, W: cutW}
	hashKey := "mirror/" + OriginHash(pending.Origin) + "/" + torchwood.TilePath(hashTile)
	if _, err := w.c.Backend.Fetch(ctx, hashKey); err == nil {
		return nil
	}

	widestTile := hashTile
	widestTile.L = -1
	widestTile.W = int(min(nextEntry-tileStart, 256))
	widestKey := "mirror/" + OriginHash(pending.Origin) + "/" + torchwood.TilePath(widestTile)
	data, err := fetchAndDecompress(ctx, w.c.Backend, widestKey)
	if err != nil {
		return fmtErrorf("failed to fetch and decompress tile %q: %w", widestKey, err)
	}
	var cutData, cutHashes []byte
	for range cutW {
		var entry []byte
		entry, data, err = torchwood.ReadTileEntry(data)
		if err != nil {
			return fmtErrorf("failed to read entry from tile %q: %w", widestKey, err)
		}
		cutData, err = torchwood.AppendTileEntry(cutData, entry)
		if err != nil {
			return fmtErrorf("failed to append tile entry: %w", err)
		}
		h := tlog.RecordHash(entry)
		cutHashes = append(cutHashes, h[:]...)
	}

	dataTile := hashTile
	dataTile.L = -1
	w.m.MirrorDataTileSize.WithLabelValues(pending.Origin).Observe(float64(len(cutData)))
	cutData, err = compress(cutData)
	if err != nil {
		return fmtErrorf("failed to compress data tile: %w", err)
	}
	w.m.MirrorDataTileGzipSize.WithLabelValues(pending.Origin).Observe(float64(len(cutData)))
	dataKey := "mirror/" + OriginHash(pending.Origin) + "/" + torchwood.TilePath(dataTile)
	if err := w.c.Backend.Upload(ctx, dataKey, cutData, optsDataTile); err != nil {
		return fmtErrorf("failed to upload data tile %q: %w", dataKey, err)
	}
	w.m.MirrorTiles.WithLabelValues(pending.Origin, "true").Inc()

	if err := w.c.Backend.Upload(ctx, hashKey, cutHashes, optsHashTile); err != nil {
		return fmtErrorf("failed to upload tile %q: %w", hashKey, err)
	}
	w.m.MirrorTiles.WithLabelValues(pending.Origin, "true").Inc()

	return nil
}

func readUint16LengthPrefixed(r io.Reader) ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(length[:])
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func readUint64(r io.Reader) (int64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint64(buf[:])
	if n > math.MaxInt64 {
		return 0, fmt.Errorf("uint64 value %d overflows int64", n)
	}
	return int64(n), nil
}

func readUint8(r io.Reader) (uint8, error) {
	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return buf[0], nil
}

func parseLogList(logList []byte) (map[string]string, error) {
	logs := make(map[string]string)
	var sawHeader bool
	var vkey, origin string
	finalizeLogEntry := func() {
		if vkey == "" {
			// The list may be empty.
			return
		}
		defer func() {
			vkey = ""
			origin = ""
		}()
		v, err := newLogVerifier(vkey)
		if err != nil {
			// Invalid vkey, skip.
			return
		}
		if origin == "" {
			origin = v.Name()
		}
		if logs[origin] != "" {
			// Duplicate origin, skip.
			return
		}
		logs[origin] = vkey
	}
	for line := range strings.Lines(string(logList)) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			// Comment line, skip.
			continue
		}
		if line == "" {
			// Empty line, skip.
			continue
		}
		if !sawHeader {
			// First non-comment, non-empty line is the header.
			if line != "logs/v0" {
				return nil, fmt.Errorf("invalid log list header: %q", line)
			}
			sawHeader = true
			continue
		}
		key, value, _ := strings.Cut(line, " ")
		if vkey == "" && key != "vkey" {
			return nil, fmt.Errorf("expected vkey entry, got %q", line)
		}
		switch key {
		case "vkey":
			finalizeLogEntry()
			if value == "" {
				return nil, fmt.Errorf("empty vkey entry")
			}
			vkey = value
		case "origin":
			origin = value
		default:
			// Unknown key, ignore.
		}
	}
	finalizeLogEntry()
	return logs, nil
}

// newLogVerifier returns a note.Verifier for the given vkey string, or an error
// if the vkey is invalid.
//
// It supports regular (not cosignature) Ed25519 keys, and ML-DSA-44 cosignature
// keys, which are the ones that logs can be expected to use. (Ed25519 log
// signatures and cosignatures were split because we did not have the foresight
// to include a timestamp in the original Ed25519 signatures.)
func newLogVerifier(vkey string) (note.Verifier, error) {
	v1, err1 := note.NewVerifier(vkey)
	if err1 == nil {
		return v1, nil
	}
	v2, err2 := torchwood.NewCosignatureVerifier(vkey)
	if err2 != nil {
		return nil, fmt.Errorf("invalid vkey: %v / %v", err1, err2)
	}
	switch v2.PublicKey().(type) {
	case *mldsa.PublicKey:
		return v2, nil
	case ed25519.PublicKey:
		return nil, fmt.Errorf("Ed25519 cosignature keys are not supported for logs")
	default:
		return nil, fmt.Errorf("unsupported cosignature key type: %T", v2.PublicKey())
	}
}

func compress(data []byte) ([]byte, error) {
	b := &bytes.Buffer{}
	w := gzip.NewWriter(b)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

const maxCompressRatio = 100

func fetchAndDecompress(ctx context.Context, backend ctlog.Backend, key string) ([]byte, error) {
	data, err := backend.Fetch(ctx, key)
	if err != nil {
		return nil, err
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	maxSize := int64(len(data)) * maxCompressRatio
	b, err := io.ReadAll(io.LimitReader(r, maxSize))
	if err != nil {
		return nil, err
	}
	if len(b) == int(maxSize) {
		return nil, fmt.Errorf("decompressed data hit maximum size of %d bytes", maxSize)
	}
	return b, nil
}
