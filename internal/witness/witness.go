package witness

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"filippo.io/sunlight/internal/ctlog"
	"filippo.io/torchwood"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

type Config struct {
	Name string
	Key  crypto.Signer

	Backend ctlog.LockBackend
	Log     *slog.Logger
}

// backendKeyForCheckpoint computes the LockBackend key for the given log origin.
//
// It is domain separated from all uses of LockBackend by the ctlog package, and
// by other Witness instances.
func backendKeyForCheckpoint(config *Config, origin string) [sha256.Size]byte {
	h := sha256.New()

	// Domain separation from [ctlog.logIDFromKey].
	h.Write(asn1.NullBytes)
	h.Write([]byte("witness log\n"))

	// Let multiple witnesses share the same LockBackend without affecting each
	// other's state. This is the opposite of what we want for logs we operate,
	// where we are in charge of preventing split-views, but witnesses have each
	// their own view of the state of each log they witness.
	//
	// Use the key instead of the name to prevent multiple witnesses from being
	// erroneously configured with the same key.
	h.Write(config.Key.Public().(ed25519.PublicKey))

	h.Write([]byte(origin))
	return [32]byte(h.Sum(nil))
}

// backendKeyForConfig computes the LockBackend key for the witness
// configuration.
func backendKeyForConfig(config *Config) [sha256.Size]byte {
	h := sha256.New()

	// Domain separation from all other uses of LockBackend.
	h.Write(asn1.NullBytes)
	h.Write([]byte("witness config\n"))

	h.Write(config.Key.Public().(ed25519.PublicKey))
	return [32]byte(h.Sum(nil))
}

type Witness struct {
	c *Config
	s *torchwood.CosignatureSigner
	m metrics

	// verifiers and checkpoints are indexed by log origin. They must be
	// accessed and updated under logsMu. The list of origins and their verifier
	// keys are stored in Backend, and are updated additively by PullLogList.
	logsMu      sync.RWMutex
	verifiers   map[string]note.Verifiers
	checkpoints map[string]*lockedCheckpoint
}

func (w *Witness) verifiersForOrigin(origin string) (note.Verifiers, bool) {
	w.logsMu.RLock()
	defer w.logsMu.RUnlock()
	v, ok := w.verifiers[origin]
	return v, ok
}

func (w *Witness) checkpointForOrigin(origin string) (*lockedCheckpoint, bool) {
	w.logsMu.RLock()
	defer w.logsMu.RUnlock()
	c, ok := w.checkpoints[origin]
	return c, ok
}

func (w *Witness) Logs() []string {
	w.logsMu.RLock()
	defer w.logsMu.RUnlock()
	logs := slices.Collect(maps.Keys(w.verifiers))
	slices.Sort(logs)
	return logs
}

type storedConfig struct {
	Logs []struct {
		Origin       string   `json:"origin"`
		VerifierKeys []string `json:"verifierKeys"`
	} `json:"logs"`
}

type lockedCheckpoint struct {
	sync.Mutex
	ctlog.LockedCheckpoint // can be nil if not fetched yet
}

func NewWitness(ctx context.Context, config *Config) (*Witness, error) {
	s, err := torchwood.NewCosignatureSigner(config.Name, config.Key)
	if err != nil {
		return nil, fmt.Errorf("couldn't create signer: %w", err)
	}

	w := &Witness{c: config, s: s, m: initMetrics()}

	logs, err := config.Backend.Fetch(ctx, backendKeyForConfig(config))
	if errors.Is(err, ctlog.ErrLogNotFound) {
		config.Log.WarnContext(ctx, "witness config not found in backend; creating new empty config")
		if err := config.Backend.Create(ctx, backendKeyForConfig(config), []byte("{}")); err != nil {
			return nil, fmt.Errorf("couldn't create witness config in backend: %w", err)
		}
		logs, err = config.Backend.Fetch(ctx, backendKeyForConfig(config))
	}
	if err != nil {
		return nil, fmt.Errorf("couldn't fetch witness config from backend: %w", err)
	}
	var stored storedConfig
	if err := json.Unmarshal(logs.Bytes(), &stored); err != nil {
		return nil, fmt.Errorf("couldn't parse stored witness config: %w", err)
	}

	w.verifiers = make(map[string]note.Verifiers, len(stored.Logs))
	w.checkpoints = make(map[string]*lockedCheckpoint, len(stored.Logs))
	for _, log := range stored.Logs {
		if _, ok := w.verifiers[log.Origin]; ok {
			return nil, fmt.Errorf("two logs with origin %q", log.Origin)
		}
		config.Log.DebugContext(ctx, "configured to witness log", "origin", log.Origin, "vkeys", log.VerifierKeys)
		var verifiers []note.Verifier
		for _, k := range log.VerifierKeys {
			v, err := note.NewVerifier(k)
			if err != nil {
				return nil, fmt.Errorf("couldn't parse vkey %q for log %q: %w", k, log.Origin, err)
			}
			verifiers = append(verifiers, v)
		}
		w.verifiers[log.Origin] = note.VerifierList(verifiers...)
		// Defer fetching checkpoints until needed, to avoid blocking startup.
		w.checkpoints[log.Origin] = &lockedCheckpoint{}
	}

	w.m.KnownLogs.Set(float64(len(stored.Logs)))
	config.Log.InfoContext(ctx, "starting witness", "name", config.Name, "logs", len(stored.Logs))
	return w, nil
}

func (w *Witness) VerifierKey() string {
	return w.s.Verifier().String()
}

func (w *Witness) PullLogList(ctx context.Context, url string) error {
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read log list response: %w", err)
	}
	logs, err := parseLogList(body)
	if err != nil {
		return fmt.Errorf("failed to parse log list: %w", err)
	}

	w.logsMu.Lock()
	defer w.logsMu.Unlock()
	verifiers := maps.Clone(w.verifiers)
	checkpoints := maps.Clone(w.checkpoints)
	newLogsAndVkeys := make(map[string]string)
	for origin, vkey := range logs {
		if _, ok := verifiers[origin]; ok {
			// Already known, skip.
			continue
		}
		v, err := note.NewVerifier(vkey)
		if err != nil {
			return fmt.Errorf("couldn't parse vkey %q for log %q: %w", vkey, origin, err)
		}
		w.c.Log.InfoContext(ctx, "adding new log to witness config", "origin", origin, "vkey", vkey, "source", url)
		if err := w.c.Backend.Create(ctx, backendKeyForCheckpoint(w.c, origin), nil); err != nil {
			return fmt.Errorf("couldn't create empty checkpoint for new log %q: %w", origin, err)
		}
		ch, err := w.c.Backend.Fetch(ctx, backendKeyForCheckpoint(w.c, origin))
		if err != nil {
			return fmt.Errorf("couldn't fetch empty checkpoint for new log %q: %w", origin, err)
		}
		verifiers[origin] = note.VerifierList(v)
		checkpoints[origin] = &lockedCheckpoint{LockedCheckpoint: ch}
		newLogsAndVkeys[origin] = vkey
	}

	// We don't actually need the compare-and-swap semantics to update the list
	// of verifier keys, a rollback of that would not cause a checkpoint rollback.
	oldLogs, err := w.c.Backend.Fetch(ctx, backendKeyForConfig(w.c))
	if err != nil {
		return fmt.Errorf("couldn't fetch existing witness config from backend: %w", err)
	}
	var stored storedConfig
	if err := json.Unmarshal(oldLogs.Bytes(), &stored); err != nil {
		return fmt.Errorf("couldn't parse stored witness config: %w", err)
	}
	for origin, vkey := range newLogsAndVkeys {
		stored.Logs = append(stored.Logs, struct {
			Origin       string   `json:"origin"`
			VerifierKeys []string `json:"verifierKeys"`
		}{
			Origin:       origin,
			VerifierKeys: []string{vkey},
		})
	}
	newConfigBytes, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("couldn't marshal updated witness config: %w", err)
	}
	if _, err := w.c.Backend.Replace(ctx, oldLogs, newConfigBytes); err != nil {
		return fmt.Errorf("couldn't store updated witness config: %w", err)
	}
	w.verifiers = verifiers
	w.checkpoints = checkpoints
	w.m.KnownLogs.Set(float64(len(w.verifiers)))

	return nil
}

func (w *Witness) Handler() http.Handler {
	labels := prometheus.Labels{"endpoint": "add-checkpoint"}
	addCheckpoint := http.Handler(http.HandlerFunc(w.serveAddCheckpoint))
	addCheckpoint = promhttp.InstrumentHandlerCounter(w.m.ReqCount.MustCurryWith(labels), addCheckpoint)
	addCheckpoint = promhttp.InstrumentHandlerDuration(w.m.ReqDuration.MustCurryWith(labels), addCheckpoint)
	addCheckpoint = promhttp.InstrumentHandlerInFlight(w.m.ReqInFlight.With(labels), addCheckpoint)

	mux := http.NewServeMux()
	mux.Handle("POST /add-checkpoint", addCheckpoint)
	return http.MaxBytesHandler(mux, 128*1024)
}

type conflictError struct {
	known int64
}

func (*conflictError) Error() string { return "known tree size doesn't match provided old size" }

var errUnknownLog = errors.New("unknown log")
var errInvalidSignature = errors.New("invalid signature")
var errBadRequest = errors.New("invalid input")
var errBadCheckpoint = errors.New("invalid checkpoint")
var errProof = errors.New("bad consistency proof")

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
	case errBadRequest:
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
			labels["error"] = err.Error()
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
	if err != nil || oldSize < 0 {
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
		return nil, errors.New("internal error: failed to verify note")
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return nil, errBadCheckpoint
	}
	if origin != c.Origin {
		return nil, errors.New("internal error: incoherent parsing")
	}
	labels["progress"] = "false"
	if c.N > oldSize {
		labels["progress"] = "true"
	}
	return w.updateCheckpoint(ctx, c.Origin, oldSize, c.N, c.Hash, proof, noteBytes)
}

func (w *Witness) updateCheckpoint(ctx context.Context, origin string,
	oldSize, newSize int64, newHash tlog.Hash, proof tlog.TreeProof,
	noteBytes []byte) ([]byte, error) {

	lock, ok := w.checkpointForOrigin(origin)
	if !ok {
		return nil, errors.New("internal error: lock not found for known log")
	}
	lock.Lock()
	defer lock.Unlock()

	if lock.LockedCheckpoint == nil {
		// Might not have been fetched yet, do it now. It must exist because it
		// is created (empty) when the log is added to the witness config.
		c, err := w.c.Backend.Fetch(ctx, backendKeyForCheckpoint(w.c, origin))
		if err != nil {
			return nil, errors.New("internal error: couldn't fetch checkpoint for known log")
		}
		lock.LockedCheckpoint = c
	}

	if len(lock.Bytes()) == 0 {
		if oldSize != 0 {
			return nil, &conflictError{0}
		}
	} else {
		n, err := note.Open(lock.Bytes(), note.VerifierList(w.s.Verifier()))
		if err != nil {
			return nil, errors.New("internal error: can't verify stored checkpoint")
		}
		known, err := torchwood.ParseCheckpoint(n.Text)
		if err != nil {
			return nil, errors.New("internal error: can't parse stored checkpoint")
		}

		if known.Origin != origin {
			return nil, errors.New("internal error: incoherent stored checkpoint")
		}
		if oldSize > newSize {
			return nil, errBadRequest
		}
		if known.N != oldSize {
			return nil, &conflictError{known.N}
		}
		if err := tlog.CheckTree(proof, newSize, newHash, known.N, known.Hash); err != nil {
			return nil, errProof
		}
	}

	// To avoid parser alignment issues, sign a re-encoding of what we interpreted.
	// If everything is working correctly, it will also be a valid signature on the
	// original note. If not, this fails safe.
	// https://bsky.app/profile/filippo.abyssdomain.expert/post/3lezjsf6wc2os
	signed, err := note.Sign(&note.Note{Text: torchwood.Checkpoint{
		Origin: origin, Tree: tlog.Tree{N: newSize, Hash: newHash},
	}.String()}, w.s)
	if err != nil {
		// Don't return the error here and below, to avoid leaking the signature
		// before the backend compare-and-swap succeeds, which is the ultimate
		// check against concurrent signers and locking bugs.
		return nil, errors.New("internal error: failed to sign note")
	}
	sigs, err := splitSignatures(signed)
	if err != nil {
		return nil, errors.New("internal error: produced invalid note")
	}
	new := append(noteBytes[:len(noteBytes):len(noteBytes)], sigs...)

	newLock, err := w.c.Backend.Replace(ctx, lock.LockedCheckpoint, new)
	if err != nil {
		// TODO: this is a fatal error, because we don't know if it was persisted.
		return nil, errors.New("internal error: failed to store new checkpoint")
	}
	lock.LockedCheckpoint = newLock

	w.m.LogSize.WithLabelValues(origin).Set(float64(newSize))

	return sigs, nil
}

func splitSignatures(note []byte) ([]byte, error) {
	var sigSplit = []byte("\n\n")
	split := bytes.LastIndex(note, sigSplit)
	if split < 0 {
		return nil, errors.New("invalid note")
	}
	_, sigs := note[:split+1], note[split+2:]
	if len(sigs) == 0 || sigs[len(sigs)-1] != '\n' {
		return nil, errors.New("invalid note")
	}
	return sigs, nil
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
		v, err := note.NewVerifier(vkey)
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
