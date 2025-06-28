package witness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
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
	Key  ed25519.PrivateKey

	Backend ctlog.LockBackend
	Log     *slog.Logger

	Logs []LogConfig
}

type LogConfig struct {
	// Origin is the fully qualified log name for the checkpoint origin
	// line, usually a schema-less URL.
	Origin string

	// VerifierKeys is a list of vkey strings for the log.
	VerifierKeys []string
}

func logIDFromOrigin(origin string) [sha256.Size]byte {
	h := sha256.New()
	h.Write(asn1.NullBytes) // Domain separation from [ctlog.logIDFromKey].
	h.Write([]byte("Sunlight witness\n"))
	h.Write([]byte(origin))
	return [32]byte(h.Sum(nil))
}

type Witness struct {
	c *Config
	s *torchwood.CosignatureSigner
	m metrics

	verifiers map[string]note.Verifiers
	locks     map[string]*lockedCheckpoint
}

type lockedCheckpoint struct {
	sync.Mutex
	ctlog.LockedCheckpoint
}

func NewWitness(ctx context.Context, config *Config) (*Witness, error) {
	s, err := torchwood.NewCosignatureSigner(config.Name, config.Key)
	if err != nil {
		return nil, fmt.Errorf("couldn't create signer: %w", err)
	}

	l := make(map[string]note.Verifiers, len(config.Logs))
	locks := make(map[string]*lockedCheckpoint)
	for _, log := range config.Logs {
		if _, ok := l[log.Origin]; ok {
			return nil, fmt.Errorf("two logs with origin %q", log.Origin)
		}
		var verifiers []note.Verifier
		for _, k := range log.VerifierKeys {
			v, err := note.NewVerifier(k)
			if err != nil {
				return nil, fmt.Errorf("couldn't parse vkey %q for log %q: %w", k, log.Origin, err)
			}
			verifiers = append(verifiers, v)
		}
		l[log.Origin] = note.VerifierList(verifiers...)
		c, err := config.Backend.Fetch(ctx, logIDFromOrigin(log.Origin))
		if err != nil && !errors.Is(err, ctlog.ErrLogNotFound) {
			return nil, fmt.Errorf("couldn't fetch checkpoint for log %q: %w", log.Origin, err)
		}
		locks[log.Origin] = &lockedCheckpoint{LockedCheckpoint: c}
	}

	config.Log.InfoContext(ctx, "starting witness", "name", config.Name, "numLogs", len(config.Logs))

	w := &Witness{c: config, s: s, verifiers: l, locks: locks, m: initMetrics()}
	return w, nil
}

func (w *Witness) VerifierKey() string {
	return w.s.Verifier().String()
}

func (w *Witness) Handler() http.Handler {
	labels := prometheus.Labels{"endpoint": "get-roots"}
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
	case errUnknownLog, errInvalidSignature:
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
	l := w.c.Log.With("request", string(body))
	defer func() {
		if err != nil {
			l = l.With("error", err)
		}
		l.Debug("processed add-checkpoint request")
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
	l = l.With("oldSize", oldSize)
	proof := make(tlog.TreeProof, len(lines[1:]))
	for i, h := range lines[1:] {
		proof[i], err = tlog.ParseHash(h)
		if err != nil {
			return nil, errBadRequest
		}
	}
	origin, _, _ := strings.Cut(string(noteBytes), "\n")
	l = l.With("origin", origin)
	v, ok := w.verifiers[origin]
	if !ok {
		return nil, errUnknownLog
	}
	n, err := note.Open(noteBytes, v)
	switch err.(type) {
	case *note.UnverifiedNoteError, *note.InvalidSignatureError:
		return nil, errInvalidSignature
	}
	if err != nil {
		return nil, err
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return nil, err
	}
	if origin != c.Origin {
		return nil, errors.New("internal error: incoherent parsing")
	}
	l = l.With("size", c.N)
	return w.updateCheckpoint(ctx, c.Origin, oldSize, c.N, c.Hash, proof, noteBytes)
}

func (w *Witness) updateCheckpoint(ctx context.Context, origin string,
	oldSize, newSize int64, newHash tlog.Hash, proof tlog.TreeProof,
	noteBytes []byte) ([]byte, error) {

	lock, ok := w.locks[origin]
	if !ok {
		return nil, errors.New("internal error: lock not found for known log")
	}
	lock.Lock()
	defer lock.Unlock()

	if lock.LockedCheckpoint == nil {
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

	if lock.LockedCheckpoint == nil {
		err := w.c.Backend.Create(ctx, logIDFromOrigin(origin), new)
		if err != nil {
			return nil, errors.New("internal error: failed to create new checkpoint")
		}
		// Kinda unclear why [ctlog.LockBackend.Create] doesn't return the
		// [ctlog.LockedCheckpoint], but a race here would be harmless anyway.
		newLock, err := w.c.Backend.Fetch(ctx, logIDFromOrigin(origin))
		if err != nil {
			return nil, errors.New("internal error: failed to fetch new checkpoint")
		}
		lock.LockedCheckpoint = newLock
	} else {
		newLock, err := w.c.Backend.Replace(ctx, lock.LockedCheckpoint, new)
		if err != nil {
			return nil, errors.New("internal error: failed to store new checkpoint")
		}
		lock.LockedCheckpoint = newLock
	}

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
