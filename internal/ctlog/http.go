package ctlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"filippo.io/sunlight"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (l *Log) Handler() http.Handler {
	addChainLabels := prometheus.Labels{"endpoint": "add-chain"}
	addChain := http.Handler(http.HandlerFunc(l.addChain))
	addChain = promhttp.InstrumentHandlerCounter(l.m.ReqCount.MustCurryWith(addChainLabels), addChain)
	addChain = promhttp.InstrumentHandlerDuration(l.m.ReqDuration.MustCurryWith(addChainLabels), addChain)
	addChain = promhttp.InstrumentHandlerInFlight(l.m.ReqInFlight.With(addChainLabels), addChain)

	addPreChainLabels := prometheus.Labels{"endpoint": "add-pre-chain"}
	addPreChain := http.Handler(http.HandlerFunc(l.addPreChain))
	addPreChain = promhttp.InstrumentHandlerCounter(l.m.ReqCount.MustCurryWith(addPreChainLabels), addPreChain)
	addPreChain = promhttp.InstrumentHandlerDuration(l.m.ReqDuration.MustCurryWith(addPreChainLabels), addPreChain)
	addPreChain = promhttp.InstrumentHandlerInFlight(l.m.ReqInFlight.With(addPreChainLabels), addPreChain)

	getRootsLabels := prometheus.Labels{"endpoint": "get-roots"}
	getRoots := http.Handler(http.HandlerFunc(l.getRoots))
	getRoots = promhttp.InstrumentHandlerCounter(l.m.ReqCount.MustCurryWith(getRootsLabels), getRoots)
	getRoots = promhttp.InstrumentHandlerDuration(l.m.ReqDuration.MustCurryWith(getRootsLabels), getRoots)
	getRoots = promhttp.InstrumentHandlerInFlight(l.m.ReqInFlight.With(getRootsLabels), getRoots)

	mux := http.NewServeMux()
	mux.Handle("POST /ct/v1/add-chain", addChain)
	mux.Handle("POST /ct/v1/add-pre-chain", addPreChain)
	mux.Handle("GET /ct/v1/get-roots", getRoots)
	return http.MaxBytesHandler(mux, 128*1024)
}

type reusedConnContextKey struct{}

// ReusedConnContext must be used as the http.Server.ConnContext field to allow
// tracking of reused connections.
func ReusedConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, reusedConnContextKey{}, &atomic.Bool{})
}

func (l *Log) addChain(rw http.ResponseWriter, r *http.Request) {
	rsp, code, err := l.addChainOrPreChain(r.Context(), r.Body, func(le *PendingLogEntry) error {
		if le.IsPrecert {
			return fmtErrorf("pre-certificate submitted to add-chain")
		}
		return nil
	})
	if err != nil {
		l.c.Log.DebugContext(r.Context(), "add-chain error", "code", code, "err", err)
		if code == http.StatusServiceUnavailable {
			rw.Header().Set("Retry-After", fmt.Sprintf("%d", 30+rand.Intn(60)))
			http.Error(rw, "😮‍💨 this party is popular and the pool is full ✨ please retry later 🥺", code)
			return
		}
		http.Error(rw, err.Error(), code)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	if _, err := rw.Write(rsp); err != nil {
		l.c.Log.DebugContext(r.Context(), "failed to write add-chain response", "err", err)
		return
	}
}

func (l *Log) addPreChain(rw http.ResponseWriter, r *http.Request) {
	rsp, code, err := l.addChainOrPreChain(r.Context(), r.Body, func(le *PendingLogEntry) error {
		if !le.IsPrecert {
			return fmtErrorf("final certificate submitted to add-pre-chain")
		}
		return nil
	})
	if err != nil {
		l.c.Log.DebugContext(r.Context(), "add-pre-chain error", "code", code, "err", err)
		if code == http.StatusServiceUnavailable {
			rw.Header().Set("Retry-After", fmt.Sprintf("%d", 30+rand.Intn(60)))
			http.Error(rw, "😮‍💨 this party is popular and the pool is full ✨ please retry later 🥺", code)
			return
		}
		http.Error(rw, err.Error(), code)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	if _, err := rw.Write(rsp); err != nil {
		l.c.Log.DebugContext(r.Context(), "failed to write add-pre-chain response", "err", err)
		return
	}
}

func (l *Log) addChainOrPreChain(ctx context.Context, reqBody io.ReadCloser, checkType func(*PendingLogEntry) error) (response []byte, code int, err error) {
	labels := prometheus.Labels{"error": "", "issuer": "", "root": "", "reused": "",
		"precert": "", "preissuer": "", "chain_len": "", "source": ""}
	defer func() {
		if err != nil {
			labels["error"] = errorCategory(err)
		}
		l.m.AddChainCount.With(labels).Inc()
	}()
	if b, ok := ctx.Value(reusedConnContextKey{}).(*atomic.Bool); ok && b.Swap(true) {
		labels["reused"] = "true"
	}

	body, err := io.ReadAll(reqBody)
	if err != nil {
		return nil, http.StatusInternalServerError, fmtErrorf("failed to read body: %w", err)
	}
	var req struct {
		Chain [][]byte
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, http.StatusBadRequest, fmtErrorf("failed to parse request: %w", err)
	}
	if len(req.Chain) == 0 {
		return nil, http.StatusBadRequest, fmtErrorf("empty chain")
	}

	chain, err := ctfe.ValidateChain(req.Chain, ctfe.NewCertValidationOpts(l.c.Roots, time.Time{}, false, false, &l.c.NotAfterStart, &l.c.NotAfterLimit, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}))
	if err != nil {
		return nil, http.StatusBadRequest, fmtErrorf("invalid chain: %w", err)
	}
	labels["chain_len"] = fmt.Sprintf("%d", len(chain))
	labels["root"] = x509util.NameToString(chain[len(chain)-1].Subject)
	labels["issuer"] = x509util.NameToString(chain[0].Issuer)

	e := &PendingLogEntry{Certificate: chain[0].Raw}
	issuers := chain[1:]
	if isPrecert, err := ctfe.IsPrecertificate(chain[0]); err != nil {
		l.c.Log.WarnContext(ctx, "invalid precertificate", "err", err, "body", body)
		return nil, http.StatusBadRequest, fmtErrorf("invalid precertificate: %w", err)
	} else if isPrecert {
		labels["precert"] = "true"
		if len(issuers) == 0 {
			l.c.Log.WarnContext(ctx, "missing precertificate issuer", "err", err, "body", body)
			return nil, http.StatusBadRequest, fmtErrorf("missing precertificate issuer")
		}

		var preIssuer *x509.Certificate
		if ct.IsPreIssuer(issuers[0]) {
			preIssuer = issuers[0]
			labels["preissuer"] = "true"
			labels["issuer"] = x509util.NameToString(preIssuer.Issuer)
			if len(issuers) == 1 {
				l.c.Log.WarnContext(ctx, "missing precertificate signing certificate issuer", "err", err, "body", body)
				return nil, http.StatusBadRequest, fmtErrorf("missing precertificate signing certificate issuer")
			}
		}

		defangedTBS, err := x509.BuildPrecertTBS(chain[0].RawTBSCertificate, preIssuer)
		if err != nil {
			l.c.Log.ErrorContext(ctx, "failed to build TBSCertificate", "err", err, "body", body)
			return nil, http.StatusInternalServerError, fmtErrorf("failed to build TBSCertificate: %w", err)
		}

		e.IsPrecert = true
		e.Certificate = defangedTBS
		e.PreCertificate = chain[0].Raw
		if preIssuer != nil {
			e.IssuerKeyHash = sha256.Sum256(issuers[1].RawSubjectPublicKeyInfo)
		} else {
			e.IssuerKeyHash = sha256.Sum256(issuers[0].RawSubjectPublicKeyInfo)
		}
	}
	if err := checkType(e); err != nil {
		return nil, http.StatusBadRequest, err
	}

	for _, issuer := range issuers {
		if err := l.uploadIssuer(ctx, issuer); err != nil {
			l.c.Log.ErrorContext(ctx, "failed to upload issuer", "err", err, "body", body)
			return nil, http.StatusInternalServerError, fmtErrorf("failed to upload issuer: %w", err)
		}
	}

	waitLeaf, source := l.addLeafToPool(e)
	labels["source"] = source
	waitTimer := prometheus.NewTimer(l.m.AddChainWait)
	seq, err := waitLeaf(ctx)
	if source == "sequencer" {
		waitTimer.ObserveDuration()
	}
	if err == errPoolFull {
		return nil, http.StatusServiceUnavailable, err
	} else if err != nil {
		return nil, http.StatusInternalServerError, fmtErrorf("failed to sequence leaf: %w", err)
	}

	ext, err := sunlight.MarshalExtensions(sunlight.Extensions{LeafIndex: seq.LeafIndex})
	if err != nil {
		l.c.Log.ErrorContext(ctx, "failed to encode extensions", "err", err, "body", body)
		return nil, http.StatusInternalServerError, fmtErrorf("failed to encode extensions: %w", err)
	}
	// The digitally-signed data of an SCT is technically not a MerkleTreeLeaf,
	// but it's a completely identical structure, except for the second field,
	// which is a SignatureType of value 0 and length 1 instead of a
	// MerkleLeafType of value 0 and length 1.
	sctSignature, err := digitallySign(l.c.Key, seq.MerkleTreeLeaf())
	if err != nil {
		l.c.Log.ErrorContext(ctx, "failed to sign SCT", "err", err, "body", body)
		return nil, http.StatusInternalServerError, fmtErrorf("failed to sign SCT: %w", err)
	}

	rsp, err := json.Marshal(&ct.AddChainResponse{
		SCTVersion: ct.V1,
		Timestamp:  uint64(seq.Timestamp),
		ID:         l.logID[:],
		Extensions: base64.StdEncoding.EncodeToString(ext),
		Signature:  sctSignature,
	})
	if err != nil {
		l.c.Log.ErrorContext(ctx, "failed to encode response", "err", err, "body", body)
		return nil, http.StatusInternalServerError, fmtErrorf("failed to encode response: %w", err)
	}

	return rsp, http.StatusOK, nil
}

func (l *Log) uploadIssuer(ctx context.Context, issuer *x509.Certificate) error {
	fingerprint := sha256.Sum256(issuer.Raw)

	l.issuersMu.RLock()
	found := l.issuers[fingerprint]
	l.issuersMu.RUnlock()
	if found {
		return nil
	}

	l.issuersMu.Lock()
	defer l.issuersMu.Unlock()

	if l.issuers[fingerprint] {
		return nil
	}

	path := fmt.Sprintf("issuer/%x", fingerprint)
	l.c.Log.InfoContext(ctx, "observed new issuer", "issuer", x509util.NameToString(issuer.Subject), "path", path)

	// First we try to download and check the issuer from the backend.
	// If it's not there, we upload it.

	old, err := l.c.Backend.Fetch(ctx, path)
	if err != nil {
		upErr := l.c.Backend.Upload(ctx, path, issuer.Raw, optsIssuer)
		l.c.Log.InfoContext(ctx, "uploaded issuer", "path", path, "err", upErr, "fetchErr", err, "size", len(issuer.Raw))
		if upErr != nil {
			return fmtErrorf("upload error: %w; fetch error: %v", upErr, err)
		}
	} else {
		if !bytes.Equal(old, issuer.Raw) {
			return fmtErrorf("invalid existing issuer: %x", old)
		}
	}

	l.issuers[fingerprint] = true
	l.m.Issuers.Set(float64(len(l.issuers)))
	return nil
}

func (l *Log) getRoots(rw http.ResponseWriter, r *http.Request) {
	roots := l.c.Roots.RawCertificates()
	var res struct {
		Certificates [][]byte `json:"certificates"`
	}
	res.Certificates = make([][]byte, 0, len(roots))
	for _, r := range roots {
		res.Certificates = append(res.Certificates, r.Raw)
	}

	rw.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(rw).Encode(res); err != nil {
		l.c.Log.DebugContext(r.Context(), "failed to write get-roots response", "err", err)
	}
}
