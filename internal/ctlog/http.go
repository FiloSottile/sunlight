package ctlog

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/reused"
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
	mux.Handle("OPTIONS /ct/v1/add-chain", addChain)
	mux.Handle("POST /ct/v1/add-pre-chain", addPreChain)
	mux.Handle("OPTIONS /ct/v1/add-pre-chain", addPreChain)
	mux.Handle("GET /ct/v1/get-roots", getRoots)
	return http.MaxBytesHandler(mux, 128*1024)
}

func (l *Log) addChain(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		rw.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		rw.WriteHeader(http.StatusNoContent)
		return
	}

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
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		rw.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		rw.WriteHeader(http.StatusNoContent)
		return
	}

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
	if r, ok := ctx.Value(reused.ContextKey).(bool); ok {
		labels["reused"] = fmt.Sprintf("%t", r)
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

	chain, err := ctfe.ValidateChain(req.Chain, ctfe.NewCertValidationOpts(l.rootPool(), time.Time{}, false, false, &l.c.NotAfterStart, &l.c.NotAfterLimit, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}))
	if err != nil {
		return nil, http.StatusBadRequest, fmtErrorf("invalid chain: %w", err)
	}
	labels["chain_len"] = fmt.Sprintf("%d", len(chain))
	labels["root"] = x509util.NameToString(chain[len(chain)-1].Subject)
	labels["issuer"] = x509util.NameToString(chain[0].Issuer)

	e := &PendingLogEntry{Certificate: chain[0].Raw}
	for _, issuer := range chain[1:] {
		e.Issuers = append(e.Issuers, issuer.Raw)
	}
	if isPrecert, err := ctfe.IsPrecertificate(chain[0]); err != nil {
		l.c.Log.WarnContext(ctx, "invalid precertificate", "err", err, "body", body)
		return nil, http.StatusBadRequest, fmtErrorf("invalid precertificate: %w", err)
	} else if isPrecert {
		labels["precert"] = "true"
		if len(chain) < 2 {
			l.c.Log.WarnContext(ctx, "missing precertificate issuer", "err", err, "body", body)
			return nil, http.StatusBadRequest, fmtErrorf("missing precertificate issuer")
		}

		var preIssuer *x509.Certificate
		if ct.IsPreIssuer(chain[1]) {
			preIssuer = chain[1]
			labels["preissuer"] = "true"
			labels["issuer"] = x509util.NameToString(preIssuer.Issuer)
			if len(chain) < 3 {
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
			e.IssuerKeyHash = sha256.Sum256(chain[2].RawSubjectPublicKeyInfo)
		} else {
			e.IssuerKeyHash = sha256.Sum256(chain[1].RawSubjectPublicKeyInfo)
		}
	}
	if err := checkType(e); err != nil {
		return nil, http.StatusBadRequest, err
	}

	waitLeaf, source := l.addLeafToPool(ctx, e)
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

func (l *Log) getRoots(rw http.ResponseWriter, r *http.Request) {
	roots := l.rootPool().RawCertificates()
	var res struct {
		Certificates [][]byte `json:"certificates"`
	}
	res.Certificates = make([][]byte, 0, len(roots))
	for _, r := range roots {
		res.Certificates = append(res.Certificates, r.Raw)
	}

	rw.Header().Set("Access-Control-Allow-Origin", "*")
	rw.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(rw).Encode(res); err != nil {
		l.c.Log.DebugContext(r.Context(), "failed to write get-roots response", "err", err)
	}
}
