package ctlog

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/trillian/ctfe"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type metrics struct {
	inFlight *prometheus.GaugeVec
	requests *prometheus.CounterVec
	duration *prometheus.SummaryVec
}

func initMetrics() metrics {
	m := metrics{}
	m.inFlight = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "in_flight_requests",
		},
		[]string{"endpoint"},
	)
	m.requests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "requests_total",
		},
		[]string{"endpoint", "code"},
	)
	m.duration = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "request_duration_seconds",
			Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
			MaxAge:     1 * time.Minute,
			AgeBuckets: 6,
		},
		[]string{"endpoint", "code"},
	)
	return m
}

func (l *Log) Metrics() []prometheus.Collector {
	return append([]prometheus.Collector{
		l.m.duration,
		l.m.inFlight,
		l.m.requests,
	}, l.c.Backend.Metrics()...)
}

func (l *Log) Handler() http.Handler {
	addChainLabels := prometheus.Labels{"endpoint": "add-chain"}
	addChain := http.Handler(http.HandlerFunc(l.addChain))
	addChain = promhttp.InstrumentHandlerCounter(l.m.requests.MustCurryWith(addChainLabels), addChain)
	addChain = promhttp.InstrumentHandlerDuration(l.m.duration.MustCurryWith(addChainLabels), addChain)
	addChain = promhttp.InstrumentHandlerInFlight(l.m.inFlight.With(addChainLabels), addChain)

	addPreChainLabels := prometheus.Labels{"endpoint": "add-pre-chain"}
	addPreChain := http.Handler(http.HandlerFunc(l.addPreChain))
	addPreChain = promhttp.InstrumentHandlerCounter(l.m.requests.MustCurryWith(addPreChainLabels), addPreChain)
	addPreChain = promhttp.InstrumentHandlerDuration(l.m.duration.MustCurryWith(addPreChainLabels), addPreChain)
	addPreChain = promhttp.InstrumentHandlerInFlight(l.m.inFlight.With(addPreChainLabels), addPreChain)

	getRootsLabels := prometheus.Labels{"endpoint": "get-roots"}
	getRoots := http.Handler(http.HandlerFunc(l.getRoots))
	getRoots = promhttp.InstrumentHandlerCounter(l.m.requests.MustCurryWith(getRootsLabels), getRoots)
	getRoots = promhttp.InstrumentHandlerDuration(l.m.duration.MustCurryWith(getRootsLabels), getRoots)
	getRoots = promhttp.InstrumentHandlerInFlight(l.m.inFlight.With(getRootsLabels), getRoots)

	mux := http.NewServeMux()
	mux.Handle("/ct/v1/add-chain", addChain)
	mux.Handle("/ct/v1/add-pre-chain", addPreChain)
	mux.Handle("/ct/v1/get-roots", getRoots)
	return http.MaxBytesHandler(mux, 128*1024)
}

func (l *Log) addChain(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		l.c.Log.DebugContext(r.Context(), "got a non-POST request to add-chain", "method", r.Method)
		http.Error(rw, fmt.Sprintf("unsupported method %q", r.Method), http.StatusMethodNotAllowed)
		return
	}

	rsp, code, err := l.addChainOrPreChain(r.Context(), r.Body, func(le *LogEntry) error {
		if le.IsPrecert {
			return fmt.Errorf("pre-certificate submitted to add-chain")
		}
		return nil
	})
	if err != nil {
		l.c.Log.DebugContext(r.Context(), "add-chain error", "code", code, "err", err)
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
	if r.Method != "POST" {
		l.c.Log.DebugContext(r.Context(), "got a non-POST request to add-pre-chain", "method", r.Method)
		http.Error(rw, fmt.Sprintf("unsupported method %q", r.Method), http.StatusMethodNotAllowed)
		return
	}

	rsp, code, err := l.addChainOrPreChain(r.Context(), r.Body, func(le *LogEntry) error {
		if !le.IsPrecert {
			return fmt.Errorf("final certificate submitted to add-pre-chain")
		}
		return nil
	})
	if err != nil {
		l.c.Log.DebugContext(r.Context(), "add-pre-chain error", "code", code, "err", err)
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

func (l *Log) addChainOrPreChain(ctx context.Context, reqBody io.ReadCloser, checkType func(*LogEntry) error) (response []byte, code int, err error) {
	body, err := io.ReadAll(reqBody)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to read body: %s", err)
	}
	var req struct {
		Chain [][]byte
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("failed to parse request: %s", err)
	}
	if len(req.Chain) == 0 {
		return nil, http.StatusBadRequest, errors.New("empty chain")
	}

	chain, err := ctfe.ValidateChain(req.Chain, ctfe.NewCertValidationOpts(l.c.Roots, time.Time{}, true, false, &l.c.NotAfterStart, &l.c.NotAfterLimit, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}))
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid chain: %s", err)
	}

	e := &LogEntry{Certificate: chain[0].Raw}
	issuers := chain[1:]
	if isPrecert, err := ctfe.IsPrecertificate(chain[0]); err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid precertificate: %s", err)
	} else if isPrecert {
		if len(issuers) == 0 {
			return nil, http.StatusBadRequest, errors.New("missing precertificate issuer")
		}

		var preIssuer *x509.Certificate
		if ct.IsPreIssuer(issuers[0]) {
			preIssuer = issuers[0]
			issuers = issuers[1:]
			if len(issuers) == 0 {
				return nil, http.StatusBadRequest, errors.New("missing precertificate signing certificate issuer")
			}
		}

		defangedTBS, err := x509.BuildPrecertTBS(chain[0].RawTBSCertificate, preIssuer)
		if err != nil {
			return nil, http.StatusInternalServerError, fmt.Errorf("failed to build TBSCertificate: %s", err)
		}

		e.IsPrecert = true
		e.Certificate = defangedTBS
		e.PreCertificate = chain[0].Raw
		if preIssuer != nil {
			e.PrecertSigningCert = preIssuer.Raw
		}
		e.IssuerKeyHash = sha256.Sum256(issuers[0].RawSubjectPublicKeyInfo)
	}
	if err := checkType(e); err != nil {
		return nil, http.StatusBadRequest, err
	}

	// TODO: upload any new issuers.

	waitLeaf := l.addLeafToPool(e)
	seq, err := waitLeaf(ctx)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	// The digitally-signed data of an SCT is technically not a MerkleTreeLeaf,
	// but it's a completely identical structure, except for the second field,
	// which is a SignatureType of value 0 and length 1 instead of a
	// MerkleLeafType of value 0 and length 1.
	sctSignature, err := digitallySign(l.c.Key, seq.MerkleTreeLeaf())
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	rsp, err := json.Marshal(&ct.AddChainResponse{
		SCTVersion: ct.V1,
		Timestamp:  uint64(seq.Timestamp),
		ID:         l.logID[:],
		Extensions: base64.StdEncoding.EncodeToString(seq.Extensions()),
		Signature:  sctSignature,
	})
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	return rsp, http.StatusOK, nil
}

func (l *Log) getRoots(rw http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		l.c.Log.DebugContext(r.Context(), "got a non-GET request to get-roots", "method", r.Method)
		http.Error(rw, fmt.Sprintf("unsupported method %q", r.Method), http.StatusMethodNotAllowed)
		return
	}

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
