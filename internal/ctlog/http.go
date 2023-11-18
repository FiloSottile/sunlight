package ctlog

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

	mux := http.NewServeMux()
	mux.Handle("/ct/v1/add-chain", addChain)
	mux.Handle("/ct/v1/add-pre-chain", addPreChain)
	return http.MaxBytesHandler(mux, 128*1024)
}

func (l *Log) addChain(rw http.ResponseWriter, r *http.Request) {
	l.addChainOrPreChain(rw, r, func(le *LogEntry) error {
		if le.IsPrecert {
			return fmt.Errorf("pre-certificate submitted to add-chain")
		}
		return nil
	})
}

func (l *Log) addPreChain(rw http.ResponseWriter, r *http.Request) {
	l.addChainOrPreChain(rw, r, func(le *LogEntry) error {
		if !le.IsPrecert {
			return fmt.Errorf("final certificate submitted to add-pre-chain")
		}
		return nil
	})
}

func (l *Log) addChainOrPreChain(rw http.ResponseWriter, r *http.Request, checkType func(*LogEntry) error) {
	if r.Method != "POST" {
		http.Error(rw, fmt.Sprintf("unsupported method %q", r.Method), http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, fmt.Sprintf("failed to read body: %s", err), http.StatusInternalServerError)
		return
	}
	var req struct {
		Chain [][]byte
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(rw, fmt.Sprintf("failed to parse request: %s", err), http.StatusBadRequest)
		return
	}
	if len(req.Chain) == 0 {
		http.Error(rw, "empty chain", http.StatusBadRequest)
		return
	}

	chain, err := ctfe.ValidateChain(req.Chain, ctfe.NewCertValidationOpts(l.c.Roots, time.Time{}, true, false, &l.c.NotAfterStart, &l.c.NotAfterLimit, false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}))
	if err != nil {
		http.Error(rw, fmt.Sprintf("invalid chain: %s", err), http.StatusBadRequest)
		return
	}

	e := &LogEntry{Certificate: chain[0].Raw}
	issuers := chain[1:]
	if isPrecert, err := ctfe.IsPrecertificate(chain[0]); err != nil {
		http.Error(rw, fmt.Sprintf("invalid precertificate: %s", err), http.StatusBadRequest)
		return
	} else if isPrecert {
		if len(issuers) == 0 {
			http.Error(rw, "missing precertificate issuer", http.StatusBadRequest)
			return
		}

		var preIssuer *x509.Certificate
		if ct.IsPreIssuer(issuers[0]) {
			preIssuer = issuers[0]
			issuers = issuers[1:]
			if len(issuers) == 0 {
				http.Error(rw, "missing precertificate signing certificate issuer", http.StatusBadRequest)
				return
			}
		}

		defangedTBS, err := x509.BuildPrecertTBS(chain[0].RawTBSCertificate, preIssuer)
		if err != nil {
			http.Error(rw, fmt.Sprintf("failed to build TBSCertificate: %s", err), http.StatusInternalServerError)
			return
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
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: upload any new issuers.

	waitLeaf := l.addLeafToPool(e)
	seq, err := waitLeaf(r.Context())
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	// The digitally-signed data of an SCT is technically not a MerkleTreeLeaf,
	// but it's a completely identical structure, except for the second field,
	// which is a SignatureType of value 0 and length 1 instead of a
	// MerkleLeafType of value 0 and length 1.
	sctSignature, err := digitallySign(l.c.Key, seq.MerkleTreeLeaf())
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rsp, err := json.Marshal(&ct.AddChainResponse{
		SCTVersion: ct.V1,
		Timestamp:  uint64(seq.Timestamp),
		ID:         l.logID[:],
		Extensions: base64.StdEncoding.EncodeToString(seq.Extensions()),
		Signature:  sctSignature,
	})
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	if _, err := rw.Write(rsp); err != nil {
		// Too late for http.Error.
		return
	}
}
