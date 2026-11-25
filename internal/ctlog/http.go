package ctlog

import (
	"cmp"
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"filippo.io/sunlight"
	"filippo.io/sunlight/chain"
	"filippo.io/sunlight/internal/clientaddr"
	"filippo.io/sunlight/internal/reused"
	ct "github.com/google/certificate-transparency-go"
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

	rsp, code, err := l.addChainOrPreChain(r.Context(), r.Body, r.UserAgent(), clientaddr.Source(r), false)
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
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		rw.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		rw.WriteHeader(http.StatusNoContent)
		return
	}

	rsp, code, err := l.addChainOrPreChain(r.Context(), r.Body, r.UserAgent(), clientaddr.Source(r), true)
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

func (l *Log) addChainOrPreChain(ctx context.Context, reqBody io.ReadCloser, userAgent string, client netip.Prefix, precert bool) (response []byte, code int, err error) {
	labels := prometheus.Labels{"error": "", "issuer": "", "root": "", "reused": "",
		"precert": "", "chain_len": "", "low_priority": "", "source": ""}
	defer func() {
		// If the client went away before a response could be served, log a
		// non-standard status code to distinguish it from server errors.
		if errors.Is(err, context.Canceled) && ctx.Err() == context.Canceled {
			code = 499
			err = fmtErrorf("client went away: %w", err)
		}
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
		if errors.As(err, new(*http.MaxBytesError)) {
			return nil, http.StatusRequestEntityTooLarge, fmtErrorf("request body too large")
		}
		return nil, 499, fmtErrorf("failed to read body: %w", err)
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

	verifier := &chain.Verifier{
		Roots:         l.rootPool(),
		NotAfterStart: l.c.NotAfterStart,
		NotAfterLimit: l.c.NotAfterLimit,
		ExtKeyUsage:   chain.ServerAuth,
		BlockedKeys:   l.c.BlockedSPKIs,
	}
	if l.c.MarkCertificates {
		verifier.ExtKeyUsage = chain.BrandIndicatorForMessageIdentification
	}
	verified, err := verifier.Verify(req.Chain, precert)
	if err != nil {
		// The reason for the rejection is the subcategory of the error.
		if e, ok := errors.AsType[*chain.Error](err); ok {
			err = categoryError{category: e.Reason, err: err}
		}
		return nil, http.StatusBadRequest, fmtErrorf("invalid chain: %w", err)
	}
	lowPriority := lowPriorityLeaf(verified)
	labels["chain_len"] = fmt.Sprintf("%d", len(verified.Chain))
	labels["root"] = nameString(verified.Root)
	labels["issuer"] = nameString(verified.Issuer)
	labels["low_priority"] = fmt.Sprintf("%v", lowPriority)

	e := &PendingLogEntry{Certificate: verified.Chain[0], Issuers: verified.Chain[1:]}
	if precert {
		labels["precert"] = "true"
		e.IsPrecert = true
		e.Certificate = verified.TBSCertificate
		e.PreCertificate = verified.Chain[0]
		e.IssuerKeyHash = verified.IssuerKeyHash
	}

	// Rate limit sources that submit too many low-priority entries that are
	// already in the log. Low-priority requests from a source over its limit
	// are rejected before reaching the pool gate and the deduplication cache.
	// Every low-priority request is charged on admission, and refunded unless
	// it turns out to be a duplicate, so that requests in flight count against
	// the limit. High-priority requests are never charged nor rejected.
	var source string
	if lowPriority && l.sourceLimiter != nil {
		receipt, ok := l.sourceLimiter.Allow(client)
		if !ok {
			labels["source"] = "duplimit"
			limitedSources.Count(client.String(), fmt.Sprintf("%s %q", l.c.Name, userAgent))
			return nil, http.StatusTooManyRequests, fmtErrorf("source rate limited: too many submissions of entries already in the log")
		}
		defer func() {
			if source == "cache" && err == nil {
				return
			}
			l.sourceLimiter.Refund(receipt)
		}()
	}

	waitLeaf, source := l.addLeafToPool(ctx, e, lowPriority)
	labels["source"] = source
	waitTimer := prometheus.NewTimer(l.m.AddChainWait)
	seq, err := waitLeaf(ctx)
	if source == "sequencer" && err != errEvicted {
		waitTimer.ObserveDuration()
	}
	if err == errEvicted {
		labels["source"] = "evicted"
	}
	if err == errPoolFull || err == errEvicted || err == errTimeout {
		return nil, http.StatusServiceUnavailable, err
	} else if errors.As(err, new(SunsetLogError)) {
		return nil, http.StatusGone, err
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

func lowPriorityLeaf(v *chain.Verified) bool {
	if v.TBSCertificate != nil {
		// The BRs allow at most 48 hours of backdating. A precertificate older
		// than that can't turn into a valid certificate anymore, so it must be
		// cross-posted.
		return time.Since(v.NotBefore) >= 48*time.Hour
	}
	// If a certificate has SCTs, it's already been logged. It'd be better to
	// verify the signatures, but this check is meant for when we are under load
	// and need to prioritize.
	return v.SCTs
}

// attributeNames are the names of the most common attribute types of X.501 Names.
var attributeNames = map[string]string{
	"2.5.4.6": "C", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.3": "CN",
	"2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.5": "serialNumber",
	"2.5.4.9": "streetAddress", "2.5.4.17": "postalCode",
}

// nameString returns a description of a DER-encoded X.501 Name for use as a
// metrics label, like "C=US, O=Let's Encrypt, CN=E7". It lists the attributes
// in the order they are encoded, by OID if they are not in attributeNames.
func nameString(der []byte) string {
	var rdns pkix.RDNSequence
	if rest, err := asn1.Unmarshal(der, &rdns); err != nil || len(rest) != 0 {
		return fmt.Sprintf("%x", der)
	}
	var parts []string
	for _, rdn := range rdns {
		for _, atv := range rdn {
			oid := atv.Type.String()
			parts = append(parts, fmt.Sprintf("%s=%v", cmp.Or(attributeNames[oid], oid), atv.Value))
		}
	}
	return strings.Join(parts, ", ")
}

func (l *Log) getRoots(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	rw.Header().Set("Content-Type", "application/json")
	if _, err := rw.Write(l.rootsResponse()); err != nil {
		l.c.Log.DebugContext(r.Context(), "failed to write get-roots response", "err", err)
	}
}
