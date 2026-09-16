package ctlog_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	ct "github.com/google/certificate-transparency-go"
)

func addPreChain(t *testing.T, tl *TestLog, ctx context.Context) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string][][]byte{
		"chain": {testPrecert, testIntermediate, testRoot}})
	fatalIfErr(t, err)
	req := httptest.NewRequestWithContext(ctx, "POST", "/ct/v1/add-pre-chain", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	tl.Log.Handler().ServeHTTP(rr, req)
	return rr
}

func TestClientDisconnect(t *testing.T) {
	tl := NewEmptyTestLog(t)
	logClient := tl.LogClient()

	// Submit a chain with the same issuers first, so that uploading the issuers
	// (the only operation before the pool wait that uses the request context)
	// is a no-op below.
	_, err := logClient.AddChain(context.Background(), []ct.ASN1Cert{
		{Data: testLeaf}, {Data: testIntermediate}, {Data: testRoot}})
	fatalIfErr(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rr := addPreChain(t, tl, ctx)

	if rr.Code != 499 {
		t.Errorf("got status %d, expected 499", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "client went away") {
		t.Errorf("unexpected response body: %s", rr.Body.String())
	}
}

func TestBodyReadErrors(t *testing.T) {
	tl := NewEmptyTestLog(t)

	t.Run("TooLarge", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/ct/v1/add-chain",
			bytes.NewReader(make([]byte, 128*1024+1)))
		rr := httptest.NewRecorder()
		tl.Log.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("got status %d, expected 413", rr.Code)
		}
	})

	t.Run("Disconnected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/ct/v1/add-chain",
			iotest.ErrReader(errors.New("connection reset by peer")))
		rr := httptest.NewRecorder()
		tl.Log.Handler().ServeHTTP(rr, req)
		if rr.Code != 499 {
			t.Errorf("got status %d, expected 499", rr.Code)
		}
	})
}

func TestStoppedSequencerIsServerError(t *testing.T) {
	tl := NewEmptyTestLog(t)

	// A stopped sequencer delivers context.Canceled to every request waiting on
	// the pool, but that's a server error, not a client disconnection.
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		if err := tl.Log.RunSequencer(ctx, time.Hour); !errors.Is(err, context.Canceled) {
			t.Errorf("RunSequencer returned %v, expected context.Canceled", err)
		}
	}()
	cancel()
	<-stopped

	rr := addPreChain(t, tl, context.Background())

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("got status %d, expected 500", rr.Code)
	}
}

// submitChain submits chain from remoteAddr with userAgent, sequencing the pool
// until the request completes, and returns the response.
func submitChain(t *testing.T, tl *TestLog, remoteAddr, userAgent string, chain [][]byte) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string][][]byte{"chain": chain})
	fatalIfErr(t, err)
	req := httptest.NewRequest("POST", "/ct/v1/add-chain", bytes.NewReader(body))
	req.RemoteAddr = remoteAddr
	req.Header.Set("User-Agent", userAgent)
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		tl.Log.Handler().ServeHTTP(rr, req)
	}()
	for {
		select {
		case <-done:
			return rr
		case <-time.After(10 * time.Millisecond):
			fatalIfErr(t, tl.Log.Sequence())
		}
	}
}

func TestDuplicateLimit(t *testing.T) {
	// testLeaf has embedded SCTs, so it's low priority, and the User-Agent
	// forces low priority anyway.
	chain := [][]byte{testLeaf, testIntermediate, testRoot}
	const crossPoster = "go-http-client/1.1 (ctlogs@google.com)"
	const a, b = "192.0.2.1:1234", "[2001:db8::1]:1234"

	t.Run("Disabled", func(t *testing.T) {
		tl := NewEmptyTestLog(t)
		for i := range 5 {
			if rr := submitChain(t, tl, a, crossPoster, chain); rr.Code != http.StatusOK {
				t.Fatalf("submission %d: got status %d, expected 200: %s", i, rr.Code, rr.Body)
			}
		}
	})

	t.Run("Enabled", func(t *testing.T) {
		tl := NewEmptyTestLog(t)
		tl.Log.SetDuplicateLimit(time.Minute, 2)

		// The first submission is sequenced, not deduplicated, so it's refunded.
		if rr := submitChain(t, tl, a, crossPoster, chain); rr.Code != http.StatusOK {
			t.Fatalf("got status %d, expected 200: %s", rr.Code, rr.Body)
		}
		// The next two are duplicates, and use up the burst.
		for i := range 2 {
			if rr := submitChain(t, tl, a, crossPoster, chain); rr.Code != http.StatusOK {
				t.Fatalf("duplicate %d: got status %d, expected 200: %s", i, rr.Code, rr.Body)
			}
		}
		// Now every low-priority request from the source is rejected, before
		// reaching the pool.
		rr := submitChain(t, tl, a, crossPoster, chain)
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("got status %d, expected 429: %s", rr.Code, rr.Body)
		}
		// High-priority requests from the same source go through, and don't
		// count against its budget.
		hpChain, hpRoot := makeHighPriorityChain(t)
		fatalIfErr(t, tl.Log.SetRootsFromPEM(t.Context(), append(
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testRoot}),
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hpRoot})...)))
		if rr := submitChain(t, tl, a, "high-priority", hpChain); rr.Code != http.StatusOK {
			t.Fatalf("got status %d for high-priority chain, expected 200: %s", rr.Code, rr.Body)
		}
		if rr := submitChain(t, tl, a, "high-priority", hpChain); rr.Code != http.StatusOK {
			t.Fatalf("got status %d for high-priority duplicate, expected 200: %s", rr.Code, rr.Body)
		}
		// Other sources are unaffected.
		if rr := submitChain(t, tl, b, crossPoster, chain); rr.Code != http.StatusOK {
			t.Fatalf("got status %d from another source, expected 200: %s", rr.Code, rr.Body)
		}
		// Rejected requests are not charged, and the rejected source is still
		// rejected while its budget refills.
		if rr := submitChain(t, tl, a, crossPoster, chain); rr.Code != http.StatusTooManyRequests {
			t.Fatalf("got status %d, expected 429: %s", rr.Code, rr.Body)
		}
	})
}

// makeHighPriorityChain returns a freshly issued certificate chain, which is
// high priority because it has no SCTs and isn't backdated, and the DER of its
// self-signed root, to be added to the log's trusted roots.
func makeHighPriorityChain(t *testing.T) (chain [][]byte, root []byte) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fatalIfErr(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test High-Priority Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	root, err = x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	fatalIfErr(t, err)
	rootCert, err := x509.ParseCertificate(root)
	fatalIfErr(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fatalIfErr(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "high-priority.example.com"},
		DNSNames:     []string{"high-priority.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	fatalIfErr(t, err)
	return [][]byte{leaf, root}, root
}
