package ctlog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
