package ctlog_test

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"filippo.io/sunlight/internal/ctlog"
	"golang.org/x/sync/errgroup"
)

// Retain the slice passed to Write so tests can check that requests share an
// immutable response, including while a root update publishes its replacement.
type rootsResponseWriter struct {
	*httptest.ResponseRecorder
	snapshot []byte
	onWrite  func()
}

func (w *rootsResponseWriter) Write(p []byte) (int, error) {
	w.snapshot = p
	if w.onWrite != nil {
		w.onWrite()
	}
	return w.ResponseRecorder.Write(p)
}

func getRootsResponse(t *testing.T, handler http.Handler) *rootsResponseWriter {
	t.Helper()
	w := &rootsResponseWriter{ResponseRecorder: httptest.NewRecorder()}
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ct/v1/get-roots", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("get-roots status = %d, want 200", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("unexpected get-roots headers: %v", w.Header())
	}
	if w.Header().Get("Cache-Control") != "" {
		t.Fatalf("get-roots unexpectedly sets cache policy: %v", w.Header())
	}
	return w
}

func rootsPEM(certs ...[]byte) []byte {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}))
	}
	return buf.Bytes()
}

func rootsJSON(t *testing.T, certs ...[]byte) []byte {
	t.Helper()
	// Match the original handler, including [] for an empty pool and the newline.
	res := struct {
		Certificates [][]byte `json:"certificates"`
	}{Certificates: append(make([][]byte, 0, len(certs)), certs...)}
	var buf bytes.Buffer
	fatalIfErr(t, json.NewEncoder(&buf).Encode(res))
	return buf.Bytes()
}

func TestGetRootsSnapshots(t *testing.T) {
	tl := NewEmptyTestLog(t)
	handler := tl.Log.Handler()
	initial := getRootsResponse(t, handler)
	if !bytes.Equal(initial.snapshot, rootsJSON(t, testRoot)) {
		t.Fatal("initial response differs from the original JSON encoding")
	}

	// An unchanged refresh must neither persist roots nor replace the response.
	backend := tl.Config.Backend.(*MemoryBackend)
	uploads := backend.uploads.Load()
	fatalIfErr(t, tl.Log.SetRootsFromPEM(t.Context(), tl.Log.RootsPEM()))
	unchanged := getRootsResponse(t, handler)
	if &initial.snapshot[0] != &unchanged.snapshot[0] || backend.uploads.Load() != uploads {
		t.Fatal("unchanged roots caused an upload or response replacement")
	}

	fatalIfErr(t, tl.Log.SetRootsFromPEM(t.Context(), rootsPEM(testRoot, testIntermediate)))
	added := getRootsResponse(t, handler)
	if !bytes.Equal(added.snapshot, rootsJSON(t, testRoot, testIntermediate)) {
		t.Fatal("response did not include the added root")
	}
	if &initial.snapshot[0] == &added.snapshot[0] || !bytes.Equal(initial.snapshot, rootsJSON(t, testRoot)) {
		t.Fatal("root addition reused or modified the previous response")
	}

	// PEM comments, ordering, and duplicates do not change the accepted set.
	reformatted := append([]byte("# refreshed roots\n"), rootsPEM(testIntermediate, testRoot, testRoot)...)
	fatalIfErr(t, tl.Log.SetRootsFromPEM(t.Context(), reformatted))
	if !bytes.Equal(tl.Log.RootsPEM(), reformatted) {
		t.Fatal("PEM metadata update was not preserved")
	}
	if next := getRootsResponse(t, handler); &next.snapshot[0] != &added.snapshot[0] {
		t.Fatal("unchanged accepted set replaced the response")
	}

	// VMark reconciliation can remove roots as well as add them.
	fatalIfErr(t, tl.Log.SetRootsFromPEM(t.Context(), rootsPEM(testIntermediate)))
	removed := getRootsResponse(t, handler)
	if !bytes.Equal(removed.snapshot, rootsJSON(t, testIntermediate)) {
		t.Fatal("response still includes a removed root")
	}
	if !bytes.Equal(added.snapshot, rootsJSON(t, testRoot, testIntermediate)) {
		t.Fatal("root removal modified the previous response")
	}

	reloaded := ReloadLog(t, tl)
	if got := getRootsResponse(t, reloaded.Log.Handler()); !bytes.Equal(got.snapshot, removed.snapshot) {
		t.Fatal("startup did not render the persisted roots")
	}
}

func TestGetRootsEmptyStartup(t *testing.T) {
	tl := NewEmptyTestLog(t)
	fatalIfErr(t, tl.Config.Backend.Upload(t.Context(), "_roots.pem", nil, &ctlog.UploadOptions{}))
	reloaded := ReloadLog(t, tl)
	if got := getRootsResponse(t, reloaded.Log.Handler()); !bytes.Equal(got.snapshot, rootsJSON(t)) {
		t.Fatalf("empty root response = %q, want an empty certificates array", got.snapshot)
	}
}

func TestGetRootsFailedUpdates(t *testing.T) {
	tl := NewEmptyTestLog(t)
	handler := tl.Log.Handler()
	initial := getRootsResponse(t, handler)
	initialPEM := bytes.Clone(tl.Log.RootsPEM())
	backend := tl.Config.Backend.(*MemoryBackend)
	for _, tc := range []struct {
		name string
		pem  []byte
		fail bool
	}{
		{name: "invalid PEM", pem: []byte("not a certificate")},
		{name: "invalid DER", pem: rootsPEM([]byte("not DER"))},
		{name: "upload failure", pem: rootsPEM(testRoot, testIntermediate), fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.fail {
				backend.UploadCallback = func(key string, _ []byte) (bool, error) {
					return false, errors.New("root upload failed")
				}
				defer func() { backend.UploadCallback = nil }()
			}
			if err := tl.Log.SetRootsFromPEM(t.Context(), tc.pem); err == nil {
				t.Fatal("expected root update failure")
			}
			got := getRootsResponse(t, handler)
			if &got.snapshot[0] != &initial.snapshot[0] || !bytes.Equal(got.snapshot, rootsJSON(t, testRoot)) {
				t.Fatal("failed update replaced or modified the response")
			}
			if !bytes.Equal(tl.Log.RootsPEM(), initialPEM) {
				t.Fatal("failed update changed accepted roots")
			}
		})
	}
	fatalIfErr(t, tl.Log.SetRootsFromPEM(t.Context(), rootsPEM(testRoot, testIntermediate)))
	if got := getRootsResponse(t, handler); !bytes.Equal(got.snapshot, rootsJSON(t, testRoot, testIntermediate)) {
		t.Fatal("successful retry did not publish new roots")
	}
}

func TestGetRootsInFlightUpdate(t *testing.T) {
	tl := NewEmptyTestLog(t)
	handler := tl.Log.Handler()
	w := &rootsResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		onWrite: func() {
			// Updating roots during Write must not block on the response's lock
			// or mutate the bytes that the client is still receiving.
			fatalIfErr(t, tl.Log.SetRootsFromPEM(t.Context(), rootsPEM(testRoot, testIntermediate)))
		},
	}
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ct/v1/get-roots", nil))
	if !bytes.Equal(w.Body.Bytes(), rootsJSON(t, testRoot)) {
		t.Fatal("in-flight response changed during the root update")
	}
	if got := getRootsResponse(t, handler); !bytes.Equal(got.snapshot, rootsJSON(t, testRoot, testIntermediate)) {
		t.Fatal("subsequent request did not see the new roots")
	}
}

func TestGetRootsConcurrentUpdates(t *testing.T) {
	tl := NewEmptyTestLog(t)
	tl.Quiet()
	handler := tl.Log.Handler()
	pems := [][]byte{rootsPEM(testRoot), rootsPEM(testRoot, testIntermediate)}
	bodies := [][]byte{rootsJSON(t, testRoot), rootsJSON(t, testRoot, testIntermediate)}
	var group errgroup.Group
	for range 8 {
		group.Go(func() error {
			for range 100 {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/ct/v1/get-roots", nil))
				if w.Code != http.StatusOK || (!bytes.Equal(w.Body.Bytes(), bodies[0]) && !bytes.Equal(w.Body.Bytes(), bodies[1])) {
					return fmt.Errorf("get-roots returned a partial or invalid snapshot (status %d)", w.Code)
				}
			}
			return nil
		})
	}
	group.Go(func() error {
		for i := range 100 {
			if err := tl.Log.SetRootsFromPEM(t.Context(), pems[i%len(pems)]); err != nil {
				return err
			}
		}
		return nil
	})
	fatalIfErr(t, group.Wait())
}
