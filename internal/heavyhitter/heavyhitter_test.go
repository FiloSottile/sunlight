package heavyhitter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// readerFromRecorder is a ResponseRecorder that implements io.ReaderFrom, like
// the net/http ResponseWriter does.
type readerFromRecorder struct {
	*httptest.ResponseRecorder
	readFromCalls int
}

func (r *readerFromRecorder) ReadFrom(src io.Reader) (int64, error) {
	r.readFromCalls++
	return io.Copy(r.ResponseRecorder, src)
}

func TestCountingWriter(t *testing.T) {
	// Like http.ServeContent, copy through a LimitedReader, which doesn't
	// implement io.WriterTo, so io.Copy uses the destination's ReadFrom.
	body := func() io.Reader { return io.LimitReader(strings.NewReader(strings.Repeat("x", 1000)), 1000) }

	rec := httptest.NewRecorder()
	cw := &countingWriter{ResponseWriter: rec}
	if _, err := io.Copy(cw, body()); err != nil {
		t.Fatal(err)
	}
	if cw.written != 1000 || rec.Body.Len() != 1000 {
		t.Errorf("without ReaderFrom: counted %d bytes, wrote %d, want 1000", cw.written, rec.Body.Len())
	}

	rfr := &readerFromRecorder{ResponseRecorder: httptest.NewRecorder()}
	cw = &countingWriter{ResponseWriter: rfr}
	if _, err := io.Copy(readerFromCountingWriter{cw}, body()); err != nil {
		t.Fatal(err)
	}
	if rfr.readFromCalls != 1 {
		t.Errorf("ReadFrom called %d times on the underlying writer, want 1", rfr.readFromCalls)
	}
	if cw.written != 1000 || rfr.Body.Len() != 1000 {
		t.Errorf("with ReaderFrom: counted %d bytes, wrote %d, want 1000", cw.written, rfr.Body.Len())
	}
}

func TestBytesTable(t *testing.T) {
	h := NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("x", 500))
	}))
	req := httptest.NewRequest("GET", "/tile/data/000", nil)
	req.Header.Set("User-Agent", "heavyhitter-test")
	req.RemoteAddr = "192.0.2.1:1234"
	for range 3 {
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	var found bool
	for _, item := range userAgentBytes.Top(200) {
		if item.Value == "heavyhitter-test" {
			found = true
			if item.Count != 1500 {
				t.Errorf("counted %d bytes, want 1500", item.Count)
			}
			if item.Latest != "192.0.2.1" {
				t.Errorf("latest source = %q, want 192.0.2.1", item.Latest)
			}
		}
	}
	if !found {
		t.Error("test User-Agent not found in the bytes table")
	}
}
