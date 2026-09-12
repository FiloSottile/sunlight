// Package heavyhitter registers two endpoints /debug/heavyhitter/useragents and
// /debug/heavyhitter/ips as a side-effect. They returns the 100 most frequent
// User-Agent strings and IP addresses (see [Source]), respectively, observed by
// Handlers wrapped with NewHandler. /debug/heavyhitter/useragents-bytes and
// /debug/heavyhitter/ips-bytes return the 100 that were served the most
// response body bytes instead.
package heavyhitter

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"

	"filippo.io/sunlight/internal/frequent"
)

var userAgents, ipAddresses = frequent.New(200), frequent.New(200)
var userAgentBytes, ipAddressBytes = frequent.New(200), frequent.New(200)

func NewHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.UserAgent()
		source := Source(r)
		userAgents.Count(userAgent, source)
		ipAddresses.Count(source, userAgent)
		cw := &countingWriter{ResponseWriter: w}
		var rw http.ResponseWriter = cw
		if _, ok := w.(io.ReaderFrom); ok {
			// Only claim to implement io.ReaderFrom if the underlying
			// ResponseWriter does, so the file server can keep using sendfile.
			rw = readerFromCountingWriter{cw}
		}
		next.ServeHTTP(rw, r)
		userAgentBytes.Add(userAgent, source, cw.written)
		ipAddressBytes.Add(source, userAgent, cw.written)
	})
}

// Source returns the client IP address of r. IPv6 addresses are truncated to
// their /64, since a single client can use many addresses within it.
func Source(r *http.Request) string {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		return host
	}
	addr := ap.Addr().Unmap()
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked().String()
	}
	return addr.String()
}

// countingWriter counts the response body bytes written through it.
type countingWriter struct {
	http.ResponseWriter
	written int
}

type readerFromCountingWriter struct {
	*countingWriter
}

func (w readerFromCountingWriter) ReadFrom(r io.Reader) (int64, error) {
	n, err := w.ResponseWriter.(io.ReaderFrom).ReadFrom(r)
	w.written += int(n)
	return n, err
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.written += n
	return n, err
}

func (w *countingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *countingWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func init() {
	handler := func(table *frequent.Table, format string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			for _, item := range table.Top(100) {
				halfError := item.MaxError / 2
				fmt.Fprintf(w, format, item.Count-halfError, halfError, item.Value, item.Latest)
			}
		}
	}
	http.HandleFunc("/debug/heavyhitter/useragents", handler(userAgents, "%d (± %d)\t%q [%s]\n"))
	http.HandleFunc("/debug/heavyhitter/useragents-bytes", handler(userAgentBytes, "%d (± %d)\t%q [%s]\n"))
	http.HandleFunc("/debug/heavyhitter/ips", handler(ipAddresses, "%d (± %d)\t%s [%q]\n"))
	http.HandleFunc("/debug/heavyhitter/ips-bytes", handler(ipAddressBytes, "%d (± %d)\t%s [%q]\n"))
}
