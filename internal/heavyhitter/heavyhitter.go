// Package heavyhitter registers two endpoints /debug/heavyhitter/useragents and
// /debug/heavyhitter/ips as a side-effect. They returns the 100 most frequent
// User-Agent strings and IP addresses, respectively, observed by Handlers
// wrapped with NewHandler.
package heavyhitter

import (
	"fmt"
	"net"
	"net/http"

	"filippo.io/sunlight/internal/frequent"
)

var userAgents, ipAddresses = frequent.New(200), frequent.New(200)

func NewHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.UserAgent()
		source, _, _ := net.SplitHostPort(r.RemoteAddr)
		userAgents.Count(userAgent, source)
		ipAddresses.Count(source, userAgent)
		next.ServeHTTP(w, r)
	})
}

func init() {
	http.HandleFunc("/debug/heavyhitter/useragents", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		for _, item := range userAgents.Top(100) {
			halfError := item.MaxError / 2
			fmt.Fprintf(w, "%d (± %d)\t%q [%s]\n", item.Count-halfError, halfError, item.Value, item.Latest)
		}
	})
	http.HandleFunc("/debug/heavyhitter/ips", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		for _, item := range ipAddresses.Top(100) {
			halfError := item.MaxError / 2
			fmt.Fprintf(w, "%d (± %d)\t%s [%q]\n", item.Count-halfError, halfError, item.Value, item.Latest)
		}
	})
}
