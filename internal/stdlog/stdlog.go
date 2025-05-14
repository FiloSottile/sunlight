// Package heavyhitter registers two endpoints, /debug/logs/on and
// /debug/logs/off, as a side-effect. When /debug/logs/on is called, the log
// level of Handler is set to debug. When /debug/logs/off is called, the log
// level of Handler is set to info.
package stdlog

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

var logLevel = new(slog.LevelVar)

// Handler is a multi-handler that writes human-readable logs to
// stdout and machine-readable logs to stderr.
var Handler = multiHandler([]slog.Handler{
	slog.Handler(slog.NewJSONHandler(os.Stdout,
		&slog.HandlerOptions{AddSource: true, Level: logLevel})),
	slog.Handler(slog.NewTextHandler(os.Stderr,
		&slog.HandlerOptions{Level: logLevel})),
})

// HTTPErrorLog is a [log.Logger] to be used as a [http.Server.ErrorLog]. It
// logs at the WARN level, filtering out common background noise unless debug
// logging is enabled.
var HTTPErrorLog = slog.NewLogLogger(newFilterHandler(
	Handler.WithAttrs(
		[]slog.Attr{slog.String("via", "http.Server.ErrorLog")},
	),
	func(r slog.Record) bool {
		// Unless debug logging is enabled, hide Internet background radiation.
		if Handler.Enabled(context.Background(), slog.LevelDebug) {
			return true
		}
		if strings.HasPrefix(r.Message, "http: TLS handshake error") {
			// Only log TLS handshake errors from autocert, filtering out
			// background noise ones.
			return strings.Contains(r.Message, "acme/autocert") &&
				!strings.HasSuffix(r.Message, "missing server name") &&
				!strings.HasSuffix(r.Message, "not configured in HostWhitelist") &&
				!strings.HasSuffix(r.Message, "server name contains invalid character") &&
				!strings.HasSuffix(r.Message, "server name component count invalid")
		}
		if strings.HasPrefix(r.Message, "http2: server: error reading preface from client") {
			return !strings.HasSuffix(r.Message, "read: connection reset by peer")
		}
		return true
	},
), slog.LevelWarn)

func init() {
	http.HandleFunc("/debug/logs/on", func(w http.ResponseWriter, r *http.Request) {
		logLevel.Set(slog.LevelDebug)
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/debug/logs/off", func(w http.ResponseWriter, r *http.Request) {
		logLevel.Set(slog.LevelInfo)
		w.WriteHeader(http.StatusOK)
	})
	if os.Getenv("DEBUG") != "" {
		logLevel.Set(slog.LevelDebug)
	}
}
