// Command skylight runs a Certificate Transparency log and
// c2sp.org/tlog-witness / c2sp.org/tlog-mirror read-path server.
//
// A YAML config file is required (specified with -c, by default skylight.yaml),
// the keys are documented in the [Config] type.
//
// If the command line flag -testcert is passed, ACME will be disabled and the
// certificate will be loaded from skylight.pem and skylight-key.pem.
//
// Requests from clients that don't specify an email address in their User-Agent
// will be globally rate-limited to 75 requests per second.
//
// Metrics are exposed publicly at /metrics, and logs are written to stderr in
// human-readable format, and to stdout in JSON format. /health reports the
// health of all logs, returning 500 if any non-staging log is stale; it also
// verifies the served checkpoints of any witness with a Key configured, and the
// mirror checkpoints and right-edge tiles of any witness with a MirrorKey.
//
// A private HTTP debug server is also started on a random port on localhost. It
// serves the net/http/pprof endpoints, the [heavyhitter] endpoints, the
// [keylog] endpoints, and the [stdlog] endpoints.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/heavyhitter"
	"filippo.io/sunlight/internal/keylog"
	"filippo.io/sunlight/internal/reused"
	"filippo.io/sunlight/internal/stdlog"
	"filippo.io/sunlight/internal/witness"
	"filippo.io/torchwood"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

type Config struct {
	// Listen are the addresses to listen on, e.g. ":443".
	Listen []string

	// ACME configures how Skylight automatically obtains certificates for its HTTPS
	// endpoints. Optional. If missing, Skylight will listen for plain HTTP or h2c.
	ACME struct {
		// Cache is the path to the directory where keys and certificates will
		// be stored. It will be created if it doesn't already exist.
		Cache string

		// Hosts are extra names for which Skylight will obtain a certificate,
		// beyond those configured as part of the MonitoringPrefix of logs and
		// witnesses. Optional.
		Hosts []string

		// Directory is an ACME directory URL to request a certificate from.
		// Defaults to Let's Encrypt Production. Optional.
		Directory string
	}

	// HomeRedirect is the 302 destination of the root. Optional.
	HomeRedirect string

	// LogsJSONPrefix is the full URL prefix of the /logs.json endpoint.
	// Optional. If empty, /logs.json will be served at the root of all hosts.
	// If ACME is enabled, Skylight will obtain a certificate for the host of
	// this URL.
	LogsJSONPrefix string

	// OperatorName is the human-readable name of the CT log operator,
	// served at /logs.json per the operator-list-v1 schema. Optional.
	OperatorName string

	Witnesses []WitnessConfig

	Logs []LogConfig
}

type WitnessConfig struct {
	// MonitoringPrefix is the full URL of the c2sp.org/tlog-witness monitoring
	// prefix of the witness.
	//
	// The HTTP server will serve the witness at this URL, and if ACME is
	// enabled, Skylight will obtain a certificate for the host of this URL.
	//
	// If the witness operates as a mirror, the c2sp.org/tlog-mirror monitoring
	// prefix will be "{MonitoringPrefix}/mirror/".
	MonitoringPrefix string

	// LocalDirectory is the path to a local directory where the witness stores
	// its data. If the witness operates as a mirror, must contain a "mirror"
	// subdirectory.
	LocalDirectory string

	// Key is the c2sp.org/signed-note vkey of the witness cosigner. If set,
	// /health verifies the served witness checkpoints. Required if MirrorKey is
	// set.
	Key string

	// MirrorKey is the c2sp.org/signed-note vkey of the mirror cosigner. If set,
	// /health verifies the served mirror checkpoints and tiles of every log
	// found under the "mirror" subdirectory of LocalDirectory, and that each is
	// behind the corresponding witness checkpoint.
	MirrorKey string

	// Staging indicates that this witness should not make /health fail.
	Staging bool
}

type LogConfig struct {
	// ShortName is the short name for the log, used as a metrics and logs label.
	ShortName string

	// MonitoringPrefix is the full URL of the c2sp.org/static-ct-api monitoring
	// prefix of the log.
	//
	// The HTTP server will serve the log at this URL, and if ACME is enabled,
	// Skylight will obtain a certificate for the host of this URL.
	MonitoringPrefix string

	// LocalDirectory is the path to a local directory where the log will store
	// its data. It must be dedicated to this specific log instance.
	LocalDirectory string

	// Staging indicates that this log should not make /health fail.
	Staging bool
}

// TAT is the Theoretical Arrival Time of a Generic Cell Rate Algorithm (GCRA)
// rate limit. See https://letsencrypt.org/2025/01/30/scaling-rate-limits/.
type TAT struct {
	sync.Mutex
	time.Time
}

// Allow returns whether the request is allowed. If it is allowed, it updates
// the TAT. Otherwise, it returns the time at which the request can be retried.
func (t *TAT) Allow(interval time.Duration, burst int) (allow bool, retryAfter time.Time) {
	now := time.Now()
	t.Lock()
	defer t.Unlock()
	tat := t.Time
	if tat.Before(now) {
		t.Time = now.Add(interval)
		return true, time.Time{}
	}
	nowPlusBurst := now.Add(interval * time.Duration(burst))
	if tat.Before(nowPlusBurst) {
		t.Time = tat.Add(interval)
		return true, time.Time{}
	}
	return false, now.Add(tat.Sub(nowPlusBurst))
}

// rateLimitInterval allows 75 req/s, which at the average size of a full data
// tile works out to about 100Mbps.
const rateLimitInterval = 1 * time.Second / 75
const rateLimitBurst = 10

// anonymousClientLimit is the rate-limit for alicents that don't specify an
// email address in their User-Agent.
var anonymousClientLimit TAT

func newRateLimitHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if clientFromContext(r.Context()) == "anonymous" {
			msg := "Please add an email address to your User-Agent."
			r.Header.Add("Skylight-Rate-Limited", msg)
			allow, retryAfter := anonymousClientLimit.Allow(rateLimitInterval, rateLimitBurst)
			if !allow {
				w.Header().Set("Retry-After", retryAfter.Format(time.RFC1123))
				// The content headers set optimistically before dispatch don't
				// apply to the error body. The file server drops them from its
				// own error responses (see serveError in net/http/fs.go), but
				// http.Error doesn't, so drop them here.
				w.Header().Del("Content-Encoding")
				w.Header().Del("Cache-Control")
				http.Error(w, msg, http.StatusTooManyRequests)
				return
			}
		}
		handler.ServeHTTP(w, r)
	})
}

type kindContextKey struct{}

func kindFromContext(ctx context.Context) string {
	k, _ := ctx.Value(kindContextKey{}).(string)
	return k
}

type originContextKey struct{}

func originFromContext(ctx context.Context) string {
	k, _ := ctx.Value(originContextKey{}).(string)
	return k
}

type clientContextKey struct{}

func clientFromContext(ctx context.Context) string {
	c, _ := ctx.Value(clientContextKey{}).(string)
	return c
}

type rateLimitedHandlerContextKey struct{}

func rateLimitedHandlerFromContext(ctx context.Context) http.Handler {
	h, _ := ctx.Value(rateLimitedHandlerContextKey{}).(http.Handler)
	return h
}

type unlimitedHandlerContextKey struct{}

func unlimitedHandlerFromContext(ctx context.Context) http.Handler {
	h, _ := ctx.Value(unlimitedHandlerContextKey{}).(http.Handler)
	return h
}

// filePrefixContextKey carries the on-disk path prefix ("/{origin}" or
// "/mirror/{origin}") that the witness file handler puts back in front of the
// request path after it was stripped for logMux routing.
type filePrefixContextKey struct{}

func filePrefixFromContext(ctx context.Context) string {
	p, _ := ctx.Value(filePrefixContextKey{}).(string)
	return p
}

func newClientContextHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If you are reading this to figure out how to bypass the rate limit,
		// we know it's easy, but please don't. We also know how to make your
		// life harder by blocking your ASN or fingerprinting your client.
		//
		// There's no need to bypass anything!
		//
		// We don't need to know who you are, we only want to be able to contact
		// you if necessary: you can just register a throwaway email address,
		// forward it to your email, and put that in your User-Agent.
		//
		// Thank you!
		if userAgent := r.UserAgent(); strings.Contains(userAgent, "example.com") {
			r = r.WithContext(context.WithValue(r.Context(), clientContextKey{}, "anonymous"))
		} else if strings.Contains(userAgent, "@") {
			r = r.WithContext(context.WithValue(r.Context(), clientContextKey{}, "with-email"))
		} else if strings.Contains(userAgent, "https://") {
			r = r.WithContext(context.WithValue(r.Context(), clientContextKey{}, "with-url"))
		} else if strings.Contains(userAgent, "github.com/") {
			r = r.WithContext(context.WithValue(r.Context(), clientContextKey{}, "with-github"))
		} else {
			r = r.WithContext(context.WithValue(r.Context(), clientContextKey{}, "anonymous"))
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	fs := flag.NewFlagSet("skylight", flag.ExitOnError)
	configFlag := fs.String("c", "skylight.yaml", "path to the config file")
	testCertFlag := fs.Bool("testcert", false, "use skylight.pem and skylight-key.pem instead of ACME")
	fs.Parse(os.Args[1:])

	logger := slog.New(stdlog.Handler)

	yml, err := os.ReadFile(*configFlag)
	if err != nil {
		fatalError(logger, "failed to read config file", "err", err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(yml, c); err != nil {
		fatalError(logger, "failed to parse config file", "err", err)
	}

	go func() {
		ln, err := net.Listen("tcp", "localhost:")
		if err != nil {
			logger.Error("failed to start debug server", "err", err)
		} else {
			logger.Info("debug server listening", "addr", ln.Addr())
			err := http.Serve(ln, nil)
			logger.Error("debug server exited", "err", err)
		}
	}()

	mux := http.NewServeMux()

	metrics := prometheus.NewRegistry()
	metrics.MustRegister(collectors.NewGoCollector())
	metrics.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	mux.Handle("/metrics", promhttp.InstrumentMetricHandler(metrics,
		promhttp.HandlerFor(metrics, promhttp.HandlerOpts{
			ErrorLog: slog.NewLogLogger(stdlog.Handler.WithAttrs(
				[]slog.Attr{slog.String("source", "metrics")},
			), slog.LevelWarn),
			Registry: metrics,
		})))
	reqInFlight := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "http_in_flight_requests",
			Help: "Requests currently being served.",
		},
	)
	reqCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "HTTP requests served.",
		},
		[]string{"log", "kind", "client", "reused", "code"},
	)
	reqDuration := prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "http_request_duration_seconds",
			Help:       "HTTP request serving latencies in seconds, at the file handler.",
			Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
			MaxAge:     1 * time.Minute,
			AgeBuckets: 6,
		},
		[]string{"log", "kind"},
	)
	resSize := prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "http_response_size_bytes",
			Help:       "HTTP response sizes in bytes for file, at the file handler.",
			Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
			MaxAge:     1 * time.Minute,
			AgeBuckets: 6,
		},
		[]string{"log", "kind"},
	)
	skylightMetrics := prometheus.WrapRegistererWithPrefix("skylight_", metrics)
	skylightMetrics.MustRegister(reqInFlight, reqCount, reqDuration, resSize)

	buildInfo, _ := debug.ReadBuildInfo()
	buildVersion := buildInfo.Main.Version
	buildCommit := ""
	for _, s := range buildInfo.Settings {
		if s.Key == "vcs.revision" {
			buildCommit = s.Value
			break
		}
	}
	buildInfoGauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "build_info",
			Help: "Build information about the running sunlight binary.",
		},
		[]string{"version", "commit"},
	)
	buildInfoGauge.WithLabelValues(buildVersion, buildCommit).Set(1)
	skylightMetrics.MustRegister(buildInfoGauge)

	homeRedirect := http.RedirectHandler(c.HomeRedirect, http.StatusFound)
	homeRedirect = promhttp.InstrumentHandlerCounter(reqCount.MustCurryWith(
		prometheus.Labels{"log": "", "kind": "index"}), homeRedirect,
		promhttp.WithLabelFromCtx("reused", reused.LabelFromContext),
		promhttp.WithLabelFromCtx("client", clientFromContext))
	if c.HomeRedirect != "" {
		mux.Handle("/{$}", homeRedirect)
	}

	// logMux is a Handler that serves a tlog-tiles log at root, using the
	// rate-limited and unlimited handlers in the request Context, specializing
	// the request, setting headers and context keys.
	logMux := http.NewServeMux()
	if c.HomeRedirect != "" {
		logMux.Handle("/{$}", homeRedirect)
	}
	logMux.HandleFunc("GET /checkpoint", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		r = r.WithContext(context.WithValue(r.Context(), kindContextKey{}, "checkpoint"))
		unlimitedHandlerFromContext(r.Context()).ServeHTTP(w, r)
	})
	logMux.HandleFunc("GET /log.v3.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		r = r.WithContext(context.WithValue(r.Context(), kindContextKey{}, "log.v3.json"))
		unlimitedHandlerFromContext(r.Context()).ServeHTTP(w, r)
	})
	logMux.HandleFunc("GET /issuer/{issuer}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
		r = r.WithContext(context.WithValue(r.Context(), kindContextKey{}, "issuer"))
		rateLimitedHandlerFromContext(r.Context()).ServeHTTP(w, r)
	})
	logMux.HandleFunc("GET /tile/{tile...}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
		tilePath := "tile/" + r.PathValue("tile")
		tile, err := sunlight.ParseTilePath(tilePath)
		if err != nil {
			tile, err = torchwood.ParseTilePath(tilePath)
		}
		_ = err // an invalid tile will take the default case below
		switch tile.L {
		case -1:
			w.Header().Set("Content-Encoding", "gzip")
			if tile.W < sunlight.TileWidth {
				r = r.WithContext(context.WithValue(r.Context(), kindContextKey{}, "partial"))
			} else {
				r = r.WithContext(context.WithValue(r.Context(), kindContextKey{}, "data"))
			}
		case -2:
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Type", "application/jsonl; charset=utf-8")
			r = r.WithContext(context.WithValue(r.Context(), kindContextKey{}, "names"))
		default:
			r = r.WithContext(context.WithValue(r.Context(), kindContextKey{}, "tile"))
		}
		rateLimitedHandlerFromContext(r.Context()).ServeHTTP(w, r)
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var acmeHosts []string
	roots := make(map[LogConfig]*os.Root)
	for _, lc := range c.Logs {
		if lc.ShortName == "" {
			fatalError(logger, "missing short name for log")
		}
		logger := slog.New(stdlog.Handler.WithAttrs([]slog.Attr{
			slog.String("log", lc.ShortName),
		}))

		prefix, err := parsePrefix(lc.MonitoringPrefix)
		if err != nil {
			fatalError(logger, "invalid MonitoringPrefix", "err", err)
		}

		acmeHosts = append(acmeHosts, prefix.Hostname())

		root, err := os.OpenRoot(lc.LocalDirectory)
		if err != nil {
			fatalError(logger, "failed to open local directory", "err", err)
		}
		roots[lc] = root
		handler := http.FileServerFS(filesOnlyFS{root.FS()})

		// Wrap the file handler with duration and response size metrics.
		// Avoid tracking the size and duration of errors or simple responses.
		labels := prometheus.Labels{"log": lc.ShortName}
		handler = promhttp.InstrumentHandlerDuration(reqDuration.MustCurryWith(labels), handler,
			promhttp.WithLabelFromCtx("kind", kindFromContext))
		handler = promhttp.InstrumentHandlerResponseSize(resSize.MustCurryWith(labels), handler,
			promhttp.WithLabelFromCtx("kind", kindFromContext))

		// Then, apply the rate limit handler. Keep an unrestricted handler for
		// small browser-friendly endpoints like checkpoint and JSON metadata.
		rateLimitedHandler := newRateLimitHandler(handler)
		unlimitedHandler := handler

		// Next, the request counter. It needs to go before the mux as it uses
		// the context keys we set in the per-path handlers, but after the rate
		// limit handler, so it will capture the 429 errors.
		unlimitedHandler = promhttp.InstrumentHandlerCounter(reqCount.MustCurryWith(labels), unlimitedHandler,
			promhttp.WithLabelFromCtx("kind", kindFromContext),
			promhttp.WithLabelFromCtx("reused", reused.LabelFromContext),
			promhttp.WithLabelFromCtx("client", clientFromContext))
		rateLimitedHandler = promhttp.InstrumentHandlerCounter(reqCount.MustCurryWith(labels), rateLimitedHandler,
			promhttp.WithLabelFromCtx("kind", kindFromContext),
			promhttp.WithLabelFromCtx("reused", reused.LabelFromContext),
			promhttp.WithLabelFromCtx("client", clientFromContext))

		patternPrefix := "GET " + prefix.Host + prefix.Path
		logMux := http.StripPrefix(prefix.Path, logMux)
		mux.HandleFunc(patternPrefix+"/", func(w http.ResponseWriter, r *http.Request) {
			r = r.WithContext(context.WithValue(r.Context(), rateLimitedHandlerContextKey{}, rateLimitedHandler))
			r = r.WithContext(context.WithValue(r.Context(), unlimitedHandlerContextKey{}, unlimitedHandler))
			logMux.ServeHTTP(w, r)
		})
	}

	var witnessChecks []witnessHealth
	for _, wc := range c.Witnesses {
		logger := slog.New(stdlog.Handler.WithAttrs([]slog.Attr{
			slog.String("witness", wc.MonitoringPrefix),
		}))

		prefix, err := parsePrefix(wc.MonitoringPrefix)
		if err != nil {
			fatalError(logger, "invalid witness MonitoringPrefix", "err", err)
		}

		acmeHosts = append(acmeHosts, prefix.Hostname())

		root, err := os.OpenRoot(wc.LocalDirectory)
		if err != nil {
			fatalError(logger, "failed to open witness directory", "err", err)
		}
		handler := http.FileServerFS(filesOnlyFS{root.FS()})

		handler = func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p := filePrefixFromContext(r.Context()) + r.URL.Path

				r2 := new(http.Request)
				*r2 = *r
				r2.URL = new(url.URL)
				*r2.URL = *r.URL
				r2.URL.Path = p
				r2.URL.RawPath = ""

				h.ServeHTTP(w, r2)
			})
		}(handler)

		handler = promhttp.InstrumentHandlerDuration(reqDuration, handler,
			promhttp.WithLabelFromCtx("log", originFromContext),
			promhttp.WithLabelFromCtx("kind", kindFromContext))
		handler = promhttp.InstrumentHandlerResponseSize(resSize, handler,
			promhttp.WithLabelFromCtx("log", originFromContext),
			promhttp.WithLabelFromCtx("kind", kindFromContext))

		unlimitedHandler := promhttp.InstrumentHandlerCounter(reqCount, handler,
			promhttp.WithLabelFromCtx("log", originFromContext),
			promhttp.WithLabelFromCtx("kind", kindFromContext),
			promhttp.WithLabelFromCtx("reused", reused.LabelFromContext),
			promhttp.WithLabelFromCtx("client", clientFromContext))
		rateLimitedHandler := promhttp.InstrumentHandlerCounter(reqCount, newRateLimitHandler(handler),
			promhttp.WithLabelFromCtx("log", originFromContext),
			promhttp.WithLabelFromCtx("kind", kindFromContext),
			promhttp.WithLabelFromCtx("reused", reused.LabelFromContext),
			promhttp.WithLabelFromCtx("client", clientFromContext))

		// Cap the cardinality of the origin metric label by only recording ones
		// that exist on the filesystem.
		cappedOrigin := func(origin, prefix string) string {
			if _, err := root.Stat(prefix + origin + "/checkpoint"); err != nil {
				return ""
			}
			return origin
		}

		patternPrefix := "GET " + prefix.Host + prefix.Path
		mux.HandleFunc(patternPrefix+"/{origin}/", func(w http.ResponseWriter, r *http.Request) {
			origin := r.PathValue("origin")
			r = r.WithContext(context.WithValue(r.Context(), originContextKey{}, cappedOrigin(origin, "")))
			r = r.WithContext(context.WithValue(r.Context(), filePrefixContextKey{}, "/"+origin))
			r = r.WithContext(context.WithValue(r.Context(), rateLimitedHandlerContextKey{}, rateLimitedHandler))
			r = r.WithContext(context.WithValue(r.Context(), unlimitedHandlerContextKey{}, unlimitedHandler))
			// We need to strip the origin from the path because logMux anchors
			// at root. It will be put back before the FileServer Handler.
			http.StripPrefix(prefix.Path+"/"+origin, logMux).ServeHTTP(w, r)
		})
		mux.HandleFunc(patternPrefix+"/mirror/{origin}/", func(w http.ResponseWriter, r *http.Request) {
			origin := r.PathValue("origin")
			r = r.WithContext(context.WithValue(r.Context(), originContextKey{}, cappedOrigin(origin, "mirror/")))
			r = r.WithContext(context.WithValue(r.Context(), filePrefixContextKey{}, "/mirror/"+origin))
			r = r.WithContext(context.WithValue(r.Context(), rateLimitedHandlerContextKey{}, rateLimitedHandler))
			r = r.WithContext(context.WithValue(r.Context(), unlimitedHandlerContextKey{}, unlimitedHandler))
			http.StripPrefix(prefix.Path+"/mirror/"+origin, logMux).ServeHTTP(w, r)
		})

		if wc.Key != "" {
			witnessVerifier, err := parseVerifier(wc.Key)
			if err != nil {
				fatalError(logger, "invalid witness Key", "err", err)
			}
			witnessChecks = append(witnessChecks, witnessHealth{
				root:     root,
				verifier: note.VerifierList(witnessVerifier),
				staging:  wc.Staging,
			})
			if wc.MirrorKey != "" {
				mirrorVerifier, err := parseVerifier(wc.MirrorKey)
				if err != nil {
					fatalError(logger, "invalid witness MirrorKey", "err", err)
				}
				mirrorRoot, err := root.OpenRoot("mirror")
				if err != nil {
					fatalError(logger, "failed to open witness mirror directory", "err", err)
				}
				witnessChecks = append(witnessChecks, witnessHealth{
					root:            mirrorRoot,
					verifier:        note.VerifierList(mirrorVerifier),
					pendingRoot:     root,
					mirror:          true,
					witnessVerifier: note.VerifierList(witnessVerifier),
					staging:         wc.Staging,
				})
			}
		}
		if wc.MirrorKey != "" && wc.Key == "" {
			fatalError(logger, "witness with MirrorKey must also set Key")
		}
	}

	var logsJSONPrefix string
	if c.LogsJSONPrefix != "" {
		logsJSONPrefix = strings.TrimSuffix(c.LogsJSONPrefix, "/")
		prefix, err := parsePrefix(logsJSONPrefix)
		if err != nil {
			fatalError(logger, "invalid LogsJSONPrefix", "err", err)
		}
		logsJSONPrefix = prefix.Host + prefix.Path
		acmeHosts = append(acmeHosts, prefix.Hostname())
	}
	mux.HandleFunc("GET "+logsJSONPrefix+"/logs.json", func(w http.ResponseWriter, r *http.Request) {
		reused := reused.LabelFromContext(r.Context())
		client := clientFromContext(r.Context())
		reqCount.WithLabelValues("", "logs.json", client, reused, "200").Inc()

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")

		var logs []string
		for log := range roots {
			prefix := strings.TrimSuffix(log.MonitoringPrefix, "/")
			logs = append(logs, prefix+"/log.v3.json")
		}
		slices.Sort(logs)
		json.NewEncoder(w).Encode(struct {
			OperatorName string   `json:"operator_name,omitempty"`
			Logs         []string `json:"logs"`
		}{
			OperatorName: c.OperatorName,
			Logs:         logs,
		})
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK
		buf := &bytes.Buffer{}
		for log, root := range roots {
			if err := checkLog(root); err != nil {
				if errors.Is(err, errLogSunset) {
					fmt.Fprintf(buf, "%s: read-only\n", log.ShortName)
				} else if log.Staging {
					fmt.Fprintf(buf, "%s: %v (ignored)\n", log.ShortName, err)
				} else {
					status = http.StatusInternalServerError
					fmt.Fprintf(buf, "%s: %v\n", log.ShortName, err)
				}
			} else {
				fmt.Fprintf(buf, "%s: OK\n", log.ShortName)
			}
		}

		for _, wh := range witnessChecks {
			kind := "witness"
			if wh.mirror {
				kind = "mirror"
			}
			hashes, err := wh.hashes()
			if err != nil {
				if wh.staging {
					fmt.Fprintf(buf, "%s: %v (ignored)\n", kind, err)
				} else {
					status = http.StatusInternalServerError
					fmt.Fprintf(buf, "%s: %v\n", kind, err)
				}
				continue
			}
			for _, hash := range hashes {
				origin, err := wh.check(r.Context(), hash)
				// Label with the verified origin, falling back to the directory
				// name if we couldn't get that far.
				label := kind + " " + hash
				if origin != "" {
					label = kind + " " + origin
				}
				if err != nil {
					if wh.staging {
						fmt.Fprintf(buf, "%s: %v (ignored)\n", label, err)
					} else {
						status = http.StatusInternalServerError
						fmt.Fprintf(buf, "%s: %v\n", label, err)
					}
				} else {
					fmt.Fprintf(buf, "%s: OK\n", label)
				}
			}
		}

		reused := reused.LabelFromContext(r.Context())
		client := clientFromContext(r.Context())
		reqCount.WithLabelValues("", "health", client, reused, strconv.Itoa(status)).Inc()

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(status)
		io.Copy(w, buf)
	})

	handler := promhttp.InstrumentHandlerInFlight(reqInFlight, mux)
	handler = heavyhitter.NewHandler(handler)
	handler = newClientContextHandler(handler)
	handler = reused.NewHandler(handler)
	s := &http.Server{
		Handler:      handler,
		ConnContext:  reused.ConnContext,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
		ErrorLog:     stdlog.HTTPErrorLog,
	}
	if *testCertFlag {
		cert, err := tls.LoadX509KeyPair("skylight.pem", "skylight-key.pem")
		if err != nil {
			fatalError(logger, "failed to load test cert", "err", err)
		}
		s.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	} else if c.ACME.Cache != "" {
		acmeHosts = append(acmeHosts, c.ACME.Hosts...)
		m := &autocert.Manager{
			Cache:      autocert.DirCache(c.ACME.Cache),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(acmeHosts...),
			Client: &acme.Client{
				DirectoryURL: c.ACME.Directory,
				UserAgent:    "filippo.io/sunlight",
			},
		}
		s.TLSConfig = m.TLSConfig()
	} else {
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		s.Protocols = protocols
	}

	if s.TLSConfig != nil {
		s.TLSConfig.KeyLogWriter = keylog.Writer
	}

	if len(c.Listen) == 0 {
		fatalError(logger, "no Listen addresses specified in config")
	}
	serveGroup, ctx := errgroup.WithContext(ctx)
	for _, addr := range c.Listen {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			fatalError(logger, "failed to listen", "addr", addr, "err", err)
		}
		serveGroup.Go(func() error {
			if s.TLSConfig != nil {
				return s.ServeTLS(l, "", "")
			}
			return s.Serve(l)
		})
	}
	<-ctx.Done()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		logger.Error("Shutdown error", "err", err)
	}

	if err := serveGroup.Wait(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("serve error", "err", err)
	}

	os.Exit(1)
}

// filesOnlyFS hides directories, so [http.FileServerFS] serves 404s instead
// of directory listings (and of redirects to them). Directories are not part
// of the tlog-tiles API surface.
type filesOnlyFS struct {
	fsys fs.FS
}

func (f filesOnlyFS) Open(name string) (fs.File, error) {
	file, err := f.fsys.Open(name)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if info.IsDir() {
		file.Close()
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return file, nil
}

func parsePrefix(prefix string) (*url.URL, error) {
	prefix = strings.TrimSuffix(prefix, "/")
	p, err := url.Parse(prefix)
	if err != nil {
		return nil, err
	}
	if p.Scheme != "https" {
		return nil, fmt.Errorf("must use https scheme: %s", prefix)
	}
	if p.Host == "" {
		return nil, fmt.Errorf("must have a host: %s", prefix)
	}
	return p, nil
}

type logInfo struct {
	Name         string `json:"description"`
	PublicKeyDER []byte `json:"key"`
	Interval     struct {
		NotAfterLimit string `json:"end_exclusive"`
	} `json:"temporal_interval"`
	FinalTree struct {
		RootHash  []byte `json:"sha256_root_hash"`
		Size      int64  `json:"tree_size"`
		Timestamp int64  `json:"timestamp"`
	} `json:"final_tree_head,omitzero"`
}

var errLogSunset = errors.New("log is read-only")

func checkLog(root *os.Root) error {
	logJSON, err := fs.ReadFile(root.FS(), "log.v3.json")
	if err != nil {
		return fmt.Errorf("failed to read log.v3.json: %w", err)
	}
	var log logInfo
	if err := json.Unmarshal(logJSON, &log); err != nil {
		return fmt.Errorf("failed to parse log.v3.json: %w", err)
	}
	key, err := x509.ParsePKIXPublicKey(log.PublicKeyDER)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	verifier, err := sunlight.NewRFC6962Verifier(log.Name, key)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}
	signedCheckpoint, err := fs.ReadFile(root.FS(), "checkpoint")
	if err != nil {
		return fmt.Errorf("failed to read checkpoint: %w", err)
	}
	n, err := note.Open(signedCheckpoint, note.VerifierList(verifier))
	if err != nil {
		return fmt.Errorf("failed to verify checkpoint note: %w", err)
	}
	checkpoint, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return fmt.Errorf("failed to parse checkpoint: %w", err)
	}
	if checkpoint.Origin != log.Name {
		return fmt.Errorf("origin mismatch: %q != %q", checkpoint.Origin, log.Name)
	}
	t, err := sunlight.RFC6962SignatureTimestamp(n.Sigs[0])
	if err != nil {
		return fmt.Errorf("failed to parse signature timestamp: %w", err)
	}
	notAfterLimit, err := time.Parse(time.RFC3339, log.Interval.NotAfterLimit)
	if err != nil {
		return fmt.Errorf("failed to parse NotAfterLimit: %w", err)
	}
	if time.Since(notAfterLimit) > 7*24*time.Hour+3*time.Second {
		if log.FinalTree.RootHash == nil {
			return fmt.Errorf("log is past NotAfterLimit + 1 week and has no final tree")
		}
		if !bytes.Equal(log.FinalTree.RootHash, checkpoint.Hash[:]) {
			return fmt.Errorf("mismatching final tree hash")
		}
		if log.FinalTree.Size != checkpoint.N {
			return fmt.Errorf("mismatching final tree size")
		}
		if log.FinalTree.Timestamp != t {
			return fmt.Errorf("mismatching final tree timestamp")
		}
		// The log is read-only, so the checkpoint can be old.
		return errLogSunset
	}
	if ct := time.UnixMilli(t); time.Since(ct) > 5*time.Second {
		return fmt.Errorf("checkpoint is too old: %v", ct)
	}
	return nil
}

type witnessHealth struct {
	root     *os.Root
	verifier note.Verifiers
	staging  bool

	// mirror, pendingRoot and witnessVerifier are only set for a mirror.
	mirror          bool
	pendingRoot     *os.Root
	witnessVerifier note.Verifiers
}

// hashes returns the origin-hash subdirectories of the witness directory, each
// identifying a log. Non-hash entries (such as the "mirror" subdirectory of a
// mirror witness) are skipped.
func (wh witnessHealth) hashes() ([]string, error) {
	entries, err := fs.ReadDir(wh.root.FS(), ".")
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate logs: %w", err)
	}
	var hashes []string
	for _, e := range entries {
		if e.IsDir() && isOriginHash(e.Name()) {
			hashes = append(hashes, e.Name())
		}
	}
	return hashes, nil
}

// check verifies the checkpoint served for the log whose origin hashes to hash,
// and for a mirror also the presence and validity of the right-edge tiles. It
// returns the origin once verified, so the caller can label a later failure.
func (wh witnessHealth) check(ctx context.Context, hash string) (string, error) {
	signedCheckpoint, err := fs.ReadFile(wh.root.FS(), hash+"/checkpoint")
	if err != nil {
		return "", fmt.Errorf("failed to read checkpoint: %w", err)
	}
	n, err := note.Open(signedCheckpoint, wh.verifier)
	if err != nil {
		return "", fmt.Errorf("failed to verify checkpoint: %w", err)
	}
	checkpoint, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return "", fmt.Errorf("failed to parse checkpoint: %w", err)
	}
	origin := checkpoint.Origin
	if h := witness.OriginHash(origin); h != hash {
		return origin, fmt.Errorf("origin %q hashes to %s, not %s", origin, h, hash)
	}
	if !wh.mirror {
		return origin, nil
	}

	// Read the right-edge hashes of the mirror tree through a verifying tile
	// reader, which loads them from the served tiles and checks them against the
	// signed checkpoint. This confirms the right-edge tiles exist and are valid.
	sub, err := fs.Sub(wh.root.FS(), hash)
	if err != nil {
		return origin, err
	}
	tr, err := torchwood.NewTileFS(sub)
	if err != nil {
		return origin, err
	}
	hr := torchwood.TileHashReaderWithContext(ctx, checkpoint.Tree, tr)
	if edge := torchwood.RightEdge(checkpoint.N); len(edge) > 0 {
		if _, err := hr.ReadHashes(edge); err != nil {
			return origin, fmt.Errorf("failed to verify right-edge tiles: %w", err)
		}
	}

	// The mirror checkpoint must never be ahead of the pending witness
	// checkpoint, which is signed by the witness cosigner and always present for
	// a mirrored log (see c2sp.org/tlog-mirror).
	signedPending, err := fs.ReadFile(wh.pendingRoot.FS(), hash+"/checkpoint")
	if err != nil {
		return origin, fmt.Errorf("failed to read pending checkpoint: %w", err)
	}
	pn, err := note.Open(signedPending, wh.witnessVerifier)
	if err != nil {
		return origin, fmt.Errorf("failed to verify pending checkpoint: %w", err)
	}
	pending, err := torchwood.ParseCheckpoint(pn.Text)
	if err != nil {
		return origin, fmt.Errorf("failed to parse pending checkpoint: %w", err)
	}
	if pending.Origin != origin {
		return origin, fmt.Errorf("pending checkpoint origin %q does not match mirror origin %q", pending.Origin, origin)
	}
	if checkpoint.N > pending.N {
		return origin, fmt.Errorf("mirror checkpoint size %d is ahead of pending checkpoint size %d", checkpoint.N, pending.N)
	}
	return origin, nil
}

func isOriginHash(name string) bool {
	b, err := hex.DecodeString(name)
	return err == nil && len(b) == sha256.Size && strings.ToLower(name) == name
}

func parseVerifier(vkey string) (note.Verifier, error) {
	if v, err := note.NewVerifier(vkey); err == nil {
		return v, nil
	}
	return torchwood.NewCosignatureVerifier(vkey)
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
