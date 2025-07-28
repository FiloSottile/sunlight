// Command skylight runs a Certificate Transparency log read-path server.
//
// A YAML config file is required (specified with -c, by default skylight.yaml),
// the keys are documented in the [Config] type.
//
// If the command line flag -testcert is passed, ACME will be disabled and the
// certificate will be loaded from skylight.pem and skylight-key.pem.
//
// Requests from clients that don't specify an email address in their
// User-Agent will be globally rate-limited to 75 requests per second.
//
// Metrics are exposed publicly at /metrics, and logs are written to stderr in
// human-readable format, and to stdout in JSON format. /health reports the
// health of all logs, returning 500 if any non-staging log is stale.
//
// A private HTTP debug server is also started on a random port on localhost. It
// serves the net/http/pprof endpoints, the [heavyhitter] endpoints, the
// [keylog] endpoints, and the [stdlog] endpoints.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"strconv"
	"strings"
	"sync"
	"time"

	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/heavyhitter"
	"filippo.io/sunlight/internal/keylog"
	"filippo.io/sunlight/internal/reused"
	"filippo.io/sunlight/internal/stdlog"
	"filippo.io/torchwood"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
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
		// beyond those configured as part of the SubmissionPrefix of logs and
		// witness. Optional.
		Hosts []string

		// Directory is an ACME directory URL to request a certificate from.
		// Defaults to Let's Encrypt Production. Optional.
		Directory string
	}

	// HomeRedirect is the 302 destination of the root. Optional.
	HomeRedirect string

	Logs []LogConfig
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

type clientContextKey struct{}

func clientFromContext(ctx context.Context) string {
	c, _ := ctx.Value(clientContextKey{}).(string)
	return c
}

func newClientContextHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if userAgent := r.UserAgent(); strings.Contains(userAgent, "changeme@example.com") {
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

		lc.MonitoringPrefix = strings.TrimSuffix(lc.MonitoringPrefix, "/")
		prefix, err := url.Parse(lc.MonitoringPrefix)
		if err != nil {
			fatalError(logger, "failed to parse MonitoringPrefix", "err", err)
		}
		if prefix.Scheme != "https" {
			fatalError(logger, "MonitoringPrefix must use https scheme",
				"prefix", lc.MonitoringPrefix)
		}
		if prefix.Host == "" {
			fatalError(logger, "MonitoringPrefix must have a host",
				"prefix", lc.MonitoringPrefix)
		}

		acmeHosts = append(acmeHosts, prefix.Hostname())

		root, err := os.OpenRoot(lc.LocalDirectory)
		if err != nil {
			fatalError(logger, "failed to open local directory", "err", err)
		}
		roots[lc] = root
		handler := http.FileServerFS(root.FS())

		// Wrap the file handler with duration and response size metrics.
		// Avoid tracking the size and duration of errors or simple responses.
		labels := prometheus.Labels{"log": lc.ShortName}
		handler = promhttp.InstrumentHandlerDuration(reqDuration.MustCurryWith(labels), handler,
			promhttp.WithLabelFromCtx("kind", kindFromContext))
		handler = promhttp.InstrumentHandlerResponseSize(resSize.MustCurryWith(labels), handler,
			promhttp.WithLabelFromCtx("kind", kindFromContext))

		// Then, apply the rate limit handler.
		handler = newRateLimitHandler(handler)

		// Next, the request counter. It needs to go before the mux as it uses
		// the context keys we set in the per-path handlers, but after the rate
		// limit handler, so it will capture the 429 errors.
		handler = promhttp.InstrumentHandlerCounter(reqCount.MustCurryWith(labels), handler,
			promhttp.WithLabelFromCtx("kind", kindFromContext),
			promhttp.WithLabelFromCtx("reused", reused.LabelFromContext),
			promhttp.WithLabelFromCtx("client", clientFromContext))

		// All paths that don't reach the instrumented handler need to observe
		// their own request count metric.
		httpError := func(w http.ResponseWriter, r *http.Request, kind, error string, code int) {
			reused := reused.LabelFromContext(r.Context())
			client := clientFromContext(r.Context())
			reqCount.WithLabelValues(lc.ShortName, kind, client, reused, strconv.Itoa(code)).Inc()
			w.Header().Del("Content-Encoding")
			w.Header().Del("Cache-Control")
			http.Error(w, error, code)
		}

		// Finally, the per-path mux handler that specialize the request,
		// setting headers and context keys.
		patternPrefix := "GET " + prefix.Host + prefix.Path
		mux.HandleFunc(patternPrefix+"/checkpoint", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			r = r.WithContext(context.WithValue(r.Context(), kindContextKey{}, "checkpoint"))
			handler.ServeHTTP(w, r)
		})
		mux.HandleFunc(patternPrefix+"/log.v3.json", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "application/json")
			r = r.WithContext(context.WithValue(r.Context(), kindContextKey{}, "log.v3.json"))
			handler.ServeHTTP(w, r)
		})
		mux.HandleFunc(patternPrefix+"/issuer/{issuer}", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "application/pkix-cert")
			w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
			if r.PathValue("issuer") == "" {
				httpError(w, r, "issuer", "missing issuer", http.StatusBadRequest)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), kindContextKey{}, "issuer"))
			handler.ServeHTTP(w, r)
		})
		mux.HandleFunc(patternPrefix+"/tile/{tile...}", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
			tilePath := "tile/" + r.PathValue("tile")
			tile, err := sunlight.ParseTilePath(tilePath)
			if err != nil {
				httpError(w, r, "tile", "invalid tile path", http.StatusBadRequest)
				return
			}
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
			handler.ServeHTTP(w, r)
		})
	}

	if c.HomeRedirect != "" {
		mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
			reused := reused.LabelFromContext(r.Context())
			client := clientFromContext(r.Context())
			reqCount.WithLabelValues("", "index", client, reused, "302").Inc()

			http.Redirect(w, r, c.HomeRedirect, http.StatusFound)
		})
	}

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK
		buf := &bytes.Buffer{}
		for log, root := range roots {
			if err := checkLog(root); err != nil {
				if log.Staging {
					fmt.Fprintf(buf, "%s: %v (ignored)\n", log.ShortName, err)
				} else {
					status = http.StatusInternalServerError
					fmt.Fprintf(buf, "%s: %v\n", log.ShortName, err)
				}
			} else {
				fmt.Fprintf(buf, "%s: OK\n", log.ShortName)
			}
		}

		reused := reused.LabelFromContext(r.Context())
		client := clientFromContext(r.Context())
		reqCount.WithLabelValues("", "health", client, reused, strconv.Itoa(status)).Inc()

		w.WriteHeader(status)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
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
		s.Handler = h2c.NewHandler(s.Handler, &http2.Server{})
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

type logInfo struct {
	Name         string `json:"description"`
	PublicKeyDER []byte `json:"key"`
}

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
	if ct := time.UnixMilli(t); time.Since(ct) > 5*time.Second {
		return fmt.Errorf("checkpoint is too old: %v", ct)
	}
	return nil
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
