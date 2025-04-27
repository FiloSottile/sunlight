package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/slogx"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

type Config struct {
	// Listen are the addresses to listen on, e.g. ":443".
	Listen []string

	// ACME is the configuration for the ACME client. Optional. If missing,
	// Skylight will listen for plain HTTP or h2c.
	ACME struct {
		// Email is the email address to use for ACME account registration.
		Email string

		// Hosts are the names for which autocert will obtain a certificate.
		Hosts []string

		// Cache is the path to the autocert cache directory.
		Cache string

		// Directory is an ACME directory URL to request a certificate from.
		// Defaults to Let's Encrypt Production. Optional.
		Directory string
	}

	Logs []LogConfig
}

type LogConfig struct {
	// ShortName is the short name for the log, used as a metrics and logs label.
	ShortName string

	// HTTPHost is the host name for the HTTP endpoint of this log instance.
	HTTPHost string

	// HTTPPrefix is the prefix for the HTTP endpoint of this log instance,
	// without trailing slash, but with a leading slash if not empty.
	HTTPPrefix string

	// HomeRedirect is the 302 destination of the root.
	HomeRedirect string

	// LocalDirectory is the path to a local directory where the log will store
	// its data. It must be dedicated to this specific log instance.
	LocalDirectory string
}

func main() {
	fs := flag.NewFlagSet("skylight", flag.ExitOnError)
	configFlag := fs.String("c", "skylight.yaml", "path to the config file")
	testCertFlag := fs.Bool("testcert", false, "use skylight.pem and skylight-key.pem instead of ACME")
	fs.Parse(os.Args[1:])

	logLevel := new(slog.LevelVar)
	logHandler := slogx.MultiHandler([]slog.Handler{
		slog.Handler(slog.NewJSONHandler(os.Stdout,
			&slog.HandlerOptions{AddSource: true, Level: logLevel})),
		slog.Handler(slog.NewTextHandler(os.Stderr,
			&slog.HandlerOptions{Level: logLevel})),
	})
	logger := slog.New(logHandler)

	yml, err := os.ReadFile(*configFlag)
	if err != nil {
		fatalError(logger, "failed to read config file", "err", err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(yml, c); err != nil {
		fatalError(logger, "failed to parse config file", "err", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	metrics := prometheus.NewRegistry()
	metrics.MustRegister(collectors.NewGoCollector())
	metrics.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	mux.Handle("/metrics", promhttp.HandlerFor(metrics, promhttp.HandlerOpts{
		ErrorLog: slog.NewLogLogger(logHandler.WithAttrs(
			[]slog.Attr{slog.String("source", "metrics")},
		), slog.LevelWarn),
	}))
	reqInFlight := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "http_in_flight_requests",
			Help: "Requests currently being served.",
		},
		[]string{"log"},
	)
	reqCount := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "HTTP requests served.",
		},
		[]string{"log", "kind", "code"},
	)
	reqDuration := prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "http_request_duration_seconds",
			Help:       "HTTP request serving latencies in seconds.",
			Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
			MaxAge:     1 * time.Minute,
			AgeBuckets: 6,
		},
		[]string{"log", "kind"},
	)
	resSize := prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "http_response_size_bytes",
			Help:       "HTTP response sizes in bytes.",
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

	for _, lc := range c.Logs {
		if lc.ShortName == "" {
			fatalError(logger, "missing name or short name for log")
		}
		logger := slog.New(logHandler.WithAttrs([]slog.Attr{
			slog.String("log", lc.ShortName),
		}))

		root, err := os.OpenRoot(lc.LocalDirectory)
		if err != nil {
			fatalError(logger, "failed to open local directory", "err", err)
		}
		handler := http.FileServerFS(root.FS())

		type kindContextKey struct{}
		kindFromContext := func(ctx context.Context) string {
			if k, ok := ctx.Value(kindContextKey{}).(string); ok {
				return k
			}
			return ""
		}

		labels := prometheus.Labels{"log": lc.ShortName}
		handler = promhttp.InstrumentHandlerInFlight(reqInFlight.With(labels), handler)
		handler = promhttp.InstrumentHandlerCounter(reqCount.MustCurryWith(labels), handler,
			promhttp.WithLabelFromCtx("kind", kindFromContext))
		handler = promhttp.InstrumentHandlerDuration(reqDuration.MustCurryWith(labels), handler,
			promhttp.WithLabelFromCtx("kind", kindFromContext))
		handler = promhttp.InstrumentHandlerResponseSize(resSize.MustCurryWith(labels), handler,
			promhttp.WithLabelFromCtx("kind", kindFromContext))

		// TODO:
		//
		//   - Rate limit partial data tiles
		//   - Rate limit unidentified clients
		//   - Throttle new connections and track reuse
		//   - User-Agent metrics?
		//   - golang.org/x/website/internal/webtest
		//

		patternPrefix := "GET " + lc.HTTPHost + lc.HTTPPrefix
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
			if r.PathValue("issuer") == "" {
				reqCount.MustCurryWith(labels).WithLabelValues("issuer", "400").Inc()
				http.Error(w, "missing issuer", http.StatusBadRequest)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Content-Type", "application/pkix-cert")
			w.Header().Set("Cache-Control", "public, max-age=604800, immutable")
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
				reqCount.MustCurryWith(labels).WithLabelValues("tile", "400").Inc()
				http.Error(w, "invalid tile path", http.StatusBadRequest)
				return
			}
			if tile.L == -1 {
				w.Header().Set("Content-Encoding", "gzip")
				if tile.W < sunlight.TileWidth {
					r = r.WithContext(context.WithValue(r.Context(), kindContextKey{}, "partial"))
				} else {
					r = r.WithContext(context.WithValue(r.Context(), kindContextKey{}, "data"))
				}
			} else {
				r = r.WithContext(context.WithValue(r.Context(), kindContextKey{}, "tile"))
			}
			handler.ServeHTTP(w, r)
		})
		mux.HandleFunc(patternPrefix+"/{$}", func(w http.ResponseWriter, r *http.Request) {
			reqCount.MustCurryWith(labels).WithLabelValues("index", "302").Inc()
			http.Redirect(w, r, lc.HomeRedirect, http.StatusFound)
		})
	}

	s := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
		ErrorLog: slog.NewLogLogger(slogx.NewFilterHandler(
			logHandler.WithAttrs(
				[]slog.Attr{slog.String("source", "http.Server")},
			),
			func(r slog.Record) bool {
				// Unless debug logging is enabled, hide Internet background radiation.
				if logHandler.Enabled(context.Background(), slog.LevelDebug) {
					return true
				}
				return strings.Contains(r.Message, "acme/autocert") &&
					!strings.HasSuffix(r.Message, "missing server name") &&
					!strings.HasSuffix(r.Message, "not configured in HostWhitelist") &&
					!strings.HasSuffix(r.Message, "server name contains invalid character") &&
					!strings.HasSuffix(r.Message, "server name component count invalid")
			},
		), slog.LevelWarn),
	}
	if *testCertFlag {
		cert, err := tls.LoadX509KeyPair("skylight.pem", "skylight-key.pem")
		if err != nil {
			fatalError(logger, "failed to load test cert", "err", err)
		}
		s.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	} else if len(c.ACME.Hosts) > 0 {
		m := &autocert.Manager{
			Cache:      autocert.DirCache(c.ACME.Cache),
			Prompt:     autocert.AcceptTOS,
			Email:      c.ACME.Email,
			HostPolicy: autocert.HostWhitelist(c.ACME.Hosts...),
			Client: &acme.Client{
				DirectoryURL: c.ACME.Directory,
				UserAgent:    "filippo.io/sunlight",
			},
		}
		s.TLSConfig = m.TLSConfig()
	} else {
		s.Handler = h2c.NewHandler(s.Handler, &http2.Server{})
		s.Handler = http.MaxBytesHandler(s.Handler, 128*1024)
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

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
