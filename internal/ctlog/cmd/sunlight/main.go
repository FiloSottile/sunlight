package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"filippo.io/litetlog/internal/ctlog"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

type Config struct {
	// Listen is the address to listen on, e.g. ":443".
	Listen string

	ACME struct {
		// Email is the email address to use for ACME account registration.
		Email string

		// Host is the name for which autocert will obtain a certificate.
		Host string

		// Cache is the path to the autocert cache directory.
		Cache string
	}

	DynamoDB struct {
		// Region is the AWS region for the DynamoDB table.
		Region string

		// Table is the name of the DynamoDB table that stores the latest
		// checkpoint for each log, with compare-and-swap semantics.
		//
		// Note that this is a global table as an extra safety measure: entries
		// in this table are keyed by log ID (the hash of the public key), so
		// even in case of misconfiguration of the logs entries, even across
		// different concurrent instances of Sunlight, a log can't split.
		//
		// The table must have a primary key named "logID" of type binary.
		Table string
	}

	Logs []LogConfig
}

type LogConfig struct {
	// Name is the fully qualified log name for the checkpoint origin line, as a
	// schema-less URL. It doesn't need to be where the log is actually hosted,
	// but that's advisable.
	Name string

	// ShortName is the short name for the log, used as a metrics and logs label.
	ShortName string

	// HTTPPrefix is the prefix for the HTTP endpoint of this log instance,
	// without trailing slash, but with a leading slash if not empty, and
	// without "/ct/v1" suffix.
	HTTPPrefix string

	// Roots is the path to the accepted roots as a PEM file.
	Roots string

	// Key is the path to the private key as a PKCS#8 PEM file.
	//
	// To generate a new key, run:
	//
	//   $ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform PEM -out key.pem
	//
	Key string

	// Cache is the path to the SQLite deduplication cache file.
	Cache string

	// S3Region is the AWS region for the S3 bucket.
	S3Region string

	// S3Bucket is the name of the S3 bucket. This bucket must be dedicated to
	// this specific log instance.
	S3Bucket string

	// NotAfterStart is the start of the validity range for certificates
	// accepted by this log instance, as and RFC 3339 date.
	NotAfterStart string

	// NotAfterLimit is the end of the validity range (not included) for
	// certificates accepted by this log instance, as and RFC 3339 date.
	NotAfterLimit string
}

func main() {
	configFlag := flag.String("c", "sunlight.yaml", "path to the config file")
	createFlag := flag.Bool("create", false, "create any logs that don't exist and exit")
	flag.Parse()

	logHandler := multiHandler([]slog.Handler{
		slog.Handler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true})),
		slog.Handler(slog.NewTextHandler(os.Stderr, nil)),
	})
	logger := slog.New(logHandler)

	yml, err := os.ReadFile(*configFlag)
	if err != nil {
		logger.Error("failed to read config file", "err", err)
		os.Exit(1)
	}
	c := &Config{}
	if err := yaml.Unmarshal(yml, c); err != nil {
		logger.Error("failed to parse config file", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	metrics := prometheus.NewRegistry()
	metrics.MustRegister(collectors.NewGoCollector())
	metrics.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	mux.Handle("/metrics", promhttp.HandlerFor(metrics, promhttp.HandlerOpts{
		ErrorLog: slog.NewLogLogger(logHandler.WithAttrs(
			[]slog.Attr{slog.String("source", "metrics")},
		), slog.LevelWarn),
	}))
	sunlightMetrics := prometheus.WrapRegistererWithPrefix("sunlight_", metrics)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	db, err := ctlog.NewDynamoDBBackend(ctx, c.DynamoDB.Region, c.DynamoDB.Table, logger)
	if err != nil {
		logger.Error("failed to create DynamoDB backend", "err", err)
		os.Exit(1)
	}
	sunlightMetrics.MustRegister(db.Metrics()...)

	sequencerGroup, sequencerContext := errgroup.WithContext(ctx)

	for _, lc := range c.Logs {
		if lc.Name == "" || lc.ShortName == "" {
			logger.Error("missing name or short name for log")
			os.Exit(1)
		}
		logger := slog.New(logHandler.WithAttrs([]slog.Attr{
			slog.String("log", lc.ShortName),
		}))

		b, err := ctlog.NewS3Backend(ctx, lc.S3Region, lc.S3Bucket, logger)
		if err != nil {
			logger.Error("failed to create backend", "err", err)
			os.Exit(1)
		}

		r := x509util.NewPEMCertPool()
		if err := r.AppendCertsFromPEMFile(lc.Roots); err != nil {
			logger.Error("failed to load roots", "err", err)
			os.Exit(1)
		}

		keyPEM, err := os.ReadFile(lc.Key)
		if err != nil {
			logger.Error("failed to load key", "err", err)
			os.Exit(1)
		}
		block, _ := pem.Decode(keyPEM)
		if block == nil || block.Type != "PRIVATE KEY" {
			logger.Error("failed to parse key PEM")
			os.Exit(1)
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			logger.Error("failed to parse key", "err", err)
			os.Exit(1)
		}
		if _, ok := k.(*ecdsa.PrivateKey); !ok {
			logger.Error("key is not an ECDSA private key")
			os.Exit(1)
		}

		notAfterStart, err := time.Parse(time.RFC3339, lc.NotAfterStart)
		if err != nil {
			logger.Error("failed to parse NotAfterStart", "err", err)
			os.Exit(1)
		}
		notAfterLimit, err := time.Parse(time.RFC3339, lc.NotAfterLimit)
		if err != nil {
			logger.Error("failed to parse NotAfterLimit", "err", err)
			os.Exit(1)
		}

		cc := &ctlog.Config{
			Name:          lc.Name,
			Key:           k.(*ecdsa.PrivateKey),
			Cache:         lc.Cache,
			Backend:       b,
			Lock:          db,
			Log:           logger,
			Roots:         r,
			NotAfterStart: notAfterStart,
			NotAfterLimit: notAfterLimit,
		}

		if *createFlag {
			if err := ctlog.CreateLog(ctx, cc); err == ctlog.ErrLogExists {
				logger.Info("log exists")
			} else if err != nil {
				logger.Error("failed to create log", "err", err)
			}
			continue
		}

		l, err := ctlog.LoadLog(ctx, cc)
		if err != nil {
			logger.Error("failed to load log", "err", err)
			os.Exit(1)
		}
		defer l.CloseCache()

		sequencerGroup.Go(func() error {
			return l.RunSequencer(sequencerContext, 1*time.Second)
		})

		mux.Handle(lc.HTTPPrefix+"/", http.StripPrefix(lc.HTTPPrefix, l.Handler()))

		prometheus.WrapRegistererWith(prometheus.Labels{"log": lc.ShortName}, sunlightMetrics).
			MustRegister(l.Metrics()...)
	}
	if *createFlag {
		return
	}

	m := &autocert.Manager{
		Cache:      autocert.DirCache(c.ACME.Cache),
		Prompt:     autocert.AcceptTOS,
		Email:      c.ACME.Email,
		HostPolicy: autocert.HostWhitelist(c.ACME.Host),
	}
	s := &http.Server{
		Addr:         c.Listen,
		TLSConfig:    m.TLSConfig(),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
		ErrorLog: slog.NewLogLogger(filterHandler{
			handler: logHandler.WithAttrs(
				[]slog.Attr{slog.String("source", "http.Server")},
			),
			filter: func(r slog.Record) bool {
				return !strings.HasPrefix(r.Message, "http: TLS handshake error")
			},
		}, slog.LevelWarn),
	}

	go func() {
		err := s.ListenAndServeTLS("", "")
		logger.Error("ListenAndServeTLS error", "err", err)
		stop()
	}()

	sequencerGroup.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		logger.Error("Shutdown error", "err", err)
	}
}
