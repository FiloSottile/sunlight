// Command sunlight runs a Certificate Transparency log write-path server.
//
// A YAML config file is required (specified with -c, by default sunlight.yaml),
// the keys are documented in the [Config] type.
//
// If the command line flag -testcert is passed, ACME will be disabled and the
// certificate will be loaded from sunlight.pem and sunlight-key.pem.
//
// Metrics are exposed publicly at /metrics, and logs are written to stderr in
// human-readable format, and to stdout in JSON format.
//
// A private HTTP debug server is also started on a random port on localhost. It
// serves the net/http/pprof endpoints, as well as /debug/logson and
// /debug/logsoff which enable and disable debug logging, respectively.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"time"

	"filippo.io/sunlight/internal/ctlog"
	"github.com/google/certificate-transparency-go/x509util"
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
	// Listen is the address to listen on, e.g. ":443".
	Listen string

	// ACME is the configuration for the ACME client. Optional. If missing,
	// Sunlight will listen for plain HTTP or h2c.
	ACME struct {
		// Email is the email address to use for ACME account registration.
		Email string

		// Host is the name for which autocert will obtain a certificate.
		Host string

		// Cache is the path to the autocert cache directory.
		Cache string

		// Directory is an ACME directory URL to request a certificate from.
		// Defaults to Let's Encrypt Production. Optional.
		Directory string
	}

	// Checkpoints, ETagS3, or DynamoDB store the latest checkpoint for each
	// log, with compare-and-swap semantics.
	//
	// Note that these are global as an extra safety measure: entries are keyed
	// by log ID (the hash of the public key), so even in case of
	// misconfiguration of the logs entries, even across different concurrent
	// instances of Sunlight, a log can't split.
	//
	// Only one of these can be set at the same time.

	// Checkpoints is the path to the SQLite file.
	//
	// The database must already exist to protect against accidental
	// misconfiguration. Create the table with:
	//
	//     $ sqlite3 checkpoints.db "CREATE TABLE checkpoints (logID BLOB PRIMARY KEY, body TEXT)"
	//
	Checkpoints string

	// ETagS3 is an S3-compatible object storage bucket that supports ETag on
	// both reads and writes, and If-Match on writes, such as Tigris.
	ETagS3 struct {
		// Region is the AWS region for the S3 bucket.
		Region string

		// Bucket is the name of the S3 bucket.
		Bucket string

		// Endpoint is the base URL the AWS SDK will use to connect to S3.
		Endpoint string
	}

	DynamoDB struct {
		// Region is the AWS region for the DynamoDB table.
		Region string

		// Table is the name of the DynamoDB table.
		//
		// The table must have a primary key named "logID" of type binary.
		Table string

		// Endpoint is the base URL the AWS SDK will use to connect to DynamoDB. Optional.
		Endpoint string
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

	// Inception is the creation date of the log, as an RFC 3339 date.
	//
	// On the inception date, the log will be created if it doesn't exist. After
	// that date, a non-existing log will be a fatal error. This assumes it is
	// due to misconfiguration, and prevents accidental forks.
	Inception string

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

	// PublicKey is the SubjectPublicKeyInfo for this log, base64 encoded.
	//
	// This is the same format as used in Google and Apple's log list JSON files.
	//
	// To generate from a private key, run:
	//
	//   $ openssl pkey -in key.pem -pubout -outform DER | base64 -w0
	//
	// If provided, the loaded private Key is required to match it. Optional.
	PublicKey string

	// Cache is the path to the SQLite deduplication cache file.
	Cache string

	// PoolSize is the maximum number of chains pending in the sequencing pool.
	// Since the pool is sequenced every second, it works as a qps limit. If the
	// pool is full, add-chain requests will be rejected with a 503. Zero means
	// no limit.
	PoolSize int

	// S3Region is the AWS region for the S3 bucket.
	S3Region string

	// S3Bucket is the name of the S3 bucket. This bucket must be dedicated to
	// this specific log instance.
	S3Bucket string

	// S3Endpoint is the base URL the AWS SDK will use to connect to S3. Optional.
	S3Endpoint string

	// S3KeyPrefix is a prefix on all keys written to S3. Optional.
	//
	// S3 doesn't have directories, but using a prefix ending in a "/" is
	// going to be treated like a directory in many tools using S3.
	S3KeyPrefix string

	// LocalBackend is the path to the directory where backend data is going to
	// be saved.
	//
	// Not meant to be used in production, only for testing and development purposes.
	//
	// Cannot be used at the same time as the S3 bucket.
	LocalBackend string

	// NotAfterStart is the start of the validity range for certificates
	// accepted by this log instance, as and RFC 3339 date.
	NotAfterStart string

	// NotAfterLimit is the end of the validity range (not included) for
	// certificates accepted by this log instance, as and RFC 3339 date.
	NotAfterLimit string
}

func main() {
	fs := flag.NewFlagSet("sunlight", flag.ExitOnError)
	configFlag := fs.String("c", "sunlight.yaml", "path to the config file")
	testCertFlag := fs.Bool("testcert", false, "use sunlight.pem and sunlight-key.pem instead of ACME")
	fs.Parse(os.Args[1:])

	logLevel := new(slog.LevelVar)
	logHandler := multiHandler([]slog.Handler{
		slog.Handler(slog.NewJSONHandler(os.Stdout,
			&slog.HandlerOptions{AddSource: true, Level: logLevel})),
		slog.Handler(slog.NewTextHandler(os.Stderr,
			&slog.HandlerOptions{Level: logLevel})),
	})
	logger := slog.New(logHandler)

	http.HandleFunc("/debug/logson", func(w http.ResponseWriter, r *http.Request) {
		logLevel.Set(slog.LevelDebug)
		w.WriteHeader(http.StatusOK)
	})
	http.HandleFunc("/debug/logsoff", func(w http.ResponseWriter, r *http.Request) {
		logLevel.Set(slog.LevelInfo)
		w.WriteHeader(http.StatusOK)
	})
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
	sunlightMetrics := prometheus.WrapRegistererWithPrefix("sunlight_", metrics)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var db ctlog.LockBackend
	switch {
	case c.Checkpoints != "" && c.DynamoDB.Table != "" ||
		c.Checkpoints != "" && c.ETagS3.Bucket != "" ||
		c.DynamoDB.Table != "" && c.ETagS3.Bucket != "":
		logger.Error("only one of Checkpoints, DynamoDB, or ETagS3 can be set at the same time")
		os.Exit(1)

	case c.Checkpoints != "":
		b, err := ctlog.NewSQLiteBackend(ctx, c.Checkpoints, logger)
		if err != nil {
			logger.Error("failed to create SQLite checkpoint backend", "err", err)
			os.Exit(1)
		}
		sunlightMetrics.MustRegister(b.Metrics()...)
		db = b

	case c.DynamoDB.Table != "":
		b, err := ctlog.NewDynamoDBBackend(ctx,
			c.DynamoDB.Region, c.DynamoDB.Table, c.DynamoDB.Endpoint, logger)
		if err != nil {
			logger.Error("failed to create DynamoDB backend", "err", err)
			os.Exit(1)
		}
		sunlightMetrics.MustRegister(b.Metrics()...)
		db = b

	case c.ETagS3.Bucket != "":
		b, err := ctlog.NewETagBackend(ctx,
			c.ETagS3.Region, c.ETagS3.Bucket, c.ETagS3.Endpoint, logger)
		if err != nil {
			logger.Error("failed to create ETag S3 backend", "err", err)
			os.Exit(1)
		}
		sunlightMetrics.MustRegister(b.Metrics()...)
		db = b

	default:
		logger.Error("neither Checkpoints nor DynamoDB are set, one must be used")
		os.Exit(1)
	}

	sequencerGroup, sequencerContext := errgroup.WithContext(ctx)

	for _, lc := range c.Logs {
		if lc.Name == "" || lc.ShortName == "" {
			logger.Error("missing name or short name for log")
			os.Exit(1)
		}
		logger := slog.New(logHandler.WithAttrs([]slog.Attr{
			slog.String("log", lc.ShortName),
		}))

		var b ctlog.Backend
		if lc.LocalBackend != "" {
			if lc.S3Bucket != "" || lc.S3Region != "" || lc.S3Endpoint != "" || lc.S3KeyPrefix != "" {
				logger.Error("local backend cannot be used with S3")
				os.Exit(1)
			}

			b, err = ctlog.NewLocalBackend(lc.LocalBackend)
			if err != nil {
				logger.Error("failed to create backend", "err", err)
				os.Exit(1)
			}
		} else {
			b, err = ctlog.NewS3Backend(ctx, lc.S3Region, lc.S3Bucket, lc.S3Endpoint, lc.S3KeyPrefix, logger)
			if err != nil {
				logger.Error("failed to create backend", "err", err)
				os.Exit(1)
			}
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

		if lc.PublicKey != "" {
			cfgPubKey, err := base64.StdEncoding.DecodeString(lc.PublicKey)
			if err != nil {
				logger.Error("failed to parse public key base64", "err", err)
				os.Exit(1)
			}

			parsedPubKey, err := x509.ParsePKIXPublicKey(cfgPubKey)
			if err != nil {
				logger.Error("failed to parse public key", "err", err)
				os.Exit(1)
			}

			if !k.(*ecdsa.PrivateKey).PublicKey.Equal(parsedPubKey) {
				spki, err := x509.MarshalPKIXPublicKey(&k.(*ecdsa.PrivateKey).PublicKey)
				if err != nil {
					logger.Error("failed to marshal public key from private key for display", "err", err)
					os.Exit(1)
				}

				publicFromPrivate := base64.StdEncoding.EncodeToString(spki)
				logger.Error("configured private and public keys do not match", "configured", lc.PublicKey, "publicFromPrivate", publicFromPrivate)
				os.Exit(1)
			}
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
			PoolSize:      lc.PoolSize,
			Backend:       b,
			Lock:          db,
			Log:           logger,
			Roots:         r,
			NotAfterStart: notAfterStart,
			NotAfterLimit: notAfterLimit,
		}

		if time.Now().Format(time.DateOnly) == lc.Inception {
			logger.Info("today is the Inception date, creating log")
			if err := ctlog.CreateLog(ctx, cc); err == ctlog.ErrLogExists {
				logger.Info("log exists")
			} else if err != nil {
				logger.Error("failed to create log", "err", err)
			}
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

	s := &http.Server{
		Addr:         c.Listen,
		Handler:      mux,
		ConnContext:  ctlog.ReusedConnContext,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
		ErrorLog: slog.NewLogLogger(filterHandler{
			handler: logHandler.WithAttrs(
				[]slog.Attr{slog.String("source", "http.Server")},
			),
			filter: func(r slog.Record) bool {
				// Unless debug logging is enabled, hide Internet background radiation.
				if logHandler.Enabled(context.Background(), slog.LevelDebug) {
					return true
				}
				if !strings.HasPrefix(r.Message, "http: TLS handshake error") {
					return true
				}
				return strings.Contains(r.Message, "acme/autocert") &&
					!strings.HasSuffix(r.Message, "missing server name") &&
					!strings.HasSuffix(r.Message, "not configured in HostWhitelist") &&
					!strings.HasSuffix(r.Message, "server name contains invalid character") &&
					!strings.HasSuffix(r.Message, "server name component count invalid")
			},
		}, slog.LevelWarn),
	}
	if *testCertFlag {
		cert, err := tls.LoadX509KeyPair("sunlight.pem", "sunlight-key.pem")
		if err != nil {
			logger.Error("failed to load test cert", "err", err)
			os.Exit(1)
		}
		s.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	} else if c.ACME.Host != "" {
		m := &autocert.Manager{
			Cache:      autocert.DirCache(c.ACME.Cache),
			Prompt:     autocert.AcceptTOS,
			Email:      c.ACME.Email,
			HostPolicy: autocert.HostWhitelist(c.ACME.Host),
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

	go func() {
		if s.TLSConfig != nil {
			err := s.ListenAndServeTLS("", "")
			logger.Error("ListenAndServeTLS error", "err", err)
		} else {
			err := s.ListenAndServe()
			logger.Error("ListenAndServe error", "err", err)
		}
		stop()
	}()

	sequencerGroup.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		logger.Error("Shutdown error", "err", err)
	}

	os.Exit(1)
}
