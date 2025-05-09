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
// /debug/logsoff which enable and disable debug logging, respectively, and
// /debug/keylogon and /debug/keylogoff which enable and disable SSLKEYLOGFILE.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"sync"
	"text/template"
	"time"

	"filippo.io/keygen"
	"filippo.io/sunlight/internal/ctlog"
	"filippo.io/sunlight/internal/reused"
	"filippo.io/sunlight/internal/slogx"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

type Config struct {
	// Listen are the addresses to listen on, e.g. ":443".
	Listen []string

	// ACME is the configuration for the ACME client. Optional. If missing,
	// Sunlight will listen for plain HTTP or h2c.
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

	// HTTPHost is the host name for the HTTP endpoint of this log instance.
	HTTPHost string

	// HTTPPrefix is the prefix for the HTTP endpoint of this log instance,
	// without trailing slash, but with a leading slash if not empty, and
	// without "/ct/v1" suffix.
	HTTPPrefix string

	// SubmissionPrefix is the full URL of the c2sp.org/static-ct-api submission
	// prefix of the log, without trailing slash.
	SubmissionPrefix string

	// MonitoringPrefix is the full URL of the c2sp.org/static-ct-api monitoring
	// prefix of the log, without trailing slash.
	MonitoringPrefix string

	// Roots is the path to the accepted roots as a PEM file.
	Roots string

	// Seed is the path to a file containing a secret seed from which the log's
	// private keys are derived. The whole file is used as HKDF input. It must
	// be at least 32 bytes long.
	//
	// To generate a new seed, run:
	//
	//   $ head -c 32 /dev/urandom > seed.bin
	//
	Seed string

	// PublicKey is the SubjectPublicKeyInfo for this log, base64 encoded.
	//
	// This is the same format as used in Google and Apple's log list JSON files.
	//
	// To generate this from a seed, run:
	//
	//   $ sunlight-keygen log.example/logA seed.bin
	//
	// The loaded private Key is required to match it.
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

	// LocalDirectory is the path to a local directory where the log will store
	// its data. It must be dedicated to this specific log instance.
	//
	// Only one of S3Bucket or LocalDirectory can be set at the same time.
	LocalDirectory string

	// NotAfterStart is the start of the validity range for certificates
	// accepted by this log instance, as and RFC 3339 date.
	NotAfterStart string

	// NotAfterLimit is the end of the validity range (not included) for
	// certificates accepted by this log instance, as and RFC 3339 date.
	NotAfterLimit string
}

// logInfo is used on the homepage and for /log.v3.json. The JSON schema is from
// https://www.gstatic.com/ct/log_list/v3/log_list_schema.json.
type logInfo struct {
	// Fields from LogConfig, we don't embed the whole struct to avoid
	// accidentally exposing sensitive fields.
	Name             string `json:"description"`
	SubmissionPrefix string `json:"submission_url"`
	MonitoringPrefix string `json:"monitoring_url"`
	PoolSize         int    `json:"-"`
	Interval         struct {
		NotAfterStart string `json:"start_inclusive"`
		NotAfterLimit string `json:"end_exclusive"`
	} `json:"temporal_interval"`

	// ID is the base64 encoded SHA-256 of the public key.
	ID string `json:"log_id"`

	// PublicKeyPEM and PublicKeyDER are the SubjectPublicKeyInfo.
	PublicKeyPEM string `json:"-"`
	PublicKeyDER []byte `json:"key"`

	// MMD is always 60 seconds but note that Sunlight logs have zero MMD.
	MMD int `json:"mmd"`
}

//go:embed home.html
var homeHTML string
var homeTmpl = template.Must(template.New("home").Parse(homeHTML))

func main() {
	fs := flag.NewFlagSet("sunlight", flag.ExitOnError)
	configFlag := fs.String("c", "sunlight.yaml", "path to the config file")
	testCertFlag := fs.Bool("testcert", false, "use sunlight.pem and sunlight-key.pem instead of ACME")
	fs.Parse(os.Args[1:])

	logLevel := new(slog.LevelVar)
	logHandler := slogx.MultiHandler([]slog.Handler{
		slog.Handler(slog.NewJSONHandler(os.Stdout,
			&slog.HandlerOptions{AddSource: true, Level: logLevel})),
		slog.Handler(slog.NewTextHandler(os.Stderr,
			&slog.HandlerOptions{Level: logLevel})),
	})
	logger := slog.New(logHandler)

	var keyLogFileMutex sync.RWMutex
	var keyLogFile *os.File
	http.HandleFunc("/debug/keylogon", func(w http.ResponseWriter, r *http.Request) {
		keyLogFileMutex.Lock()
		defer keyLogFileMutex.Unlock()
		if keyLogFile != nil {
			http.Error(w, "key log file already open", http.StatusBadRequest)
			return
		}
		f, err := os.CreateTemp("", "sunlight-keylog-")
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create key log file: %v", err),
				http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%s\n", f.Name())
		keyLogFile = f
	})
	http.HandleFunc("/debug/keylogoff", func(w http.ResponseWriter, r *http.Request) {
		keyLogFileMutex.Lock()
		defer keyLogFileMutex.Unlock()
		if keyLogFile == nil {
			http.Error(w, "key log file not open", http.StatusBadRequest)
			return
		}
		if err := keyLogFile.Close(); err != nil {
			http.Error(w, fmt.Sprintf("failed to close key log file: %v", err),
				http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%s\n", keyLogFile.Name())
		keyLogFile = nil
	})
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
		fatalError(logger, "failed to read config file", "err", err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(yml, c); err != nil {
		fatalError(logger, "failed to parse config file", "err", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// TODO: print total certificates serialized in last 60s.
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

	serveGroup, ctx := errgroup.WithContext(ctx)

	var db ctlog.LockBackend
	switch {
	case c.Checkpoints != "" && c.DynamoDB.Table != "" ||
		c.Checkpoints != "" && c.ETagS3.Bucket != "" ||
		c.DynamoDB.Table != "" && c.ETagS3.Bucket != "":
		fatalError(logger, "only one of Checkpoints, DynamoDB, or ETagS3 can be set at the same time")

	case c.Checkpoints != "":
		b, err := ctlog.NewSQLiteBackend(ctx, c.Checkpoints, logger)
		if err != nil {
			fatalError(logger, "failed to create SQLite checkpoint backend", "err", err)
		}
		sunlightMetrics.MustRegister(b.Metrics()...)
		db = b

	case c.DynamoDB.Table != "":
		b, err := ctlog.NewDynamoDBBackend(ctx,
			c.DynamoDB.Region, c.DynamoDB.Table, c.DynamoDB.Endpoint, logger)
		if err != nil {
			fatalError(logger, "failed to create DynamoDB backend", "err", err)
		}
		sunlightMetrics.MustRegister(b.Metrics()...)
		db = b

	case c.ETagS3.Bucket != "":
		b, err := ctlog.NewETagBackend(ctx,
			c.ETagS3.Region, c.ETagS3.Bucket, c.ETagS3.Endpoint, logger)
		if err != nil {
			fatalError(logger, "failed to create ETag S3 backend", "err", err)
		}
		sunlightMetrics.MustRegister(b.Metrics()...)
		db = b

	default:
		fatalError(logger, "neither Checkpoints nor DynamoDB are set, one must be used")
	}

	sequencerGroup, sequencerContext := errgroup.WithContext(ctx)

	var logList []logInfo
	serveHome := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if err := homeTmpl.Execute(w, logList); err != nil {
			logger.Error("failed to execute homepage template", "err", err)
		}
	}
	mux.HandleFunc("/{$}", serveHome)
	for _, lc := range c.Logs {
		if lc.Name == "" || lc.ShortName == "" {
			fatalError(logger, "missing name or short name for log")
		}
		logger := slog.New(logHandler.WithAttrs([]slog.Attr{
			slog.String("log", lc.ShortName),
		}))

		var b ctlog.Backend
		switch {
		case lc.S3Bucket != "" && lc.LocalDirectory != "":
			fatalError(logger, "only one of S3Bucket or LocalDirectory can be set at the same time")
		case lc.S3Bucket != "":
			b, err = ctlog.NewS3Backend(ctx, lc.S3Region, lc.S3Bucket, lc.S3Endpoint, lc.S3KeyPrefix, logger)
			if err != nil {
				fatalError(logger, "failed to create backend", "err", err)
			}
		case lc.LocalDirectory != "":
			b, err = ctlog.NewLocalBackend(ctx, lc.LocalDirectory, logger)
			if err != nil {
				fatalError(logger, "failed to create backend", "err", err)
			}
		default:
			fatalError(logger, "neither S3Bucket nor LocalDirectory are set, one must be used")
		}

		r := x509util.NewPEMCertPool()
		if err := r.AppendCertsFromPEMFile(lc.Roots); err != nil {
			fatalError(logger, "failed to load roots", "err", err)
		}

		seed, err := os.ReadFile(lc.Seed)
		if err != nil {
			fatalError(logger, "failed to load seed", "err", err)
		}
		if len(seed) < 32 {
			fatalError(logger, "seed file too short, must be at least 32 bytes")
		}

		ecdsaSecret := make([]byte, 32)
		if _, err := io.ReadFull(hkdf.New(sha256.New, seed, []byte("sunlight"), []byte("ECDSA P-256 log key")), ecdsaSecret); err != nil {
			fatalError(logger, "failed to derive ECDSA secret", "err", err)
		}
		k, err := keygen.ECDSA(elliptic.P256(), ecdsaSecret)
		if err != nil {
			fatalError(logger, "failed to generate ECDSA key", "err", err)
		}

		ed25519Secret := make([]byte, ed25519.SeedSize)
		if _, err := io.ReadFull(hkdf.New(sha256.New, seed, []byte("sunlight"), []byte("Ed25519 log key")), ed25519Secret); err != nil {
			fatalError(logger, "failed to derive Ed25519 key", "err", err)
		}
		wk := ed25519.NewKeyFromSeed(ed25519Secret)

		cfgPubKey, err := base64.StdEncoding.DecodeString(lc.PublicKey)
		if err != nil {
			fatalError(logger, "failed to parse public key base64", "err", err)
		}
		parsedPubKey, err := x509.ParsePKIXPublicKey(cfgPubKey)
		if err != nil {
			fatalError(logger, "failed to parse public key", "err", err)
		}
		if !k.PublicKey.Equal(parsedPubKey) {
			spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
			if err != nil {
				fatalError(logger, "failed to marshal public key from private key for display", "err", err)
			}
			publicFromPrivate := base64.StdEncoding.EncodeToString(spki)
			fatalError(logger, "configured private and public keys do not match", "configured", lc.PublicKey, "publicFromPrivate", publicFromPrivate)
		}

		// Compare the checkpoint from the Backend with the one accessible over
		// the MonitoringPrefix, to catch misconfigurations. We ignore failures
		// to fetch from the backend, as the log might not exist yet.
		if exp, err := b.Fetch(ctx, "checkpoint"); err == nil &&
			!bytes.Equal(fetchCheckpoint(ctx, logger, lc.MonitoringPrefix), exp) {
			fatalError(logger, "checkpoints from Backend and MonitoringPrefix don't match")
		}

		notAfterStart, err := time.Parse(time.RFC3339, lc.NotAfterStart)
		if err != nil {
			fatalError(logger, "failed to parse NotAfterStart", "err", err)
		}
		notAfterLimit, err := time.Parse(time.RFC3339, lc.NotAfterLimit)
		if err != nil {
			fatalError(logger, "failed to parse NotAfterLimit", "err", err)
		}

		cc := &ctlog.Config{
			Name:          lc.Name,
			Key:           k,
			WitnessKey:    wk,
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
				fatalError(logger, "failed to create log", "err", err)
			}
		}

		l, err := ctlog.LoadLog(ctx, cc)
		if errors.Is(err, ctlog.ErrLogNotFound) {
			fatalError(logger, "log not found, but today is not the Inception date",
				"today", time.Now().Format(time.DateOnly), "inception", lc.Inception)
		} else if err != nil {
			fatalError(logger, "failed to load log", "err", err)
		}
		defer l.CloseCache()

		sequencerGroup.Go(func() error {
			return l.RunSequencer(sequencerContext, 1*time.Second)
		})

		mux.Handle(lc.HTTPHost+lc.HTTPPrefix+"/", http.StripPrefix(lc.HTTPPrefix, l.Handler()))

		prometheus.WrapRegistererWith(prometheus.Labels{"log": lc.ShortName}, sunlightMetrics).
			MustRegister(l.Metrics()...)

		pkix, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			fatalError(logger, "failed to marshal public key for display", "err", err)
		}
		pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix})
		logID := sha256.Sum256(pkix)
		log := logInfo{
			Name:             lc.Name,
			ID:               base64.StdEncoding.EncodeToString(logID[:]),
			SubmissionPrefix: lc.SubmissionPrefix + "/",
			MonitoringPrefix: lc.MonitoringPrefix + "/",
			PoolSize:         lc.PoolSize,
			PublicKeyPEM:     string(pemKey),
			PublicKeyDER:     pkix,
			MMD:              60,
		}
		log.Interval.NotAfterStart = lc.NotAfterStart
		log.Interval.NotAfterLimit = lc.NotAfterLimit
		logList = append(logList, log)

		j, err := json.MarshalIndent(log, "", "    ")
		if err != nil {
			fatalError(logger, "failed to marshal log info", "err", err)
		}
		err = b.Upload(ctx, "log.v3.json", j, &ctlog.UploadOptions{ContentType: "application/json"})
		if err != nil {
			fatalError(logger, "failed to upload log info", "err", err)
		}
		mux.HandleFunc(lc.HTTPHost+lc.HTTPPrefix+"/log.v3.json", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write(j)
		})

		if lc.HTTPHost != "" {
			mux.HandleFunc(lc.HTTPHost+"/{$}", serveHome)
		}
	}

	s := &http.Server{
		Handler:      reused.NewHandler(mux),
		ConnContext:  reused.ConnContext,
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
				if strings.HasPrefix(r.Message, "http: TLS handshake error") {
					// Only log TLS handshake errors from autocert, filtering out
					// background noise ones.
					return strings.Contains(r.Message, "acme/autocert") &&
						!strings.HasSuffix(r.Message, "missing server name") &&
						!strings.HasSuffix(r.Message, "not configured in HostWhitelist") &&
						!strings.HasSuffix(r.Message, "server name contains invalid character") &&
						!strings.HasSuffix(r.Message, "server name component count invalid")
				}
				return true
			},
		), slog.LevelWarn),
	}
	if *testCertFlag {
		cert, err := tls.LoadX509KeyPair("sunlight.pem", "sunlight-key.pem")
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

	if s.TLSConfig != nil {
		s.TLSConfig.KeyLogWriter = WriterFunc(func(p []byte) (n int, err error) {
			keyLogFileMutex.RLock()
			defer keyLogFileMutex.RUnlock()
			if keyLogFile == nil {
				return 0, nil
			}
			return keyLogFile.Write(p)
		})
	}

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

	if err := sequencerGroup.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("sequencer error", "err", err)
	}

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

func fetchCheckpoint(ctx context.Context, logger *slog.Logger, prefix string) []byte {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", prefix+"/checkpoint", nil)
	if err != nil {
		fatalError(logger, "failed to create request", "err", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatalError(logger, "failed to fetch checkpoint from MonitoringPrefix", "err", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fatalError(logger, "failed to fetch checkpoint from MonitoringPrefix", "status", resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		fatalError(logger, "failed to read checkpoint body", "err", err)
	}
	return b
}

type WriterFunc func(p []byte) (n int, err error)

func (f WriterFunc) Write(p []byte) (n int, err error) {
	return f(p)
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
