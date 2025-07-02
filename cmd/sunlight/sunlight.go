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
// serves the net/http/pprof endpoints, the [heavyhitter] endpoints, the
// [keylog] endpoints, and the [stdlog] endpoints.
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
	"io"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"text/template"
	"time"

	"filippo.io/keygen"
	"filippo.io/sunlight/internal/ctlog"
	"filippo.io/sunlight/internal/heavyhitter"
	"filippo.io/sunlight/internal/keylog"
	"filippo.io/sunlight/internal/reused"
	"filippo.io/sunlight/internal/stdlog"
	"filippo.io/sunlight/internal/witness"
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

	// ACME configures how Sunlight automatically obtains certificates for its HTTPS
	// endpoints. Optional. If missing, Sunlight will listen for plain HTTP or h2c.
	ACME struct {
		// Cache is the path to the directory where keys and certificates will
		// be stored. It will be created if it doesn't already exist.
		Cache string

		// Hosts are extra names for which Sunlight will obtain a certificate,
		// beyond those configured as part of the SubmissionPrefix of logs and
		// witness. Optional.
		Hosts []string

		// Directory is an ACME directory URL to request a certificate from.
		// Defaults to Let's Encrypt Production. Optional.
		Directory string
	}

	// Checkpoints, ETagS3, or DynamoDB configure the global lock backend, which
	// stores the latest checkpoint for each log, with compare-and-swap semantics.
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

	// Witness is the configuration for the optional witness server, which uses
	// the compare-and-swap backend.
	Witness struct {
		// Name is the cosigner name.
		Name string

		// SubmissionPrefix is the full URL of the c2sp.org/tlog-witness
		// submission prefix of the witness.
		//
		// The HTTP server will serve the witness at this URL, and if ACME is
		// enabled, Sunlight will obtain a certificate for the host of this URL.
		SubmissionPrefix string

		// Secret is the path to a file containing a secret seed from which the
		// witness's private key is derived. The file contents are used as HKDF
		// input and mixed with the Name. It must be exactly 32 bytes long.
		//
		// To generate a new seed, run:
		//
		//   $ head -c 32 /dev/urandom > seed.bin
		//
		Secret string

		// KnownLogs is a list of known logs that the witness will accept and
		// cosign checkpoints for, along with their vkeys.
		KnownLogs []witness.LogConfig
	}

	Logs []LogConfig
}

type LogConfig struct {
	// Name is the fully qualified log name for the checkpoint origin line, as a
	// schema-less URL.
	//
	// Deprecated: this should be omitted and must match SubmissionPrefix.
	Name string

	// ShortName is the short name for the log, used as a metrics and logs label.
	ShortName string

	// Inception is the creation date of the log, as an RFC 3339 date.
	//
	// On the inception date, the log will be created if it doesn't exist. After
	// that date, a non-existing log will be a fatal error. This assumes it is
	// due to misconfiguration, and prevents accidental forks.
	Inception string

	// Period is the time between sequence operations, as milliseconds.
	//
	// If a sequencing is still in progress when the next one is due, the next
	// one will be skipped.
	//
	// Defaults to 1000 milliseconds (1 second).
	Period int

	// HTTPHost is the host name for the HTTP endpoint of this log instance.
	//
	// Deprecated: this should be omitted and must match SubmissionPrefix.
	HTTPHost string

	// HTTPPrefix is the prefix for the HTTP endpoint of this log instance,
	// without trailing slash, but with a leading slash if not empty, and
	// without "/ct/v1" suffix.
	//
	// Deprecated: this should be omitted and must match SubmissionPrefix.
	HTTPPrefix string

	// SubmissionPrefix is the full URL of the c2sp.org/static-ct-api submission
	// prefix of the log.
	//
	// The HTTP server will serve the log at this URL, and if ACME is enabled,
	// Sunlight will obtain a certificate for the host of this URL.
	SubmissionPrefix string

	// MonitoringPrefix is the full URL of the c2sp.org/static-ct-api monitoring
	// prefix of the log.
	MonitoringPrefix string

	// Roots is the path to the accepted roots as a PEM file.
	Roots string

	// Secret is the path to a file containing a secret seed from which the
	// log's private keys are derived. The file contents are used as HKDF input.
	// It must be exactly 32 bytes long.
	//
	// To generate a new seed, run:
	//
	//   $ head -c 32 /dev/urandom > seed.bin
	//
	Secret string

	// Seed is a legacy name for the Secret field.
	//
	// Deprecated: use Secret instead.
	Seed string

	// Cache is the path to the SQLite deduplication cache file. It will be
	// created if it doesn't already exist.
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
	//
	// Only one of S3Bucket or LocalDirectory can be set at the same time.
	S3Bucket string

	// S3Endpoint is the base URL the AWS SDK will use to connect to S3. Optional.
	S3Endpoint string

	// S3KeyPrefix is a prefix on all keys written to S3. Optional.
	//
	// S3 doesn't have directories, but using a prefix ending in a "/" is
	// going to be treated like a directory in many tools using S3.
	S3KeyPrefix string

	// LocalDirectory is the path to a local directory where the log will store
	// its data. It must be dedicated to this specific log instance. It will
	// be created if it doesn't already exist.
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
	ShortName        string `json:"-"`
	SubmissionPrefix string `json:"submission_url"` // with trailing slash
	MonitoringPrefix string `json:"monitoring_url"` // with trailing slash
	PoolSize         int    `json:"-"`
	Interval         struct {
		NotAfterStart string `json:"start_inclusive"`
		NotAfterLimit string `json:"end_exclusive"`
	} `json:"temporal_interval"`

	// ID is the base64 encoded SHA-256 of the public key.
	ID string `json:"log_id"`

	// PublicKeyPEM, PublicKeyDER, and PublicKeyBase64 are the
	// SubjectPublicKeyInfo in various encodings.
	PublicKeyPEM    string `json:"-"`
	PublicKeyDER    []byte `json:"key"`
	PublicKeyBase64 string `json:"-"`

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

	logger := slog.New(stdlog.Handler)

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
		ErrorLog: slog.NewLogLogger(stdlog.Handler.WithAttrs(
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

	var homeData struct {
		Logs    []logInfo
		Witness struct {
			Name             string
			SubmissionPrefix string
			VerifierKey      string
			Logs             []string
		}
	}
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if err := homeTmpl.Execute(w, homeData); err != nil {
			logger.Error("failed to execute homepage template", "err", err)
		}
	})

	var acmeHosts []string
	for _, lc := range c.Logs {
		if lc.ShortName == "" {
			fatalError(logger, "missing short name for log")
		}
		logger := slog.New(stdlog.Handler.WithAttrs([]slog.Attr{
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

		if lc.Secret == "" && lc.Seed != "" {
			logger.Warn("using deprecated Seed field, use Secret instead")
			lc.Secret = lc.Seed
		}
		seed, err := os.ReadFile(lc.Secret)
		if err != nil {
			fatalError(logger, "failed to load seed", "err", err)
		}
		if len(seed) != 32 {
			fatalError(logger, "seed file must be exactly 32 bytes")
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

		lc.SubmissionPrefix = strings.TrimSuffix(lc.SubmissionPrefix, "/")
		lc.MonitoringPrefix = strings.TrimSuffix(lc.MonitoringPrefix, "/")
		prefix, err := url.Parse(lc.SubmissionPrefix)
		if err != nil {
			fatalError(logger, "failed to parse SubmissionPrefix", "err", err)
		}
		if prefix.Scheme != "https" {
			fatalError(logger, "SubmissionPrefix must be an https URL", "prefix", lc.SubmissionPrefix)
		}
		if prefix.Host == "" {
			fatalError(logger, "SubmissionPrefix must have a host", "prefix", lc.SubmissionPrefix)
		}
		if lc.HTTPHost != "" && lc.HTTPHost != prefix.Host {
			fatalError(logger, "HTTPHost must match SubmissionPrefix host",
				"httpHost", lc.HTTPHost, "submissionPrefix", lc.SubmissionPrefix)
		}
		if lc.HTTPPrefix != "" && lc.HTTPPrefix != prefix.Path {
			fatalError(logger, "HTTPPrefix must match SubmissionPrefix path",
				"httpPrefix", lc.HTTPPrefix, "submissionPrefix", lc.SubmissionPrefix)
		}
		if lc.Name != "" && lc.Name != prefix.Host+prefix.Path {
			fatalError(logger, "Name must match SubmissionPrefix host and path",
				"name", lc.Name, "submissionPrefix", lc.SubmissionPrefix)
		}

		cc := &ctlog.Config{
			Name:          prefix.Host + prefix.Path,
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

		period := 1 * time.Second
		if lc.Period > 0 {
			period = time.Duration(lc.Period) * time.Millisecond
		}
		sequencerGroup.Go(func() error {
			return l.RunSequencer(sequencerContext, period)
		})
		mux.Handle(prefix.Host+prefix.Path+"/ct/v1/", http.StripPrefix(prefix.Path, l.Handler()))

		acmeHosts = append(acmeHosts, prefix.Hostname())

		prometheus.WrapRegistererWith(prometheus.Labels{"log": lc.ShortName}, sunlightMetrics).
			MustRegister(l.Metrics()...)

		pkix, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			fatalError(logger, "failed to marshal public key for display", "err", err)
		}
		pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix})
		logID := sha256.Sum256(pkix)
		log := logInfo{
			Name:             prefix.Host + prefix.Path,
			ShortName:        lc.ShortName,
			ID:               base64.StdEncoding.EncodeToString(logID[:]),
			SubmissionPrefix: lc.SubmissionPrefix + "/",
			MonitoringPrefix: lc.MonitoringPrefix + "/",
			PoolSize:         lc.PoolSize,
			PublicKeyPEM:     string(pemKey),
			PublicKeyDER:     pkix,
			PublicKeyBase64:  base64.StdEncoding.EncodeToString(pkix),
			MMD:              60,
		}
		log.Interval.NotAfterStart = lc.NotAfterStart
		log.Interval.NotAfterLimit = lc.NotAfterLimit
		homeData.Logs = append(homeData.Logs, log)

		j, err := json.MarshalIndent(log, "", "    ")
		if err != nil {
			fatalError(logger, "failed to marshal log info", "err", err)
		}
		err = b.Upload(ctx, "log.v3.json", j, &ctlog.UploadOptions{ContentType: "application/json"})
		if err != nil {
			fatalError(logger, "failed to upload log info", "err", err)
		}
		mux.HandleFunc(prefix.Host+prefix.Path+"/log.v3.json", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write(j)
		})
	}

	if c.Witness.Name != "" {
		logger := slog.New(stdlog.Handler.WithAttrs([]slog.Attr{
			slog.String("witness", c.Witness.Name),
		}))

		seed, err := os.ReadFile(c.Witness.Secret)
		if err != nil {
			fatalError(logger, "failed to load witness seed", "err", err)
		}
		if len(seed) != 32 {
			fatalError(logger, "witness seed file must be exactly 32 bytes")
		}

		ed25519Secret := make([]byte, ed25519.SeedSize)
		if _, err := io.ReadFull(hkdf.New(sha256.New, seed, []byte("sunlight Ed25519 witness key"),
			[]byte(c.Witness.Name)), ed25519Secret); err != nil {
			fatalError(logger, "failed to derive Ed25519 key", "err", err)
		}
		wk := ed25519.NewKeyFromSeed(ed25519Secret)

		w, err := witness.NewWitness(ctx, &witness.Config{
			Name:    c.Witness.Name,
			Key:     wk,
			Backend: db,
			Log:     logger,
			Logs:    c.Witness.KnownLogs,
		})
		if err != nil {
			fatalError(logger, "failed to create witness", "err", err)
		}

		c.Witness.SubmissionPrefix = strings.TrimSuffix(c.Witness.SubmissionPrefix, "/")
		prefix, err := url.Parse(c.Witness.SubmissionPrefix)
		if err != nil {
			fatalError(logger, "failed to parse SubmissionPrefix", "err", err)
		}
		if prefix.Scheme != "https" {
			fatalError(logger, "SubmissionPrefix must be an https URL",
				"prefix", c.Witness.SubmissionPrefix)
		}
		if prefix.Host == "" {
			fatalError(logger, "SubmissionPrefix must have a host",
				"prefix", c.Witness.SubmissionPrefix)
		}
		mux.Handle(prefix.Host+prefix.Path+"/", http.StripPrefix(prefix.Path, w.Handler()))

		acmeHosts = append(acmeHosts, prefix.Host)

		witnessMetrics := prometheus.WrapRegistererWithPrefix("witness_", sunlightMetrics)
		witnessMetrics.MustRegister(w.Metrics()...)

		homeData.Witness.Name = c.Witness.Name
		homeData.Witness.SubmissionPrefix = c.Witness.SubmissionPrefix
		homeData.Witness.VerifierKey = w.VerifierKey()
		for _, log := range c.Witness.KnownLogs {
			homeData.Witness.Logs = append(homeData.Witness.Logs, log.Origin)
		}
	}

	handler := reused.NewHandler(mux)
	handler = heavyhitter.NewHandler(handler)
	s := &http.Server{
		Handler:      handler,
		ConnContext:  reused.ConnContext,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
		ErrorLog:     stdlog.HTTPErrorLog,
	}
	if *testCertFlag {
		cert, err := tls.LoadX509KeyPair("sunlight.pem", "sunlight-key.pem")
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
	req.Header.Set("User-Agent", "+https://filippo.io/sunlight")
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

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
