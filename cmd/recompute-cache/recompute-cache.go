// Command recompute-cache adds entries to the cache for all entries in a
// Sunlight log. If the backend is a local directory, it will be used directly,
// otherwise the HTTPS monitoring prefix will be used. This can run in parallel
// with production.
package main

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"filippo.io/keygen"
	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/stdlog"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
	"gopkg.in/yaml.v3"
)

type LogConfig struct {
	// ShortName is the short name for the log, used as a metrics and logs label.
	ShortName string

	// MonitoringPrefix is the full URL of the c2sp.org/static-ct-api monitoring
	// prefix of the log.
	MonitoringPrefix string

	// Secret is the path to a file containing a secret seed from which the
	// log's private keys are derived. The file contents are used as HKDF input.
	// It must be exactly 32 bytes long.
	//
	// To generate a new seed, run:
	//
	//   $ sunlight-keygen -f seed.bin
	//
	Secret string

	// Cache is the path to the SQLite deduplication cache file. It will be
	// created if it doesn't already exist.
	Cache string

	// LocalDirectory is the path to a local directory where the log will store
	// its data. It must be dedicated to this specific log instance. It will
	// be created if it doesn't already exist.
	//
	// Only one of S3Bucket or LocalDirectory can be set at the same time.
	LocalDirectory string
}

func main() {
	flagSet := flag.NewFlagSet("recompute-cache", flag.ExitOnError)
	configFlag := flagSet.String("c", "sunlight.yaml", "path to the Sunlight config file")
	logNameFlag := flagSet.String("log", "", "short name of the log to recompute cache for")
	flagSet.Parse(os.Args[1:])

	if *logNameFlag == "" {
		flagSet.Usage()
		os.Exit(1)
	}

	logger := slog.New(stdlog.Handler)

	yml, err := os.ReadFile(*configFlag)
	if err != nil {
		fatalError(logger, "failed to read config file", "err", err)
	}
	var config struct {
		Logs []LogConfig
	}
	if err := yaml.Unmarshal(yml, &config); err != nil {
		fatalError(logger, "failed to parse config file", "err", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var lc *LogConfig
	for _, l := range config.Logs {
		if l.ShortName == "" {
			fatalError(logger, "missing short name for log")
		}
		if l.ShortName != *logNameFlag {
			continue
		}
		if l.Secret == "" {
			fatalError(logger, "missing secret for log", "log", l.ShortName)
		}
		if l.Cache == "" {
			fatalError(logger, "missing cache path for log", "log", l.ShortName)
		}
		lc = &l
		break
	}
	if lc == nil {
		fatalError(logger, "log not found in config", "log", *logNameFlag)
	}

	logger = slog.New(stdlog.Handler.WithAttrs([]slog.Attr{
		slog.String("log", lc.ShortName),
	}))

	var pubKey crypto.PublicKey
	{
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

		pubKey = k.Public()
	}

	writeConn, err := sqlite.OpenConn(lc.Cache, 0)
	if err != nil {
		fatalError(logger, "failed to open cache database", "err", err)
	}
	if err := sqlitex.ExecTransient(writeConn,
		`PRAGMA synchronous = NORMAL;`, nil); err != nil {
		writeConn.Close()
		fatalError(logger, "failed to set PRAGMA synchronous", "err", err)
	}
	if err := sqlitex.ExecTransient(writeConn, `
		CREATE TABLE IF NOT EXISTS cache256 (
			key BLOB PRIMARY KEY,
			timestamp INTEGER NOT NULL,
			leaf_index INTEGER NOT NULL
		) WITHOUT ROWID, STRICT;`, nil); err != nil {
		writeConn.Close()
		fatalError(logger, "failed to create cache table", "err", err)
	}

	cc := &sunlight.ClientConfig{
		UserAgent: "recompute-cache (+https://filippo.io/sunlight)",
		PublicKey: pubKey,
		Logger:    logger,
	}
	if lc.LocalDirectory != "" {
		cc.MonitoringPrefix = "gzip+file://" + lc.LocalDirectory
	} else {
		cc.MonitoringPrefix = lc.MonitoringPrefix
	}
	client, err := sunlight.NewClient(cc)
	if err != nil {
		fatalError(logger, "failed to create client", "err", err)
	}

	checkpoint, _, err := client.Checkpoint(ctx)
	if err != nil {
		fatalError(logger, "failed to get checkpoint", "err", err)
	}
	lastReport, lastDone := time.Now(), int64(0)
	// Intentionally not using AllEntries here: a single partial tile of
	// duplicates is not the end of the world, and the partial tile might be
	// gone (reaped by partial-aftersun) by the time we get to it.
	for i, se := range client.Entries(ctx, checkpoint.Tree, 0) {
		if err := ctx.Err(); err != nil {
			fatalError(logger, "interrupted", "err", err)
		}
		if se.LeafIndex != i {
			fatalError(logger, "unexpected leaf index", "expected", i, "got", se.LeafIndex)
		}
		h := computeCacheHash(se.Certificate, se.IsPrecert, se.IssuerKeyHash)
		err := sqlitex.Exec(writeConn, "INSERT OR IGNORE INTO cache256 "+
			"(key, timestamp, leaf_index) VALUES (?, ?, ?)",
			nil, h[:], se.Timestamp, se.LeafIndex)
		if err != nil {
			fatalError(logger, "failed to insert cache entry", "err", err, "index", i)
		}

		if now := time.Now(); now.Sub(lastReport) >= 10*time.Second {
			logProgress(logger, lastDone, lastReport, i+1, now, checkpoint.N)
			lastDone = i + 1
			lastReport = now
		}
	}
	if err := client.Err(); err != nil {
		fatalError(logger, "failed to iterate entries", "err", err)
	}

	if err := writeConn.Close(); err != nil {
		fatalError(logger, "failed to close cache database", "err", err)
	}

	logger.Info("cache recomputation completed successfully")
}

func logProgress(logger *slog.Logger, lastDone int64, lastReport time.Time, done int64, now time.Time, total int64) {
	elapsed := now.Sub(lastReport)
	rate := float64(done-lastDone) / elapsed.Seconds()
	var eta time.Duration
	if rate > 0 {
		eta = time.Duration(float64(total-done)/rate) * time.Second
	}
	logger.Info("recomputing cache",
		"done", done,
		"total", total,
		"progress", fmt.Sprintf("%.1f%%", float64(done)/float64(total)*100),
		"rate", fmt.Sprintf("%.0f/s", rate),
		"eta", eta.Round(time.Second).String(),
	)
}

type cacheHash [32]byte

func computeCacheHash(Certificate []byte, IsPrecert bool, IssuerKeyHash [32]byte) cacheHash {
	b := &cryptobyte.Builder{}
	if !IsPrecert {
		b.AddUint16(0 /* entry_type = x509_entry */)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(Certificate)
		})
	} else {
		b.AddUint16(1 /* entry_type = precert_entry */)
		b.AddBytes(IssuerKeyHash[:])
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(Certificate)
		})
	}
	return cacheHash(sha256.Sum256(b.BytesOrPanic()))
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
