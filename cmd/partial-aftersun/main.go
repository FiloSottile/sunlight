// Command partial-aftersun deletes partial tiles from a Sunlight local backend
// where a corresponding full tile exists.
package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/immutable"
	"filippo.io/sunlight/internal/stdlog"
	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"gopkg.in/yaml.v3"
)

type LogConfig struct {
	// Name is the fully qualified log name for the checkpoint origin line.
	Name string

	// ShortName is the short name for the log, used as a metrics and logs label.
	ShortName string

	// PublicKey is the SubjectPublicKeyInfo for this log, base64 encoded.
	PublicKey string

	// LocalDirectory is the path to a local directory where the log will store
	// its data. It must be dedicated to this specific log instance.
	LocalDirectory string
}

func main() {
	flagSet := flag.NewFlagSet("partial-aftersun", flag.ExitOnError)
	configFlag := flagSet.String("c", "sunlight.yaml", "path to the Sunlight config file")
	flagSet.Parse(os.Args[1:])

	logger := slog.New(stdlog.Handler)

	yml, err := os.ReadFile(*configFlag)
	if err != nil {
		fatalError(logger, "failed to read config file", "err", err)
	}
	var c struct {
		Logs []LogConfig
	}
	if err := yaml.Unmarshal(yml, &c); err != nil {
		fatalError(logger, "failed to parse config file", "err", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var exitCode int
	for _, lc := range c.Logs {
		if lc.ShortName == "" {
			fatalError(logger, "missing short name for log")
		}
		logger := slog.New(stdlog.Handler.WithAttrs([]slog.Attr{
			slog.String("log", lc.ShortName),
		}))

		if lc.LocalDirectory == "" {
			fatalError(logger, "missing LocalDirectory for log")
		}
		root, err := os.OpenRoot(lc.LocalDirectory)
		if err != nil {
			fatalError(logger, "failed to open local directory", "err", err)
		}

		size, err := logSize(root, &lc)
		if err != nil {
			fatalError(logger, "failed to get log size", "err", err)
		}

		levels, err := fs.ReadDir(root.FS(), "tile")
		if os.IsNotExist(err) {
			logger.DebugContext(ctx, "tile directory does not exist, skipping")
			continue
		}
		if err != nil {
			fatalError(logger, "failed to read tile directory", "err", err)
		}
		for _, level := range levels {
			name := filepath.Join("tile", level.Name())
			if err := cleanDir(ctx, logger, root, name, size); err != nil {
				logger.Error("failed to clean directory", "name", name, "err", err)
				exitCode = 1
				break
			}
		}
	}

	logger.Info("done", "files", removedFiles, "dirs", removedDirs, "bytes", removedBytes)
	os.Exit(exitCode)
}

var removedFiles int64
var removedDirs int64
var removedBytes int64

func cleanDir(ctx context.Context, logger *slog.Logger, root *os.Root, prefix string, size int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := fs.ReadDir(root.FS(), prefix)
	if err != nil {
		return err
	}
	names := make(map[string]fs.DirEntry, len(entries))
	for _, entry := range entries {
		names[entry.Name()] = entry
	}
	for _, entry := range entries {
		name := filepath.Join(prefix, entry.Name())

		if strings.HasPrefix(entry.Name(), "x") {
			if err := cleanDir(ctx, logger, root, name, size); err != nil {
				return err
			}
			continue
		}

		// First level of safety: never delete a partial tile that doesn't have
		// a corresponding full tile.
		full, ok := strings.CutSuffix(entry.Name(), ".p")
		if !ok {
			continue
		}
		if _, ok := names[full]; !ok {
			continue
		}

		// Second level of safety: never delete a partial tile at the right edge
		// of the tree.
		t, err := sunlight.ParseTilePath(strings.TrimSuffix(name, ".p"))
		if err != nil {
			return fmt.Errorf("failed to parse tile path %s: %w", name, err)
		}
		tileSize := int64(1) << (sunlight.TileHeight * (max(0, t.L) + 1))
		if t.N >= size/tileSize {
			continue
		}

		partials, err := fs.ReadDir(root.FS(), name)
		if err != nil {
			return err
		}
		for _, partial := range partials {
			name := filepath.Join(prefix, entry.Name(), partial.Name())

			// Third level of safety: never delete a non-partial tile.
			t, err := sunlight.ParseTilePath(name)
			if err != nil {
				return fmt.Errorf("failed to parse tile path %s: %w", name, err)
			}
			if t.W == sunlight.TileWidth {
				return fmt.Errorf("%s is not a partial tile", name)
			}

			if err := overrideImmutable(root, name); err != nil {
				return fmt.Errorf("failed to override immutable flag for %s: %w", name, err)
			}
			logger.DebugContext(ctx, "removing partial", "name", name)
			removedFiles++
			i, err := partial.Info()
			if err != nil {
				return err
			}
			removedBytes += i.Size()
			if err := root.Remove(name); err != nil {
				return err
			}
		}
		logger.DebugContext(ctx, "removing dir", "name", name)
		removedDirs++
		i, err := entry.Info()
		if err != nil {
			return err
		}
		removedBytes += i.Size()
		if err := root.Remove(name); err != nil {
			return err
		}
	}
	return nil
}

func overrideImmutable(root *os.Root, name string) error {
	// Fourth level of safety: refuse to make a partial tile if there isn't a
	// full tile, which is checked through a *different* mechanism.
	full, size, ok := strings.Cut(name, ".p/")
	if !ok {
		return fmt.Errorf("failed to parse partial tile path %s", name)
	}
	if _, err := strconv.Atoi(size); err != nil {
		return fmt.Errorf("failed to parse partial tile size %s: %w", size, err)
	}
	if fi, err := root.Stat(full); err != nil {
		return fmt.Errorf("failed to stat full tile %s: %w", full, err)
	} else if fi.IsDir() {
		return fmt.Errorf("full tile %s is a directory", full)
	} else if fi.Size() == 0 {
		return fmt.Errorf("full tile %s is empty", full)
	}

	f, err := root.Open(name)
	if err != nil {
		return err
	}
	immutable.Unset(f)
	return f.Close()
}

func logSize(root *os.Root, log *LogConfig) (int64, error) {
	cfgPubKey, err := base64.StdEncoding.DecodeString(log.PublicKey)
	if err != nil {
		return 0, fmt.Errorf("failed to parse public key base64: %w", err)
	}
	pubKey, err := x509.ParsePKIXPublicKey(cfgPubKey)
	if err != nil {
		return 0, fmt.Errorf("failed to parse public key: %w", err)
	}
	verifier, err := sunlight.NewRFC6962Verifier(log.Name, pubKey)
	if err != nil {
		return 0, fmt.Errorf("failed to create verifier: %w", err)
	}
	signedCheckpoint, err := fs.ReadFile(root.FS(), "checkpoint")
	if err != nil {
		return 0, fmt.Errorf("failed to read checkpoint: %w", err)
	}
	n, err := note.Open(signedCheckpoint, note.VerifierList(verifier))
	if err != nil {
		return 0, fmt.Errorf("failed to verify checkpoint note: %w", err)
	}
	checkpoint, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return 0, fmt.Errorf("failed to parse checkpoint: %w", err)
	}
	if checkpoint.Origin != log.Name {
		return 0, fmt.Errorf("origin mismatch: %s != %s", checkpoint.Origin, log.Name)
	}
	t, err := sunlight.RFC6962SignatureTimestamp(n.Sigs[0])
	if err != nil {
		return 0, fmt.Errorf("failed to parse signature timestamp: %w", err)
	}
	if ct := time.UnixMilli(t); time.Since(ct) > 5*time.Second {
		return 0, fmt.Errorf("checkpoint is too old: %v", ct)
	}
	return checkpoint.N, nil
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
