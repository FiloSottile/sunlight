// Command partial-aftersun deletes partial tiles from a Sunlight local backend
// where a corresponding full tile exists.
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/immutable"
	"filippo.io/sunlight/internal/stdlog"
	"filippo.io/sunlight/internal/witness"
	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"gopkg.in/yaml.v3"
)

type LogConfig struct {
	// ShortName is the short name for the log, used as a metrics and logs label.
	ShortName string

	// LocalDirectory is the path to a local directory where the log will store
	// its data. It must be dedicated to this specific log instance.
	LocalDirectory string
}

func main() {
	flagSet := flag.NewFlagSet("partial-aftersun", flag.ExitOnError)
	configFlag := flagSet.String("c", "sunlight.yaml", "path to the Sunlight config file")
	metricsFlag := flagSet.String("metrics", "", "path of a node_exporter textfile collector file")
	flagSet.Parse(os.Args[1:])

	logger := slog.New(stdlog.Handler)

	yml, err := os.ReadFile(*configFlag)
	if err != nil {
		fatalError(logger, "failed to read config file", "err", err)
	}
	var c struct {
		Logs    []LogConfig
		Witness struct {
			// LocalDirectory is the path to a local directory where the witness
			// will store its public data.
			LocalDirectory string
		}
	}
	if err := yaml.Unmarshal(yml, &c); err != nil {
		fatalError(logger, "failed to parse config file", "err", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var exitCode int
	var stats []*logStats
	for _, lc := range c.Logs {
		if lc.ShortName == "" {
			fatalError(logger, "missing short name for log")
		}
		logger := slog.New(stdlog.Handler.WithAttrs([]slog.Attr{
			slog.String("log", lc.ShortName),
		}))
		st := &logStats{log: lc.ShortName, failed: true}
		stats = append(stats, st)

		if lc.LocalDirectory == "" {
			logger.Error("missing LocalDirectory for log")
			exitCode = 1
			continue
		}
		root, err := os.OpenRoot(lc.LocalDirectory)
		if err != nil {
			logger.Error("failed to open local directory", "err", err)
			exitCode = 1
			continue
		}

		size, err := logSize(root)
		if err != nil {
			root.Close()
			logger.Error("failed to get log size", "err", err)
			exitCode = 1
			continue
		}

		if err := cleanLog(ctx, logger, root, size, sunlight.ParseTilePath, st); err != nil {
			logger.Error("failed to clean log", "err", err)
			exitCode = 1
		}
		root.Close()
	}

	if c.Witness.LocalDirectory != "" {
		dir, err := os.ReadDir(filepath.Join(c.Witness.LocalDirectory, "mirror"))
		if os.IsNotExist(err) {
			logger.DebugContext(ctx, "witness mirror directory does not exist, skipping")
		} else if err != nil {
			fatalError(logger, "failed to read witness mirror directory", "err", err)
		}
		for _, entry := range dir {
			if !entry.IsDir() {
				continue
			}
			logger := slog.New(stdlog.Handler.WithAttrs([]slog.Attr{
				slog.String("log", entry.Name()),
			}))
			st := &logStats{log: entry.Name(), failed: true}

			root, err := os.OpenRoot(filepath.Join(c.Witness.LocalDirectory, "mirror", entry.Name()))
			if err != nil {
				stats = append(stats, st)
				logger.Error("failed to open witness mirror directory", "err", err)
				exitCode = 1
				continue
			}

			size, err := mirroredLogSize(root, entry.Name())
			if errors.Is(err, fs.ErrNotExist) {
				root.Close()
				logger.DebugContext(ctx, "mirror checkpoint does not exist yet, skipping")
				continue
			}
			stats = append(stats, st)
			if err != nil {
				root.Close()
				logger.Error("failed to get mirrored log size", "err", err)
				exitCode = 1
				continue
			}

			if err := cleanLog(ctx, logger, root, size, torchwood.ParseTilePath, st); err != nil {
				logger.Error("failed to clean mirrored log", "err", err)
				exitCode = 1
			}
			root.Close()
		}
	}

	var files, dirs, bytes int64
	for _, st := range stats {
		files += st.files
		dirs += st.dirs
		bytes += st.bytes
	}
	logger.Info("done", "files", files, "dirs", dirs, "bytes", bytes)

	if *metricsFlag != "" {
		if err := writeMetrics(*metricsFlag, stats); err != nil {
			logger.Error("failed to write metrics", "err", err)
			exitCode = 1
		}
	}
	os.Exit(exitCode)
}

// logStats is what a run removed from one log, and how long it took.
type logStats struct {
	log     string
	files   int64
	dirs    int64
	bytes   int64
	elapsed time.Duration
	failed  bool
}

// cleanLog removes the redundant partial tiles of every level of a log, and
// records the outcome in st. The tile directory is created by the first upload,
// so it is allowed to be missing only while the tree is empty.
func cleanLog(ctx context.Context, logger *slog.Logger, root *os.Root, size int64, parseTilePath func(path string) (tlog.Tile, error), st *logStats) (err error) {
	start := time.Now()
	defer func() {
		st.elapsed = time.Since(start)
		st.failed = err != nil
	}()

	levels, err := readDirNames(root, "tile")
	if os.IsNotExist(err) && size == 0 {
		logger.DebugContext(ctx, "empty log has no tile directory yet, skipping")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read tile directory: %w", err)
	}
	for _, level := range levels {
		name := filepath.Join("tile", level)
		if err := cleanDir(ctx, logger, root, name, size, parseTilePath, st); err != nil {
			return fmt.Errorf("failed to clean directory %s: %w", name, err)
		}
	}
	return nil
}

// writeMetrics writes the per-log statistics of this run as Prometheus gauges
// for the node_exporter textfile collector. The file is replaced atomically
// through a temporary name that does not end in .prom, so the collector never
// sees a partially written file.
func writeMetrics(path string, stats []*logStats) error {
	var b bytes.Buffer
	labelEscaper := strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"")
	gauge := func(name, help string, value func(*logStats) any) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
		for _, st := range stats {
			fmt.Fprintf(&b, "%s{log=\"%s\"} %v\n", name, labelEscaper.Replace(st.log), value(st))
		}
	}
	gauge("partial_aftersun_removed_files", "Partial tile files removed in the last run.",
		func(st *logStats) any { return st.files })
	gauge("partial_aftersun_removed_dirs", "Partial tile directories removed in the last run.",
		func(st *logStats) any { return st.dirs })
	gauge("partial_aftersun_removed_bytes", "Apparent size of the files and directories removed in the last run.",
		func(st *logStats) any { return st.bytes })
	gauge("partial_aftersun_duration_seconds", "Time spent walking and cleaning the log in the last run.",
		func(st *logStats) any { return st.elapsed.Seconds() })
	gauge("partial_aftersun_success", "Whether the last run cleaned the log without errors.",
		func(st *logStats) any {
			if st.failed {
				return 0
			}
			return 1
		})

	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b.Bytes()); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func cleanDir(ctx context.Context, logger *slog.Logger, root *os.Root, prefix string, size int64, parseTilePath func(path string) (tlog.Tile, error), st *logStats) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entries, err := readDirNames(root, prefix)
	if err != nil {
		return err
	}
	names := make(map[string]bool, len(entries))
	for _, entry := range entries {
		names[entry] = true
	}
	for _, entry := range entries {
		name := filepath.Join(prefix, entry)

		if strings.HasPrefix(entry, "x") {
			if err := cleanDir(ctx, logger, root, name, size, parseTilePath, st); err != nil {
				return err
			}
			continue
		}

		// First level of safety: never delete a partial tile that doesn't have
		// a corresponding full tile.
		full, ok := strings.CutSuffix(entry, ".p")
		if !ok {
			continue
		}
		if !names[full] {
			continue
		}

		// Second level of safety: never delete a partial tile at the right edge
		// of the tree.
		t, err := parseTilePath(strings.TrimSuffix(name, ".p"))
		if err != nil {
			return fmt.Errorf("failed to parse tile path %s: %w", name, err)
		}
		tileSize := int64(1) << (sunlight.TileHeight * (max(0, t.L) + 1))
		if t.N >= size/tileSize {
			continue
		}

		partials, err := readDirNames(root, name)
		if err != nil {
			return err
		}
		for _, partial := range partials {
			name := filepath.Join(prefix, entry, partial)

			// Third level of safety: never delete a non-partial tile.
			t, err := parseTilePath(name)
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
			st.files++
			i, err := root.Lstat(name)
			if err != nil {
				return err
			}
			st.bytes += i.Size()
			if err := root.Remove(name); err != nil {
				return err
			}
		}
		logger.DebugContext(ctx, "removing dir", "name", name)
		st.dirs++
		i, err := root.Lstat(name)
		if err != nil {
			return err
		}
		st.bytes += i.Size()
		if err := root.Remove(name); err != nil {
			return err
		}
	}
	return nil
}

// readDirNames returns the sorted names of the entries of the named directory.
//
// It deliberately avoids fs.ReadDir on root.FS(): for directories opened
// through an os.Root, the os package ignores the d_type reported by the
// filesystem and eagerly lstat()s every entry to populate DirEntry.Info. On a
// log with millions of tiles, that instantiates a dentry and inode for every
// tile on each run, which on ZFS pins enough metadata to starve the ARC.
// Readdirnames never stats, so callers stat only the few entries they delete.
func readDirNames(root *os.Root, name string) ([]string, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	return names, nil
}

func overrideImmutable(root *os.Root, name string) error {
	// Fourth level of safety: refuse to make a partial tile mutable if there
	// isn't a full tile, which is checked through a *different* mechanism.
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

type logInfo struct {
	Name         string `json:"description"`
	PublicKeyDER []byte `json:"key"`
}

func logSize(root *os.Root) (int64, error) {
	logJSON, err := fs.ReadFile(root.FS(), "log.v3.json")
	if err != nil {
		return 0, fmt.Errorf("failed to read log.v3.json: %w", err)
	}
	var log logInfo
	if err := json.Unmarshal(logJSON, &log); err != nil {
		return 0, fmt.Errorf("failed to parse log.v3.json: %w", err)
	}
	pubKey, err := x509.ParsePKIXPublicKey(log.PublicKeyDER)
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
		return 0, fmt.Errorf("origin mismatch: %q != %q", checkpoint.Origin, log.Name)
	}
	return checkpoint.N, nil
}

func mirroredLogSize(root *os.Root, originHash string) (int64, error) {
	signedCheckpoint, err := fs.ReadFile(root.FS(), "checkpoint")
	if err != nil {
		return 0, fmt.Errorf("failed to read checkpoint: %w", err)
	}
	sep := bytes.Index(signedCheckpoint, []byte("\n\n"))
	if sep == -1 {
		return 0, fmt.Errorf("invalid checkpoint format")
	}
	checkpoint, err := torchwood.ParseCheckpoint(string(signedCheckpoint[:sep+1]))
	if err != nil {
		return 0, fmt.Errorf("failed to parse checkpoint: %w", err)
	}
	if exp := witness.OriginHash(checkpoint.Origin); exp != originHash {
		return 0, fmt.Errorf("origin hash mismatch: %q != %q", exp, originHash)
	}
	return checkpoint.N, nil
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
