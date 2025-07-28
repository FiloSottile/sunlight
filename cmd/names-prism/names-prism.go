// Command names-prism creates missing names tiles for existing data tiles.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"strings"

	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/stdlog"
)

func main() {
	logger := slog.New(stdlog.Handler)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	root, err := os.OpenRoot(os.Args[1])
	if err != nil {
		fatalError(logger, "failed to open local directory", "err", err)
	}

	var existing, created int
	if err := fs.WalkDir(root.FS(), "tile/data", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		namesPath := "tile/names/" + strings.TrimPrefix(path, "tile/data/")

		if d.IsDir() {
			if path != "tile/data" {
				root.Mkdir(namesPath, 0755)
			}
			return nil
		}

		if _, err := root.Stat(namesPath); err == nil {
			existing++
			return nil
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("%s: %w", path, err)
		}

		dataTile, err := fs.ReadFile(root.FS(), path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		dataTile, err = decompress(dataTile)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		var namesTile []byte
		for len(dataTile) > 0 {
			var e *sunlight.LogEntry
			e, dataTile, err = sunlight.ReadTileLeaf(dataTile)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}

			if tl, err := e.TrimmedEntry(); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			} else if line, err := json.Marshal(tl); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			} else {
				namesTile = append(namesTile, line...)
				namesTile = append(namesTile, '\n')
			}
		}
		namesTile, err = compress(namesTile)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		f, err := root.OpenFile(namesPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0444)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if _, err := f.Write(namesTile); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		created++
		return nil
	}); err != nil {
		logger.Error("failed to walk tile directory", "err", err)
	}

	logger.Info("done", "existing", existing, "created", created)
}

func compress(data []byte) ([]byte, error) {
	b := &bytes.Buffer{}
	w := gzip.NewWriter(b)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

const maxCompressRatio = 100

func decompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	maxSize := int64(len(data)) * maxCompressRatio
	return io.ReadAll(io.LimitReader(r, maxSize))
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
