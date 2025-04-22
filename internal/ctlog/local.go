package ctlog

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"filippo.io/sunlight/internal/durable"
	"github.com/prometheus/client_golang/prometheus"
)

type LocalBackend struct {
	dir     string
	metrics []prometheus.Collector
	log     *slog.Logger
}

func NewLocalBackend(ctx context.Context, dir string, l *slog.Logger) (*LocalBackend, error) {
	if fi, err := os.Stat(dir); err != nil {
		return nil, fmtErrorf("failed to stat local backend directory %q: %w", dir, err)
	} else if !fi.IsDir() {
		return nil, fmtErrorf("local backend path %q is not a directory", dir)
	}
	return &LocalBackend{
		dir:     dir,
		metrics: []prometheus.Collector{},
		log:     l,
	}, nil
}

var _ Backend = &LocalBackend{}

func (s *LocalBackend) Upload(ctx context.Context, key string, data []byte, opts *UploadOptions) error {
	start := time.Now()
	name, err := filepath.Localize(key)
	if err != nil {
		return fmtErrorf("failed to localize key %q as a filesystem path: %w", key, err)
	}
	path := filepath.Join(s.dir, name)
	if err := durable.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmtErrorf("failed to create directory %q: %w", filepath.Dir(path), err)
	}
	var perms os.FileMode = 0644
	if opts != nil && opts.Immutable {
		perms = 0444
	}
	err = durable.WriteFile(path, data, perms)
	s.log.DebugContext(ctx, "local file write", "key", key, "size", len(data),
		"path", path, "perms", perms, "elapsed", time.Since(start), "err", err)
	return err
}

func (s *LocalBackend) Fetch(ctx context.Context, key string) ([]byte, error) {
	name, err := filepath.Localize(key)
	if err != nil {
		return nil, fmtErrorf("failed to localize key %q as a filesystem path: %w", key, err)
	}
	path := filepath.Join(s.dir, name)
	s.log.DebugContext(ctx, "local file read", "key", key, "path", path)
	return os.ReadFile(path)
}

func (s *LocalBackend) Metrics() []prometheus.Collector {
	return s.metrics
}
