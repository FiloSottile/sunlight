package ctlog

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// LocalFilesystemBackend is a backend that stores key-value pairs in the
// local filesystem.
// The keys are base64-encoded and the values are stored in files named after
// the base64-encoded key.
//
// This is not meant to be used in production, but rather for testing and
// development purposes.
type LocalFilesystemBackend struct {
	mu       *sync.RWMutex
	rootPath string
}

func NewLocalBackend(path string) (*LocalFilesystemBackend, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			if err = os.MkdirAll(path, 0755); err != nil {
				return nil, fmt.Errorf("failed to create directory %s: %w", path, err)
			}
		} else {
			return nil, fmt.Errorf("failed to check if directory %s exists: %w", path, err)
		}
	}

	return &LocalFilesystemBackend{
		mu:       &sync.RWMutex{},
		rootPath: path,
	}, nil
}

// Upload saves the data associated to the key in the local filesystem.
// Note well: upload options are not handled
func (b *LocalFilesystemBackend) Upload(ctx context.Context, key string, data []byte, opts *UploadOptions) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	filename := keyToFilename(b.rootPath, key)
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to save key %s to file %s: %w", key, filename, err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("failed to write contents of key %s to file %s: %w", key, filename, err)
	}
	return nil
}

func (b *LocalFilesystemBackend) Fetch(ctx context.Context, key string) ([]byte, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	filename := keyToFilename(b.rootPath, key)

	data, err := os.ReadFile(filename)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to read contents of file %s associated to key %s: %w", filename, key, err)
	}

	return data, nil
}

func (b *LocalFilesystemBackend) Metrics() []prometheus.Collector {
	return []prometheus.Collector{}
}

func keyToFilename(rootPath, key string) string {
	return path.Join(rootPath, base64.StdEncoding.EncodeToString([]byte(key)))
}
