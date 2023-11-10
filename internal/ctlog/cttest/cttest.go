package cttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"testing"

	"filippo.io/litetlog/internal/ctlog"
)

type TestLog struct {
	Log     *ctlog.Log
	Backend *MemoryBackend
	Key     *ecdsa.PrivateKey
}

func NewEmptyTestLog(t testing.TB) *TestLog {
	backend := NewMemoryBackend(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	log, err := ctlog.NewLog("example.com/TestLog", key, backend)
	if err != nil {
		t.Fatal(err)
	}
	return &TestLog{
		Log:     log,
		Backend: backend,
		Key:     key,
	}
}

type MemoryBackend struct {
	t  testing.TB
	mu sync.Mutex
	m  map[string][]byte
}

func NewMemoryBackend(t testing.TB) *MemoryBackend {
	return &MemoryBackend{
		t: t, m: make(map[string][]byte),
	}
}

func (b *MemoryBackend) Upload(ctx context.Context, key string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.m[key] = data
	return nil
}
