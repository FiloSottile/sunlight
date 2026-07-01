package ctlog

import (
	"path/filepath"
	"testing"

	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"filippo.io/sunlight"
)

const legacyCacheSchema = `CREATE TABLE cache (
	key BLOB PRIMARY KEY,
	timestamp INTEGER NOT NULL,
	leaf_index INTEGER NOT NULL
) WITHOUT ROWID, STRICT;`

func cacheRowCount(t *testing.T, conn *sqlite.Conn, table string) int64 {
	t.Helper()
	var n int64
	if err := sqlitex.ExecTransient(conn, "SELECT COUNT(*) AS n FROM "+table,
		func(stmt *sqlite.Stmt) error { n = stmt.GetInt64("n"); return nil }); err != nil {
		t.Fatalf("counting rows in %q: %v", table, err)
	}
	return n
}

// TestCacheNewEntriesUse256BitTable verifies that cachePut writes full-length
// 256-bit keys to cache256 and never to the truncated 128-bit "cache" table,
// even while the legacy table is still present mid-migration. This is the
// property that defeats the offline collision attack: an attacker can no longer
// plant an entry under a 128-bit key, so the only entries with truncated keys
// are the frozen honest ones predating the upgrade.
func TestCacheNewEntriesUse256BitTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.db")

	// Simulate a mid-migration database that still carries the legacy table
	// with one pre-existing row.
	func() {
		conn, err := sqlite.OpenConn(path, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := sqlitex.ExecTransient(conn, legacyCacheSchema, nil); err != nil {
			t.Fatal(err)
		}
		if err := sqlitex.Exec(conn, "INSERT INTO cache (key, timestamp, leaf_index) VALUES (?, ?, ?)",
			nil, make([]byte, 16), int64(1), int64(0)); err != nil {
			t.Fatal(err)
		}
	}()

	rc, wc, err := initCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	defer wc.Close()
	legacy, err := cacheLegacy(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !legacy {
		t.Fatal("legacy cache table was not detected")
	}
	l := &Log{cacheRead: rc, cacheWrite: wc, cacheLegacy: legacy}

	if err := l.cachePut([]*sunlight.LogEntry{{
		Certificate: []byte("new-entry"),
		LeafIndex:   42,
		Timestamp:   1234,
	}}); err != nil {
		t.Fatal(err)
	}

	// The new entry round-trips through cache256.
	got, err := l.cacheGet(&PendingLogEntry{Certificate: []byte("new-entry")})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.LeafIndex != 42 || got.Timestamp != 1234 {
		t.Fatalf("cache256 round-trip: got %+v, want index 42 timestamp 1234", got)
	}

	// It landed in cache256, with a full 32-byte key.
	if n := cacheRowCount(t, rc, "cache256"); n != 1 {
		t.Errorf("cache256 has %d rows, want 1", n)
	}
	var keyLen int64
	if err := sqlitex.ExecTransient(rc, "SELECT length(key) AS n FROM cache256",
		func(stmt *sqlite.Stmt) error { keyLen = stmt.GetInt64("n"); return nil }); err != nil {
		t.Fatal(err)
	}
	if keyLen != 32 {
		t.Errorf("cache256 key is %d bytes, want 32", keyLen)
	}

	// The legacy table was left untouched: the new entry did not end up there.
	if n := cacheRowCount(t, rc, "cache"); n != 1 {
		t.Errorf("legacy cache table has %d rows, want 1 (new entries must not be written to it)", n)
	}
}

// TestCacheLegacyFallback verifies that an entry present only in the legacy
// 128-bit table is still deduplicated, via the truncated-key fallback, so
// upgrading doesn't cause a wave of cache misses.
func TestCacheLegacyFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.db")

	cert := []byte("legacy-entry")
	h := computeCacheHash(cert, false, [32]byte{})

	func() {
		conn, err := sqlite.OpenConn(path, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := sqlitex.ExecTransient(conn, legacyCacheSchema, nil); err != nil {
			t.Fatal(err)
		}
		// Keyed by the truncation of the same hash cacheGet computes.
		if err := sqlitex.Exec(conn, "INSERT INTO cache (key, timestamp, leaf_index) VALUES (?, ?, ?)",
			nil, h[:16], int64(111), int64(7)); err != nil {
			t.Fatal(err)
		}
	}()

	rc, wc, err := initCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	defer wc.Close()
	legacy, err := cacheLegacy(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !legacy {
		t.Fatal("legacy cache table was not detected")
	}
	l := &Log{cacheRead: rc, cacheWrite: wc, cacheLegacy: legacy}

	got, err := l.cacheGet(&PendingLogEntry{Certificate: cert})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected a cache hit from the legacy table, got a miss")
	}
	if got.LeafIndex != 7 || got.Timestamp != 111 {
		t.Errorf("legacy hit returned index %d timestamp %d, want 7/111", got.LeafIndex, got.Timestamp)
	}

	// The legacy hit is served from the legacy table; it is not promoted into
	// cache256 (operators migrate in bulk via cmd/recompute-cache).
	if n := cacheRowCount(t, rc, "cache256"); n != 0 {
		t.Errorf("cache256 has %d rows, want 0 (legacy hits are not promoted)", n)
	}
}

// TestCacheLegacyTableDroppedMidRun verifies that if the legacy table is
// dropped while the log is running (an operator finishing the migration after
// running cmd/recompute-cache), cacheGet degrades to a miss instead of
// erroring, and disables the fallback so later lookups skip it.
func TestCacheLegacyTableDroppedMidRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.db")

	func() {
		conn, err := sqlite.OpenConn(path, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := sqlitex.ExecTransient(conn, legacyCacheSchema, nil); err != nil {
			t.Fatal(err)
		}
	}()

	rc, wc, err := initCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	defer wc.Close()
	legacy, err := cacheLegacy(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !legacy {
		t.Fatal("legacy cache table was not detected")
	}
	l := &Log{cacheRead: rc, cacheWrite: wc, cacheLegacy: legacy}

	// Drop the legacy table out from under the running log, on another
	// connection, as an external sqlite3 process would.
	if err := sqlitex.ExecTransient(wc, "DROP TABLE cache;", nil); err != nil {
		t.Fatal(err)
	}

	got, err := l.cacheGet(&PendingLogEntry{Certificate: []byte("anything")})
	if err != nil {
		t.Fatalf("cacheGet errored after the legacy table was dropped: %v", err)
	}
	if got != nil {
		t.Errorf("expected a cache miss, got index %d", got.LeafIndex)
	}
	if l.cacheLegacy {
		t.Error("cacheLegacy should be false after the legacy table disappeared")
	}

	// It keeps working on the next call, now skipping the fallback entirely.
	if _, err := l.cacheGet(&PendingLogEntry{Certificate: []byte("anything-else")}); err != nil {
		t.Fatalf("cacheGet errored on a subsequent call: %v", err)
	}
}
