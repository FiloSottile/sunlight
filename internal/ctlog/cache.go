package ctlog

import (
	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"filippo.io/sunlight"
	"github.com/prometheus/client_golang/prometheus"
)

func initCache(path string) (readConn, writeConn *sqlite.Conn, err error) {
	writeConn, err = sqlite.OpenConn(path, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := sqlitex.ExecTransient(writeConn,
		`PRAGMA synchronous = NORMAL;`, nil); err != nil {
		writeConn.Close()
		return nil, nil, err
	}
	if err := sqlitex.ExecTransient(writeConn, `
		CREATE TABLE IF NOT EXISTS cache256 (
			key BLOB PRIMARY KEY,
			timestamp INTEGER NOT NULL,
			leaf_index INTEGER NOT NULL
		) WITHOUT ROWID, STRICT;`, nil); err != nil {
		writeConn.Close()
		return nil, nil, err
	}
	readConn, err = sqlite.OpenConn(path, 0)
	if err != nil {
		writeConn.Close()
		return nil, nil, err
	}
	return readConn, writeConn, nil
}

// cacheLegacy reports whether the pre-v0.8.1 128-bit "cache" table is present
// in the database, in which case cacheGet falls back to it on a cache256 miss.
func cacheLegacy(conn *sqlite.Conn) (exists bool, err error) {
	err = sqlitex.ExecTransient(conn,
		`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'cache';`,
		func(stmt *sqlite.Stmt) error { exists = true; return nil })
	return
}

func (l *Log) CloseCache() error {
	if err := l.cacheRead.Close(); err != nil {
		return err
	}
	return l.cacheWrite.Close()
}

func (l *Log) cacheGet(leaf *PendingLogEntry) (*sunlight.LogEntry, error) {
	defer prometheus.NewTimer(l.m.CacheGetDuration).ObserveDuration()
	h := computeCacheHash(leaf.Certificate, leaf.IsPrecert, leaf.IssuerKeyHash)
	var se *sunlight.LogEntry
	err := sqlitex.Exec(l.cacheRead, "SELECT timestamp, leaf_index FROM cache256 WHERE key = ?",
		func(stmt *sqlite.Stmt) error {
			se = leaf.asLogEntry(stmt.GetInt64("leaf_index"), stmt.GetInt64("timestamp"))
			return nil
		}, h[:])
	if err != nil {
		return nil, err
	}
	// Through v0.8.0, the cache was using 128-bit keys. (This allowed an
	// offline collision attack if the attacker could get predictable
	// TBSCertificates signed, which in practice requires a colluding,
	// compromised, or separately vulnerable CA, due to serial number entropy.)
	//
	// If we don't find a 256-bit key, try the 128-bit key, to avoid a wave of
	// cache misses when upgrading from v0.8.0 (or earlier) to v0.8.1 (or later).
	//
	// This is relatively safe because a collision attack requires control over
	// both entries. Either the attack was executed in the past, in which case
	// the attacker already obtained a forged SCT, or the existing 128-bit keys
	// are honest. With approximately 2³² entries in the cache, a multi-target
	// second preimage attack would require 2⁹⁶ work.
	//
	// Anyway, for extra safety operators can optionally run cmd/recompute-cache
	// to rebuild the cache from the backend storage, and then run
	//
	//    sqlite3 <cache.db> "ALTER TABLE cache RENAME TO cache_legacy;"
	//
	// This is safe to run concurrently with the log.
	if se == nil && l.cacheLegacy {
		err = sqlitex.Exec(l.cacheRead, "SELECT timestamp, leaf_index FROM cache WHERE key = ?",
			func(stmt *sqlite.Stmt) error {
				se = leaf.asLogEntry(stmt.GetInt64("leaf_index"), stmt.GetInt64("timestamp"))
				return nil
			}, h[:16])
		if err != nil {
			// An operator might DROP the legacy table while the log is running
			// (but note that this is a long write tx, so it will probably stall
			// submissions). If it's gone, disable the fallback. (cacheGet runs
			// under l.poolMu to use cacheRead already.)
			if exists, checkErr := cacheLegacy(l.cacheRead); checkErr != nil || exists {
				return nil, err
			}
			l.cacheLegacy = false
		}
	}
	return se, nil
}

func (l *Log) cachePut(entries []*sunlight.LogEntry) (err error) {
	defer prometheus.NewTimer(l.m.CachePutDuration).ObserveDuration()
	defer sqlitex.Save(l.cacheWrite)(&err)
	for _, se := range entries {
		h := computeCacheHash(se.Certificate, se.IsPrecert, se.IssuerKeyHash)
		err := sqlitex.Exec(l.cacheWrite, "INSERT INTO cache256 (key, timestamp, leaf_index) VALUES (?, ?, ?)",
			nil, h[:], se.Timestamp, se.LeafIndex)
		if err != nil {
			return err
		}
	}
	return nil
}
