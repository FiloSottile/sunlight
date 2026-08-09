package ctlog

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"filippo.io/sunlight"
	"github.com/prometheus/client_golang/prometheus"
)

func initCache(log *slog.Logger, path string) (readConn, writeConn *sqlite.Conn, err error) {
	writeConn, err = sqlite.OpenConn(path, 0)
	if err != nil {
		return nil, nil, err
	}
	// On ZFS, transaction groups commit atomically and in order, so
	// synchronous=OFF doesn't corrupt the database, and it makes checkpoints
	// cheap enough to run on every sequencing round, avoiding latency spikes.
	synchronousPRAGMA := `PRAGMA synchronous = OFF;`
	if !onZFS(filepath.Dir(path)) {
		synchronousPRAGMA = `PRAGMA synchronous = NORMAL;`
		log.Warn("cache database is not on ZFS, using synchronous=NORMAL for safety; " +
			"this may cause latency spikes during checkpoints")
	}
	if err := sqlitex.ExecTransient(writeConn, synchronousPRAGMA, nil); err != nil {
		writeConn.Close()
		return nil, nil, err
	}
	// Bound how long a checkpoint can stall a sequencing round waiting for
	// in-flight cacheGet reads to move off the WAL. writeConn otherwise never
	// contends: it is the only writer, and readers don't block it in WAL mode.
	writeConn.SetBusyTimeout(time.Second)
	// Checkpoints are executed explicitly with RESTART, instead of the
	// automatic PASSIVE ones, which can't reset the WAL under sustained reads.
	// We have only one writer, so RESTART is cheap.
	if err := sqlitex.ExecTransient(writeConn,
		`PRAGMA wal_autocheckpoint = 0;`, nil); err != nil {
		writeConn.Close()
		return nil, nil, err
	}
	if err := sqlitex.ExecTransient(writeConn,
		// 1 GiB, enough for the interior pages of a full shard.
		`PRAGMA cache_size = -1048576;`, nil); err != nil {
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
	if err := sqlitex.ExecTransient(readConn,
		`PRAGMA cache_size = -1048576;`, nil); err != nil {
		readConn.Close()
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

func (l *Log) cacheCheckpoint(ctx context.Context) {
	defer prometheus.NewTimer(l.m.CacheCheckpointDuration).ObserveDuration()
	var busy, frames, checkpointed int64
	err := sqlitex.ExecTransient(l.cacheWrite, `PRAGMA wal_checkpoint(RESTART);`,
		func(stmt *sqlite.Stmt) error {
			busy = stmt.ColumnInt64(0)
			frames = stmt.ColumnInt64(1)
			checkpointed = stmt.ColumnInt64(2)
			return nil
		})
	if err != nil {
		l.c.Log.ErrorContext(ctx, "cache checkpoint failed", "err", err)
		l.m.CacheCheckpointErrors.Inc()
		return
	}
	l.m.CacheWALFrames.Set(float64(frames))
	if busy != 0 {
		// The checkpoint couldn't complete within the busy timeout.
		// The next attempt picks up where this one stopped.
		l.c.Log.WarnContext(ctx, "cache checkpoint busy",
			"frames", frames, "checkpointed", checkpointed)
		l.m.CacheCheckpointBusy.Inc()
	}
}
