package ctlog

import (
	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
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
		CREATE TABLE IF NOT EXISTS cache (
			key BLOB PRIMARY KEY,
			timestamp INTEGER,
			leaf_index INTEGER
		) WITHOUT ROWID;`, nil); err != nil {
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

func (l *Log) CloseCache() error {
	if err := l.cacheRead.Close(); err != nil {
		return err
	}
	return l.cacheWrite.Close()
}

func (l *Log) cacheGet(leaf *LogEntry) (*SequencedLogEntry, error) {
	defer prometheus.NewTimer(l.m.CacheGetDuration).ObserveDuration()
	h := leaf.cacheHash()
	var se *SequencedLogEntry
	err := sqlitex.Exec(l.cacheRead, "SELECT timestamp, leaf_index FROM cache WHERE key = ?",
		func(stmt *sqlite.Stmt) error {
			se = &SequencedLogEntry{
				LogEntry:  *leaf,
				LeafIndex: stmt.GetInt64("leaf_index"),
				Timestamp: stmt.GetInt64("timestamp"),
			}
			return nil
		}, h[:])
	if err != nil {
		return nil, err
	}
	return se, nil
}

func (l *Log) cachePut(entries []*SequencedLogEntry) (err error) {
	defer prometheus.NewTimer(l.m.CachePutDuration).ObserveDuration()
	defer sqlitex.Save(l.cacheWrite)(&err)
	for _, se := range entries {
		h := se.cacheHash()
		err := sqlitex.Exec(l.cacheWrite, "INSERT INTO cache (key, timestamp, leaf_index) VALUES (?, ?, ?)",
			nil, h[:], se.Timestamp, se.LeafIndex)
		if err != nil {
			return err
		}
	}
	return nil
}
