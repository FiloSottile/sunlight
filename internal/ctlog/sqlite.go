package ctlog

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"crawshaw.io/sqlite"
	"crawshaw.io/sqlite/sqlitex"
	"github.com/prometheus/client_golang/prometheus"
)

type SQLiteBackend struct {
	mu       *sync.Mutex
	conn     *sqlite.Conn
	duration prometheus.Summary
	log      *slog.Logger
}

func NewSQLiteBackend(ctx context.Context, path string, l *slog.Logger) (*SQLiteBackend, error) {
	duration := prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name:       "sqlite_update_duration_seconds",
			Help:       "Duration of SQLite lock backend updates.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
			MaxAge:     1 * time.Minute,
			AgeBuckets: 6,
		},
	)

	conn, err := sqlite.OpenConn(path, sqlite.OpenFlagsDefault & ^sqlite.SQLITE_OPEN_CREATE)
	if err != nil {
		return nil, fmt.Errorf(`failed to open SQLite lock database (hint: to avoid misconfiguration, the lock database must be created manually with "CREATE TABLE checkpoints (logID BLOB PRIMARY KEY, checkpoint TEXT)"): %w`, err)
	}
	if err := sqlitex.ExecTransient(conn, "PRAGMA synchronous = FULL", nil); err != nil {
		conn.Close()
		return nil, err
	}
	if err := sqlitex.ExecTransient(conn, "PRAGMA fullfsync = TRUE;", nil); err != nil {
		conn.Close()
		return nil, err
	}

	return &SQLiteBackend{
		conn:     conn,
		duration: duration,
		log:      l,
	}, nil
}

var _ LockBackend = &SQLiteBackend{}

type sqliteCheckpoint struct {
	body  []byte
	logID [sha256.Size]byte
}

func (c *sqliteCheckpoint) Bytes() []byte { return c.body }

var _ LockedCheckpoint = &sqliteCheckpoint{}

func (b *SQLiteBackend) Fetch(ctx context.Context, logID [sha256.Size]byte) (LockedCheckpoint, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var body []byte
	err := sqlitex.Exec(b.conn, "SELECT body FROM checkpoints WHERE logID = ?",
		func(stmt *sqlite.Stmt) error {
			body = []byte(stmt.GetText("body"))
			return nil
		}, logID[:])
	if err != nil {
		return nil, err
	}
	if body == nil {
		return nil, errors.New("checkpoint not found")
	}
	return &dynamoDBCheckpoint{logID: logID, body: body}, nil
}

func (b *SQLiteBackend) Replace(ctx context.Context, old LockedCheckpoint, new []byte) (LockedCheckpoint, error) {
	defer prometheus.NewTimer(b.duration).ObserveDuration()
	b.mu.Lock()
	defer b.mu.Unlock()
	o := old.(*sqliteCheckpoint)
	err := sqlitex.Exec(b.conn, "UPDATE checkpoints SET body = ? WHERE logID = ? AND body = ?",
		nil, new, o.logID[:], o.body)
	if err != nil {
		return nil, fmt.Errorf("failed to update checkpoint: %w", err)
	}
	if b.conn.Changes() == 0 {
		return nil, errors.New("checkpoint not found or has changed")
	}
	return &sqliteCheckpoint{logID: o.logID, body: new}, nil
}

func (b *SQLiteBackend) Create(ctx context.Context, logID [sha256.Size]byte, new []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	err := sqlitex.Exec(b.conn, `INSERT INTO checkpoints (logID, body) VALUES (?, ?)
		ON CONFLICT(logID) DO NOTHING`, nil, logID[:], new)
	if err != nil {
		return fmt.Errorf("failed to create checkpoint: %w", err)
	}
	if b.conn.Changes() == 0 {
		return errors.New("checkpoint already exists")
	}
	return nil
}

func (b *SQLiteBackend) Metrics() []prometheus.Collector {
	return []prometheus.Collector{b.duration}
}
