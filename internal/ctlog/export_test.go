package ctlog

import "context"

func (l *Log) AddLeafToPool(e *LogEntry) func(ctx context.Context) (*SequencedLogEntry, error) {
	return l.addLeafToPool(e)
}

func (l *Log) Sequence() error {
	l.poolMu.Lock()
	p := l.currentPool
	l.currentPool = &pool{done: make(chan struct{})}
	l.poolMu.Unlock()
	return l.sequencePool(context.Background(), p)
}

func SetTimeNowUnixMilli(f func() int64) {
	timeNowUnixMilli = f
}
