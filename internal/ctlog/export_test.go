package ctlog

import "context"

func (l *Log) AddLeafToPool(e *LogEntry) func(ctx context.Context) (*SequencedLogEntry, error) {
	return l.addLeafToPool(e)
}

func (l *Log) Sequence() error {
	return l.sequence(context.Background())
}

func SetTimeNowUnixMilli(f func() int64) {
	timeNowUnixMilli = f
}
