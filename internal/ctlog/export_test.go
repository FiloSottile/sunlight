package ctlog

import "context"

func (l *Log) AddCertificate(cert []byte) func(ctx context.Context) (*SequencedLogEntry, error) {
	return l.addLeafToPool(&LogEntry{Certificate: cert})
}

func (l *Log) AddLeafToPool(e *LogEntry) func(ctx context.Context) (*SequencedLogEntry, error) {
	return l.addLeafToPool(e)
}

func (l *Log) Sequence() error {
	return l.sequencePool()
}

func SetTimeNowUnixMilli(f func() int64) {
	timeNowUnixMilli = f
}
