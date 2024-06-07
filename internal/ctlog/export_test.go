package ctlog

import (
	"context"

	"filippo.io/sunlight"
)

func (l *Log) AddLeafToPool(e *PendingLogEntry) (waitEntryFunc, string) {
	return l.addLeafToPool(context.Background(), e)
}

func (l *Log) Sequence() error {
	return l.sequence(context.Background())
}

func (e *PendingLogEntry) AsLogEntry(idx, timestamp int64) *sunlight.LogEntry {
	return e.asLogEntry(idx, timestamp)
}

func SetTimeNowUnixMilli(f func() int64) {
	timeNowUnixMilli = f
}

var seqRunning chan struct{}

func PauseSequencer() {
	seqRunning = make(chan struct{})
	testingOnlyPauseSequencing = func() {
		<-seqRunning
	}
}

func ResumeSequencer() {
	close(seqRunning)
}
