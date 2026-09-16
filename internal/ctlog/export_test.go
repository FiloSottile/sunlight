package ctlog

import (
	"context"
	"time"

	"filippo.io/sunlight"
)

var ErrEvicted = errEvicted
var ErrPoolFull = errPoolFull
var ErrTimeout = errTimeout

type WaitEntryFunc = waitEntryFunc

func (l *Log) AddLeafToPool(e *PendingLogEntry) (WaitEntryFunc, string) {
	return l.addLeafToPool(context.Background(), e, false)
}

func (l *Log) AddLeafToPoolWithLowPriority(e *PendingLogEntry) (WaitEntryFunc, string) {
	return l.addLeafToPool(context.Background(), e, true)
}

func (l *Log) AddLeafToPoolContext(ctx context.Context, e *PendingLogEntry) (WaitEntryFunc, string) {
	return l.addLeafToPool(ctx, e, false)
}

func (l *Log) Sequence() error {
	return l.sequence(context.Background())
}

func (e *PendingLogEntry) AsLogEntry(idx, timestamp int64) *sunlight.LogEntry {
	return e.asLogEntry(idx, timestamp)
}

func (l *Log) SetDuplicateLimit(interval time.Duration, burst int) {
	l.sourceLimiter = newSourceLimiter(interval, burst)
}

func SetTimeNowUnixMilli(f func() int64) {
	timeNowUnixMilli = f
}

func SetAddLeafToPoolPause(f func()) {
	testingOnlyPauseAddLeafToPool = f
}

func SetPoolSwapCallback(f func()) {
	testingOnlyPoolSwapped = f
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
