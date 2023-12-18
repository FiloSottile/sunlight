package ctlog

import "context"

func (l *Log) AddLeafToPool(e *LogEntry) (waitEntryFunc, string) {
	return l.addLeafToPool(e)
}

func (l *Log) Sequence() error {
	return l.sequence(context.Background())
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
