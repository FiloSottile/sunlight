package ctlog

func (l *Log) AddCertificate(cert []byte) func() (id int64) {
	return l.addLeafToPool(&logEntry{cert: cert})
}

func (l *Log) Sequence() error {
	return l.sequencePool()
}
