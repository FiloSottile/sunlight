// Package keylog registers two endpoints /debug/keylog/on and /debug/keylog/off
// as a side-effect. When /debug/keylog/on is called, KeyLogWriter starts
// writing to a new temp file. When /debug/keylog/off is called, KeyLogWriter
// stops writing to the temp file and closes it. If /debug/keylog/off is not
// called, the temp file is closed after 15 minutes of inactivity.
package keylog

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

var keyLogFileMutex sync.Mutex
var keyLogFile *os.File
var keyLogTimer *time.Timer

var Writer = writerFunc(func(p []byte) (n int, err error) {
	keyLogFileMutex.Lock()
	defer keyLogFileMutex.Unlock()
	if keyLogFile == nil {
		return len(p), nil
	}
	return keyLogFile.Write(p)
})

type writerFunc func(p []byte) (n int, err error)

func (f writerFunc) Write(p []byte) (n int, err error) {
	return f(p)
}

func init() {
	http.HandleFunc("POST /debug/keylog/on", func(w http.ResponseWriter, r *http.Request) {
		keyLogFileMutex.Lock()
		defer keyLogFileMutex.Unlock()
		if keyLogFile != nil {
			http.Error(w, "key log file already open", http.StatusBadRequest)
			return
		}
		f, err := os.CreateTemp("", "keylog-")
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to create key log file: %v", err),
				http.StatusInternalServerError)
			return
		}
		keyLogTimer = time.AfterFunc(15*time.Minute, func() {
			keyLogFileMutex.Lock()
			defer keyLogFileMutex.Unlock()
			keyLogFile.Close()
			keyLogFile = nil
			keyLogTimer = nil
		})
		fmt.Fprintf(w, "%s\n", f.Name())
		keyLogFile = f
	})
	http.HandleFunc("POST /debug/keylog/off", func(w http.ResponseWriter, r *http.Request) {
		keyLogFileMutex.Lock()
		defer keyLogFileMutex.Unlock()
		if keyLogFile == nil {
			http.Error(w, "key log file not open", http.StatusBadRequest)
			return
		}
		if err := keyLogFile.Close(); err != nil {
			http.Error(w, fmt.Sprintf("failed to close key log file: %v", err),
				http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "%s\n", keyLogFile.Name())
		keyLogFile = nil
		keyLogTimer.Stop()
		keyLogTimer = nil
	})
}
