package ctlog_test

import (
	"testing"

	"filippo.io/litetlog/internal/ctlog/cttest"
)

func TestSequencer(t *testing.T) {
	tl := cttest.NewEmptyTestLog(t)
	id := tl.Log.AddCertificate([]byte("AAA"))
	fatalIfErr(t, tl.Log.Sequence())
	if id := id(); id != 0 {
		t.Errorf("got leaf index %d, expected %d", id, 0)
	}
}

func fatalIfErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
