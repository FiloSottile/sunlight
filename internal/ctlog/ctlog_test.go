package ctlog_test

import (
	"bytes"
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

func fatalIfErr(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func BenchmarkSequencer(b *testing.B) {
	tl := cttest.NewEmptyTestLog(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		const poolSize = 3000
		if i%poolSize == 0 && i != 0 {
			fatalIfErr(b, tl.Log.Sequence())
		}
		tl.Log.AddCertificate(bytes.Repeat([]byte("A"), 2350))
	}
}
