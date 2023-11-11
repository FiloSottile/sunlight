package ctlog_test

import (
	"bytes"
	"crypto/rand"
	"flag"
	mathrand "math/rand"
	"testing"
	"time"

	"filippo.io/litetlog/internal/ctlog/cttest"
)

var longFlag = flag.Bool("long", false, "run especially slow tests")

func TestSequenceOneLeaf(t *testing.T) {
	tl := cttest.NewEmptyTestLog(t)

	n := int64(1024 + 2)
	if *longFlag {
		n *= 1024
	}
	if testing.Short() {
		n = 3
	}
	for i := int64(0); i < n; i++ {
		cert := make([]byte, mathrand.Intn(4)+1)
		rand.Read(cert)

		id := tl.Log.AddCertificate(cert)
		fatalIfErr(t, tl.Log.Sequence())
		if id := id(); id != i {
			t.Errorf("got leaf index %d, expected %d", id, 0)
		}

		if !*longFlag {
			tl.CheckLog()
			// TODO: check leaf contents at index id.
		}
	}
	tl.CheckLog()
}

func TestSequenceLargeLog(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	tl := cttest.NewEmptyTestLog(t)
	for i := 0; i < 5; i++ {
		cert := make([]byte, mathrand.Intn(4)+1)
		rand.Read(cert)
		tl.Log.AddCertificate(cert)
	}
	fatalIfErr(t, tl.Log.Sequence())
	tl.CheckLog()

	for i := 0; i < 500; i++ {
		for i := 0; i < 3000; i++ {
			cert := make([]byte, mathrand.Intn(4)+1)
			rand.Read(cert)
			tl.Log.AddCertificate(cert)
		}
		fatalIfErr(t, tl.Log.Sequence())
	}
	tl.CheckLog()
}

func TestSequenceEmptyPool(t *testing.T) {
	sequenceTwice := func(tl *cttest.TestLog) {
		fatalIfErr(t, tl.Log.Sequence())
		t1 := tl.CheckLog()
		time.Sleep(3 * time.Millisecond)
		fatalIfErr(t, tl.Log.Sequence())
		t2 := tl.CheckLog()
		if t1 >= t2 {
			t.Helper()
			t.Error("time did not advance")
		}
	}
	addCerts := func(tl *cttest.TestLog, n int) {
		for i := 0; i < n; i++ {
			cert := make([]byte, mathrand.Intn(1000)+1)
			rand.Read(cert)
			tl.Log.AddCertificate(cert)
		}
	}

	tl := cttest.NewEmptyTestLog(t)
	sequenceTwice(tl)
	addCerts(tl, 5) // 5
	sequenceTwice(tl)
	addCerts(tl, 1024-5-1) // 1024 - 1
	sequenceTwice(tl)
	addCerts(tl, 1) // 1024
	sequenceTwice(tl)
	addCerts(tl, 1) // 1024 + 1
	sequenceTwice(tl)
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
