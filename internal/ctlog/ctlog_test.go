package ctlog_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"flag"
	mathrand "math/rand"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/ctlog"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
)

var globalTime = time.Now().UnixMilli()

func monotonicTime() int64 { return atomic.AddInt64(&globalTime, 1) }

func init() { ctlog.SetTimeNowUnixMilli(monotonicTime) }

var longFlag = flag.Bool("long", false, "run especially slow tests")

func TestSequenceOneLeaf(t *testing.T) {
	tl := NewEmptyTestLog(t)

	n := int64(tileWidth + 2)
	if *longFlag {
		n *= tileWidth
	}
	if testing.Short() {
		n = 3
	} else {
		tl.Quiet()
	}
	for i := int64(0); i < n; i++ {
		wait := addCertificate(t, tl)
		fatalIfErr(t, tl.Log.Sequence())
		if e, err := wait(context.Background()); err != nil {
			t.Fatal(err)
		} else if e.LeafIndex != i {
			t.Errorf("got leaf index %d, expected %d", e.LeafIndex, i)
		}

		if !*longFlag {
			tl.CheckLog(i + 1)
			// TODO: check leaf contents at index id.
		}
	}
	tl.CheckLog(n)
}

func TestSequenceLargeLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestSequenceLargeLog in -short mode")
	}

	tl := NewEmptyTestLog(t)
	tl.Quiet()
	for i := 0; i < 5; i++ {
		addCertificate(t, tl)
	}
	fatalIfErr(t, tl.Log.Sequence())
	tl.CheckLog(5)

	for i := 0; i < 500; i++ {
		for k := 0; k < 3000; k++ {
			e := &ctlog.PendingLogEntry{}
			e.Certificate = []byte(strconv.Itoa(i*3000 + k))
			tl.Log.AddLeafToPool(e)
		}
		fatalIfErr(t, tl.Log.Sequence())
	}
	tl.CheckLog(5 + 500*3000)
}

func TestSequenceEmptyPool(t *testing.T) {
	sequenceTwice := func(tl *TestLog, size int64) {
		fatalIfErr(t, tl.Log.Sequence())
		t1 := tl.CheckLog(size)
		fatalIfErr(t, tl.Log.Sequence())
		t2 := tl.CheckLog(size)
		if t1 >= t2 {
			t.Helper()
			t.Error("time did not advance")
		}
	}
	addCerts := func(tl *TestLog, n int) {
		for i := 0; i < n; i++ {
			addCertificate(t, tl)
		}
	}

	tl := NewEmptyTestLog(t)
	sequenceTwice(tl, 0)
	addCerts(tl, 5)
	sequenceTwice(tl, 5)
	addCerts(tl, tileWidth-5-1)
	sequenceTwice(tl, tileWidth-1)
	addCerts(tl, 1)
	sequenceTwice(tl, tileWidth)
	addCerts(tl, 1)
	sequenceTwice(tl, tileWidth+1)
}

func TestSequenceUploadCount(t *testing.T) {
	tl := NewEmptyTestLog(t)
	for i := 0; i < tileWidth+1; i++ {
		addCertificate(t, tl)
	}
	fatalIfErr(t, tl.Log.Sequence())

	var old uint64
	uploads := func() uint64 {
		new := tl.Config.Backend.(*MemoryBackend).uploads
		n := new - old
		old = new
		return n
	}
	uploads()

	// Empty rounds should cause only one upload: the checkpoint.
	fatalIfErr(t, tl.Log.Sequence())
	if n := uploads(); n != 1 {
		t.Errorf("got %d uploads, expected 1", n)
	}

	// One entry in steady state (not at tile boundary) should cause four
	// uploads (the staging bundle, the checkpoint, a level -1 tile, and a level
	// 0 tile).
	addCertificate(t, tl)
	fatalIfErr(t, tl.Log.Sequence())
	if n := uploads(); n != 4 {
		t.Errorf("got %d uploads, expected 4", n)
	}

	// A tile width worth of entries should cause six uploads (the staging
	// bundle, the checkpoint, two level -1 tiles, two level 0 tiles, and one
	// level 1 tile).
	for i := 0; i < tileWidth; i++ {
		addCertificate(t, tl)
	}
	fatalIfErr(t, tl.Log.Sequence())
	if n := uploads(); n != 7 {
		t.Errorf("got %d uploads, expected 7", n)
	}
}

func TestSequenceUploadPaths(t *testing.T) {
	defer func(old int64) { globalTime = old }(globalTime)
	globalTime = 0

	tl := NewEmptyTestLog(t)

	for i := int64(0); i < tileWidth+5; i++ {
		addCertificateWithSeed(t, tl, i)
	}
	fatalIfErr(t, tl.Log.Sequence())
	for i := int64(0); i < tileWidth+10; i++ {
		addCertificateWithSeed(t, tl, 1000+i)
	}
	fatalIfErr(t, tl.Log.Sequence())
	tl.CheckLog(2*tileWidth + 15)

	m := tl.Config.Backend.(*MemoryBackend).m
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	expected := []string{
		"_roots.pem",
		"checkpoint",
		"issuer/1b48a2acbba79932d3852ccde41197f678256f3c2a280e9edf9aad272d6e9c92",
		"issuer/559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd",
		"issuer/6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d",
		"issuer/81365bbc90b5b3991c762eebada7c6d84d1e39a0a1d648cb4fe5a9890b089da8",
		"issuer/df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c",
		"staging/261-0a4f1a4119ca89dc90a612834c0da004f5d1b04a5aad89b88df26a904e4a4f0f",
		"staging/527-0c3e2c4127196a1a5abb8c6d94d3607a92b510e01004607b910eb0c7ba27f710",
		"tile/0/000",
		"tile/0/001",
		"tile/0/001.p/5",
		"tile/0/002.p/15",
		"tile/1/000.p/1",
		"tile/1/000.p/2",
		"tile/data/000",
		"tile/data/001",
		"tile/data/001.p/5",
		"tile/data/002.p/15",
	}
	if !reflect.DeepEqual(keys, expected) {
		t.Errorf("got %#v, expected %#v", keys, expected)
	}

	for _, key := range keys {
		expectedImmutable := false
		expectedDeleted := false
		if key != "checkpoint" && key != "_roots.pem" {
			expectedImmutable = true
		}
		if strings.HasPrefix(key, "staging/") {
			expectedDeleted = true
		}
		if tl.Config.Backend.(*MemoryBackend).del[key] != expectedDeleted {
			t.Errorf("got deleted %v, expected %v for key %q", tl.Config.Backend.(*MemoryBackend).del[key], expectedDeleted, key)
		}
		if tl.Config.Backend.(*MemoryBackend).imm[key] != expectedImmutable {
			t.Errorf("got immutable %v, expected %v for key %q", tl.Config.Backend.(*MemoryBackend).imm[key], expectedImmutable, key)
		}
	}
}

func TestDuplicates(t *testing.T) {
	t.Run("Certificates", func(t *testing.T) {
		testDuplicates(t, addCertificateWithSeed)
	})
	t.Run("Precerts", func(t *testing.T) {
		testDuplicates(t, addPreCertificateWithSeed)
	})
}

func testDuplicates(t *testing.T, addWithSeed func(*testing.T, *TestLog, int64) func(context.Context) (*sunlight.LogEntry, error)) {
	tl := NewEmptyTestLog(t)
	addWithSeed(t, tl, mathrand.Int63()) // 0
	addWithSeed(t, tl, mathrand.Int63()) // 1
	fatalIfErr(t, tl.Log.Sequence())
	addWithSeed(t, tl, mathrand.Int63()) // 2
	addWithSeed(t, tl, mathrand.Int63()) // 3

	// Two pairs of duplicates from the byHash pool.

	wait01 := addWithSeed(t, tl, 0) // 4
	wait02 := addWithSeed(t, tl, 0)
	wait11 := addWithSeed(t, tl, 1) // 5
	wait12 := addWithSeed(t, tl, 1)
	fatalIfErr(t, tl.Log.Sequence())
	fatalIfErr(t, tl.Log.Sequence())
	tl.CheckLog(6)

	e01, err := wait01(context.Background())
	fatalIfErr(t, err)
	e02, err := wait02(context.Background())
	fatalIfErr(t, err)

	if e02.LeafIndex != e01.LeafIndex {
		t.Errorf("got leaf index %d, expected %d", e02.LeafIndex, e01.LeafIndex)
	}
	if e02.Timestamp != e01.Timestamp {
		t.Errorf("got timestamp %d, expected %d", e02.Timestamp, e01.Timestamp)
	}

	e11, err := wait11(context.Background())
	fatalIfErr(t, err)
	e12, err := wait12(context.Background())
	fatalIfErr(t, err)

	if e12.LeafIndex != e11.LeafIndex {
		t.Errorf("got leaf index %d, expected %d", e12.LeafIndex, e11.LeafIndex)
	}
	if e12.Timestamp != e11.Timestamp {
		t.Errorf("got timestamp %d, expected %d", e12.Timestamp, e11.Timestamp)
	}

	// A duplicate from the cache.

	wait03 := addWithSeed(t, tl, 0)
	fatalIfErr(t, tl.Log.Sequence())
	e03, err := wait03(context.Background())
	fatalIfErr(t, err)

	if e03.LeafIndex != e01.LeafIndex {
		t.Errorf("got leaf index %d, expected %d", e03.LeafIndex, e01.LeafIndex)
	}
	if e03.Timestamp != e01.Timestamp {
		t.Errorf("got timestamp %d, expected %d", e03.Timestamp, e01.Timestamp)
	}

	// A pair of duplicates from the inSequencing pool.

	wait21 := addWithSeed(t, tl, 2) // 6
	ctlog.PauseSequencer()
	go tl.Log.Sequence()
	wait22 := addWithSeed(t, tl, 2)
	ctlog.ResumeSequencer()

	e21, err := wait21(context.Background())
	fatalIfErr(t, err)
	e22, err := wait22(context.Background())
	fatalIfErr(t, err)

	if e22.LeafIndex != e21.LeafIndex {
		t.Errorf("got leaf index %d, expected %d", e22.LeafIndex, e21.LeafIndex)
	}
	if e22.Timestamp != e21.Timestamp {
		t.Errorf("got timestamp %d, expected %d", e22.Timestamp, e21.Timestamp)
	}

	// A failed sequencing immediately allows resubmission (i.e., the failed
	// entry in the inSequencing pool is not picked up).

	tl.Config.Backend.(*MemoryBackend).UploadCallback = failStagingButPersist
	addCertificateExpectFailureWithSeed(t, tl, 3)
	fatalIfErr(t, tl.Log.Sequence())

	tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
	addCertificateWithSeed(t, tl, 3)
	fatalIfErr(t, tl.Log.Sequence())
}

func TestReloadLog(t *testing.T) {
	t.Run("Certificates", func(t *testing.T) {
		testReloadLog(t, addCertificate)
	})
	t.Run("Precerts", func(t *testing.T) {
		testReloadLog(t, addPreCertificate)
	})
}

func testReloadLog(t *testing.T, add func(*testing.T, *TestLog) func(context.Context) (*sunlight.LogEntry, error)) {
	// TODO: test reloading after uploading tiles but before uploading STH.
	tl := NewEmptyTestLog(t)
	n := int64(tileWidth + 2)
	if testing.Short() {
		n = 3
	} else {
		tl.Quiet()
	}
	for i := int64(0); i < n; i++ {
		add(t, tl)

		fatalIfErr(t, tl.Log.Sequence())
		tl.CheckLog(i + 1)

		tl = ReloadLog(t, tl)
		fatalIfErr(t, tl.Log.Sequence())
		tl.CheckLog(i + 1)
	}
}

func TestSubmit(t *testing.T) {
	t.Run("Certificates", func(t *testing.T) {
		testSubmit(t, false)
	})
	t.Run("Precerts", func(t *testing.T) {
		testSubmit(t, true)
	})
}

func testSubmit(t *testing.T, precert bool) {
	tl := NewEmptyTestLog(t)
	logClient := tl.LogClient()

	// Don't submit at index 0 as it might hide encoding issues.
	addCertificate(t, tl)

	var err error
	var sct1, sct2 *ct.SignedCertificateTimestamp
	if precert {
		sct1, err = logClient.AddPreChain(context.Background(), []ct.ASN1Cert{
			{Data: testPrecert}, {Data: testIntermediate}, {Data: testRoot}})
	} else {
		sct1, err = logClient.AddChain(context.Background(), []ct.ASN1Cert{
			{Data: testLeaf}, {Data: testIntermediate}, {Data: testRoot}})
	}
	fatalIfErr(t, err)

	if sct1.SCTVersion != ct.V1 {
		t.Errorf("got SCT version %d, expected %d", sct1.SCTVersion, ct.V1)
	}
	pkix, err := x509.MarshalPKIXPublicKey(tl.Config.Key.Public())
	if err != nil {
		t.Fatalf("couldn't marshal public key: %v", err)
	}
	logID := sha256.Sum256(pkix)
	if sct1.LogID.KeyID != logID {
		t.Errorf("got log ID %x, expected %x", sct1.LogID.KeyID, logID)
	}
	if sct1.Timestamp == 0 {
		t.Error("got zero timestamp")
	}
	if idx, err := sunlight.ParseExtensions(sct1.Extensions); err != nil {
		t.Errorf("couldn't parse extensions: %v", err)
	} else if idx.LeafIndex != 1 {
		t.Errorf("got extensions index %d, expected 1", idx)
	}

	if precert {
		sct2, err = logClient.AddPreChain(context.Background(), []ct.ASN1Cert{
			{Data: testPrecert}, {Data: testIntermediate}, {Data: testRoot}})
	} else {
		sct2, err = logClient.AddChain(context.Background(), []ct.ASN1Cert{
			{Data: testLeaf}, {Data: testIntermediate}, {Data: testRoot}})
	}
	fatalIfErr(t, err)

	sct1Bytes, err := tls.Marshal(*sct1)
	fatalIfErr(t, err)
	sct2Bytes, err := tls.Marshal(*sct2)
	fatalIfErr(t, err)
	if !bytes.Equal(sct1Bytes, sct2Bytes) {
		t.Error("got different SCTs for the same entry")
	}
}

func TestReloadWrongName(t *testing.T) {
	tl := NewEmptyTestLog(t)
	log, err := ctlog.LoadLog(context.Background(), tl.Config)
	fatalIfErr(t, err)
	t.Cleanup(func() { fatalIfErr(t, log.CloseCache()) })

	c := tl.Config
	c.Name = "wrong"
	if _, err := ctlog.LoadLog(context.Background(), c); err == nil {
		t.Error("expected loading to fail")
	}
}

func TestReloadWrongKey(t *testing.T) {
	tl := NewEmptyTestLog(t)
	log, err := ctlog.LoadLog(context.Background(), tl.Config)
	fatalIfErr(t, err)
	t.Cleanup(func() { fatalIfErr(t, log.CloseCache()) })

	c := tl.Config
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fatalIfErr(t, err)
	c.Key = key
	if _, err := ctlog.LoadLog(context.Background(), c); err == nil {
		t.Error("expected loading to fail")
	}

	c = tl.Config
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	fatalIfErr(t, err)
	c.WitnessKey = ed25519Key
	if _, err := ctlog.LoadLog(context.Background(), c); err == nil {
		t.Error("expected loading to fail")
	}
}

func TestStagingCollision(t *testing.T) {
	tl := NewEmptyTestLog(t)
	addCertificate(t, tl)
	fatalIfErr(t, tl.Log.Sequence())

	time := monotonicTime()
	ctlog.SetTimeNowUnixMilli(func() int64 { return time })
	t.Cleanup(func() { ctlog.SetTimeNowUnixMilli(monotonicTime) })

	// First, upload a staging bundle but fail sequencing.

	addCertificateExpectFailureWithSeed(t, tl, 'A')
	addCertificateExpectFailureWithSeed(t, tl, 'B')

	tl.Config.Lock.(*MemoryLockBackend).ReplaceCallback = failLockAndNotPersist
	sequenceExpectFailure(t, tl)
	tl.CheckLog(1)

	tl.Config.Lock.(*MemoryLockBackend).ReplaceCallback = nil
	tl = ReloadLog(t, tl)
	tl.CheckLog(1)

	// Then, cause the exact same staging bundle to be uploaded.

	addCertificateWithSeed(t, tl, 'A')
	addCertificateWithSeed(t, tl, 'B')
	fatalIfErr(t, tl.Log.Sequence())
	tl.CheckLog(3)

	// Again, but now due to a staging bundle upload error.

	time++

	addCertificateExpectFailureWithSeed(t, tl, 'C')
	addCertificateExpectFailureWithSeed(t, tl, 'D')

	tl.Config.Backend.(*MemoryBackend).UploadCallback = failStagingButPersist
	fatalIfErr(t, tl.Log.Sequence())
	tl.CheckLog(3)

	tl.Config.Backend.(*MemoryBackend).UploadCallback = nil

	addCertificateWithSeed(t, tl, 'C')
	addCertificateWithSeed(t, tl, 'D')
	fatalIfErr(t, tl.Log.Sequence())
	tl.CheckLog(5)

	// Again, but reload the log after the failed upload.

	time++

	addCertificateExpectFailureWithSeed(t, tl, 'E')
	addCertificateExpectFailureWithSeed(t, tl, 'F')

	tl.Config.Backend.(*MemoryBackend).UploadCallback = failStagingButPersist
	fatalIfErr(t, tl.Log.Sequence())
	tl.CheckLog(5)

	tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
	tl = ReloadLog(t, tl)
	tl.CheckLog(5)

	addCertificateWithSeed(t, tl, 'E')
	addCertificateWithSeed(t, tl, 'F')
	fatalIfErr(t, tl.Log.Sequence())
	tl.CheckLog(7)

	// If the log doesn't progress, the staging path is the same.
	// LoadLog will re-upload the previous non-empty staging bundle.

	time++

	fatalIfErr(t, tl.Log.Sequence())
	tl.CheckLog(7)

	tl = ReloadLog(t, tl)
	tl.CheckLog(7)

	// Note that it's not possible to reach the same tree hash through different
	// sequencing paths, e.g. "[A, B, C]; [D, E]" and "[A, B]; [C, D, E]",
	// except for the trivial "[A, B, C]; []" case, because time must advance at
	// every sequencing, and it's embedded in the Merkle tree leaves.
}

func sequenceExpectFailure(t *testing.T, tl *TestLog) {
	t.Helper()
	if err := tl.Log.Sequence(); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestFatalError(t *testing.T) {
	tl := NewEmptyTestLog(t)
	addCertificate(t, tl)
	addCertificate(t, tl)
	fatalIfErr(t, tl.Log.Sequence())

	tl.Config.Lock.(*MemoryLockBackend).ReplaceCallback = failLockAndNotPersist
	addCertificateExpectFailure(t, tl)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := tl.Log.RunSequencer(ctx, 1*time.Millisecond); err == nil {
		t.Errorf("expected fatal error, got nil")
	}
	tl.CheckLog(2)

	tl.Config.Lock.(*MemoryLockBackend).ReplaceCallback = nil

	tl = ReloadLog(t, tl)
	addCertificate(t, tl)
	fatalIfErr(t, tl.Log.Sequence())
	tl.CheckLog(3)
}

func TestNonFatalError(t *testing.T) {
	// TODO
}

func TestSequenceErrors(t *testing.T) {
	tests := []struct {
		name           string
		breakSeq       func(*TestLog)
		unbreakSeq     func(*TestLog)
		expectProgress bool
		expectFatal    bool
	}{
		{
			// A fatal error while uploading to the lock backend. The upload is
			// retried, and the same tiles are generated and uploaded again.
			name: "LockUpload",
			breakSeq: func(tl *TestLog) {
				tl.Config.Lock.(*MemoryLockBackend).ReplaceCallback = failLockAndNotPersist
			},
			unbreakSeq: func(tl *TestLog) {
				tl.Config.Lock.(*MemoryLockBackend).ReplaceCallback = nil
			},
			expectProgress: false,
			expectFatal:    true,
		},
		{
			// An error while uploading to the lock backend, where the lock is
			// persisted anyway, such as a response timeout.
			name: "LockUploadPersisted",
			breakSeq: func(tl *TestLog) {
				tl.Config.Lock.(*MemoryLockBackend).ReplaceCallback = failLockButPersist
			},
			unbreakSeq: func(tl *TestLog) {
				tl.Config.Lock.(*MemoryLockBackend).ReplaceCallback = nil
			},
			expectProgress: true,
			expectFatal:    true,
		},
		{
			name: "CheckpointUpload",
			breakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = failCheckpointAndNotPersist
			},
			unbreakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
			},
			expectProgress: true,
			expectFatal:    false,
		},
		{
			name: "CheckpointUploadPersisted",
			breakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = failCheckpointButPersist
			},
			unbreakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
			},
			expectProgress: true,
			expectFatal:    false,
		},
		{
			name: "StagingUpload",
			breakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = failStagingAndNotPersist
			},
			unbreakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
			},
			expectProgress: false,
			expectFatal:    false,
		},
		{
			name: "StagingUploadPersisted",
			breakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = failStagingButPersist
			},
			unbreakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
			},
			expectProgress: false,
			expectFatal:    false,
		},
		{
			name: "DataTileUpload",
			breakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = failDataTileAndNotPersist
			},
			unbreakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
			},
			expectProgress: true,
			expectFatal:    true,
		},
		{
			name: "DataTileUploadPersisted",
			breakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = failDataTileButPersist
			},
			unbreakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
			},
			expectProgress: true,
			expectFatal:    true,
		},
		{
			name: "Level0TileUpload",
			breakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = failTile0AndNotPersist
			},
			unbreakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
			},
			expectProgress: true,
			expectFatal:    true,
		},
		{
			name: "Level0TileUploadPersisted",
			breakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = failTile0ButPersist
			},
			unbreakSeq: func(tl *TestLog) {
				tl.Config.Backend.(*MemoryBackend).UploadCallback = nil
			},
			expectProgress: true,
			expectFatal:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tl *TestLog
			var expectedSize int64
			var broken bool
			breakSeq := func() {
				tt.breakSeq(tl)
				broken = true
			}
			unbreakSeq := func() {
				tt.unbreakSeq(tl)
				broken = false
			}
			sequence := func(added int64) {
				err := tl.Log.Sequence()
				if broken && tt.expectFatal {
					if err == nil {
						t.Error("expected error, got nil")
					}
				} else {
					fatalIfErr(t, err)
				}
				if !broken || tt.expectProgress {
					expectedSize += added
				}
				tl.CheckLog(expectedSize)
				if err != nil {
					if broken {
						tt.unbreakSeq(tl)
					}
					tl = ReloadLog(t, tl)
					if broken {
						tt.breakSeq(tl)
					}
				}
			}

			tl = NewEmptyTestLog(t)
			for range tileWidth - 2 {
				addCertificate(t, tl)
			}
			sequence(tileWidth - 2)

			breakSeq()
			addCertificateExpectFailure(t, tl)
			addCertificateExpectFailure(t, tl)
			addCertificateExpectFailure(t, tl)
			sequence(3)

			// Re-failing the same tile sizes.
			addCertificateExpectFailure(t, tl)
			addCertificateExpectFailure(t, tl)
			addCertificateExpectFailure(t, tl)
			sequence(3)

			unbreakSeq()

			// Succeeding with the same size that failed.
			addCertificate(t, tl)
			addCertificate(t, tl)
			addCertificate(t, tl)
			sequence(3)

			tl = NewEmptyTestLog(t)
			expectedSize = 0
			for range tileWidth - 2 {
				addCertificate(t, tl)
			}
			sequence(tileWidth - 2)

			breakSeq()
			addCertificateExpectFailure(t, tl)
			addCertificateExpectFailure(t, tl)
			addCertificateExpectFailure(t, tl)
			sequence(3)

			unbreakSeq()

			// Succeeding with a different set of tiles.
			addCertificate(t, tl)
			sequence(1)
		})
	}
}

func BenchmarkSequencer(b *testing.B) {
	tl := NewEmptyTestLog(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		const poolSize = 3000
		if i%poolSize == 0 && i != 0 {
			fatalIfErr(b, tl.Log.Sequence())
		}
		tl.Log.AddLeafToPool(&ctlog.PendingLogEntry{Certificate: bytes.Repeat([]byte("A"), 2350)})
	}
}

var testLeaf, _ = base64.StdEncoding.DecodeString("MIIEJjCCAw6gAwIBAgISA9YVxv2Lcc/y6IhrW5svQmHPMA0GCSqGSIb3DQEBCwUAMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJSMzAeFw0yMzExMTUxMDE5MTFaFw0yNDAyMTMxMDE5MTBaMB0xGzAZBgNVBAMTEnJvbWUuY3QuZmlsaXBwby5pbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMufQMpi+5cCSw8a6D2se6bjTR6Vpcm5kr5b1UHaJZVdM4tOCy66d3iO9LcKYwIdXJJD1TbtzAuLlRCWa1HNlGSjggIUMIICEDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFIiqDtb1Rz6Y9iVID4JBRl36tE47MB8GA1UdIwQYMBaAFBQusxe3WFbLrlAJQOYfr52LFMLGMFUGCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL3IzLm8ubGVuY3Iub3JnMCIGCCsGAQUFBzAChhZodHRwOi8vcjMuaS5sZW5jci5vcmcvMB0GA1UdEQQWMBSCEnJvbWUuY3QuZmlsaXBwby5pbzATBgNVHSAEDDAKMAgGBmeBDAECATCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2AEiw42vapkc0D+VqAvqdMOscUgHLVt0sgdm7v6s52IRzAAABi9K04WIAAAQDAEcwRQIhAIjFeq4LZpEUNCTtVu1s3yURyaX18TRp4qjt02A2FYHEAiBWQxxfEsyYUFuDOFIYSh6q6MA9m2YenRmL7FqzgpMvpAB2ADtTd3U+LbmAToswWwb+QDtn2E/D9Me9AA0tcm/h+tQXAAABi9K0418AAAQDAEcwRQIhAJfS1HrW24DPJJCzwZ+Xgo4jX/o6nsXNVRuOrrqoFjBmAiAi53R5tlmS94uXLnUyX6+ULDxwCuSRSb23iEidzugiVDANBgkqhkiG9w0BAQsFAAOCAQEAc0EXBRfCal3xyXZ60DJspRf66ulLpVii1BPvcf0PWWGC/MCjbY2xwz+1p6fePMSMrUJpOTtP5L52bZNQBptq6oKSOKGpVn8eIaVqNPeJsYCuzL5tKnzfhBoyIs9tqc8U7JwZuIyCIFsxd5eDNLSNyphX9+jxATorpFJ8RYibzjmBkDjRSl6T2f32Qy4AKy2FJe2yryJjdiDHqzT3SoTYcJp/2wWklYFMtBV/j4qTGyFiVdVZ1GQUhHvlw1iVqXLHe8cVQoSc+iStlDxeFWEuKnHRTtpfNz+KzP15R13C6CBswODDjqH2HCS2OKhyENB6SF7KhhD5/hMVyj6UWq9pDw==")
var testPrecert, _ = base64.StdEncoding.DecodeString("MIIDMzCCAhugAwIBAgISA9YVxv2Lcc/y6IhrW5svQmHPMA0GCSqGSIb3DQEBCwUAMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJSMzAeFw0yMzExMTUxMDE5MTFaFw0yNDAyMTMxMDE5MTBaMB0xGzAZBgNVBAMTEnJvbWUuY3QuZmlsaXBwby5pbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMufQMpi+5cCSw8a6D2se6bjTR6Vpcm5kr5b1UHaJZVdM4tOCy66d3iO9LcKYwIdXJJD1TbtzAuLlRCWa1HNlGSjggEhMIIBHTAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFIiqDtb1Rz6Y9iVID4JBRl36tE47MB8GA1UdIwQYMBaAFBQusxe3WFbLrlAJQOYfr52LFMLGMFUGCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL3IzLm8ubGVuY3Iub3JnMCIGCCsGAQUFBzAChhZodHRwOi8vcjMuaS5sZW5jci5vcmcvMB0GA1UdEQQWMBSCEnJvbWUuY3QuZmlsaXBwby5pbzATBgNVHSAEDDAKMAgGBmeBDAECATATBgorBgEEAdZ5AgQDAQH/BAIFADANBgkqhkiG9w0BAQsFAAOCAQEAk4K63mYRtOqH2LprGfBDIXnOXGt7wicdyBD2Zh5tkqMBB0XulcAi94IUfEOBSfIIzZ5lTh8WvAB6RxMGXYf8Qx4dHCP1McpMvkOJNEz9cHVjoBxx8asdAsV6d+av3MsK83n/fnN6looyUoDz09AZNvmlR74HCmpgLydMMv8ugdiPjRlYLaKy8wiA+HpX2rb4oWJ9kSD7dxuu6+NqPi4qWVsopQKBMcYEhCfQN26tcm2X3jebcwE3TFNxhK5RcRTWMO3i5AtaUZDT4bWUTFTHP8668wvCpI8MyfIlVdlUv3BOnyjvr/zpSBb/SfbyE0yiUBKhxl5z3+LImTNwxbc5sg==")
var testIntermediate, _ = base64.StdEncoding.DecodeString("MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAwWhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cPR5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdxsxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8ZutmNHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxgZ3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaAFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6WPTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wlikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQzCkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BImlJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1OyK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90IdshCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6ZvMldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqXnLRbwHOoq7hHwg==")
var testRoot, _ = base64.StdEncoding.DecodeString("MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygch77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6UA5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sWT8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyHB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UCB5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUvKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWnOlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTnjh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbwqHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CIrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkqhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZLubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KKNFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7UrTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdCjNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVcoyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPAmRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57demyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=")
