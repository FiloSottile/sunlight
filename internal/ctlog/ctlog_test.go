package ctlog_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/litetlog/internal/ctlog"
	ct "github.com/google/certificate-transparency-go"
)

func init() {
	t := time.Now().UnixMilli()
	ctlog.SetTimeNowUnixMilli(func() int64 {
		return atomic.AddInt64(&t, 1)
	})
}

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
			tl.CheckLog()
			// TODO: check leaf contents at index id.
		}
	}
	tl.CheckLog()
}

func TestSequenceLargeLog(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestSequenceLargeLog in -short mode")
	}

	tl := NewEmptyTestLog(t)
	tl.Quiet()
	for i := 0; i < 5; i++ {
		addCertificateFast(t, tl)
	}
	fatalIfErr(t, tl.Log.Sequence())
	tl.CheckLog()

	for i := 0; i < 500; i++ {
		for i := 0; i < 3000; i++ {
			addCertificateFast(t, tl)
		}
		fatalIfErr(t, tl.Log.Sequence())
	}
	tl.CheckLog()
}

func TestSequenceEmptyPool(t *testing.T) {
	sequenceTwice := func(tl *TestLog) {
		fatalIfErr(t, tl.Log.Sequence())
		t1 := tl.CheckLog()
		fatalIfErr(t, tl.Log.Sequence())
		t2 := tl.CheckLog()
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
	sequenceTwice(tl)
	addCerts(tl, 5) // 5
	sequenceTwice(tl)
	addCerts(tl, tileWidth-5-1) // tileWidth - 1
	sequenceTwice(tl)
	addCerts(tl, 1) // tileWidth
	sequenceTwice(tl)
	addCerts(tl, 1) // tileWidth + 1
	sequenceTwice(tl)
}

func TestDuplicates(t *testing.T) {
	t.Run("Certificates", func(t *testing.T) {
		testDuplicates(t, addCertificate)
	})
	t.Run("Precerts", func(t *testing.T) {
		testDuplicates(t, addPreCertificate)
	})
}

func testDuplicates(t *testing.T, add func(*testing.T, *TestLog) func(context.Context) (*ctlog.SequencedLogEntry, error)) {
	tl := NewEmptyTestLog(t)
	addCertificate(t, tl) // 0
	addCertificate(t, tl) // 1
	fatalIfErr(t, tl.Log.Sequence())
	addCertificate(t, tl) // 2
	addCertificate(t, tl) // 3

	wait01 := addCertificateWithSeed(t, tl, 0) // 4
	wait02 := addCertificateWithSeed(t, tl, 0)
	wait11 := addCertificateWithSeed(t, tl, 1) // 5
	wait12 := addCertificateWithSeed(t, tl, 1)
	fatalIfErr(t, tl.Log.Sequence())
	fatalIfErr(t, tl.Log.Sequence())
	tl.CheckLog()

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

	wait03 := addCertificateWithSeed(t, tl, 0)
	fatalIfErr(t, tl.Log.Sequence())
	e03, err := wait03(context.Background())
	fatalIfErr(t, err)

	if e03.LeafIndex != e01.LeafIndex {
		t.Errorf("got leaf index %d, expected %d", e03.LeafIndex, e01.LeafIndex)
	}
	if e03.Timestamp != e01.Timestamp {
		t.Errorf("got timestamp %d, expected %d", e03.Timestamp, e01.Timestamp)
	}

	wait21 := addCertificateWithSeed(t, tl, 2) // 6
	ctlog.PauseSequencer()
	go tl.Log.Sequence()
	wait22 := addCertificateWithSeed(t, tl, 2)
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
}

func TestReloadLog(t *testing.T) {
	t.Run("Certificates", func(t *testing.T) {
		testReloadLog(t, addCertificate)
	})
	t.Run("Precerts", func(t *testing.T) {
		testReloadLog(t, addPreCertificate)
	})
}

func testReloadLog(t *testing.T, add func(*testing.T, *TestLog) func(context.Context) (*ctlog.SequencedLogEntry, error)) {
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
		tl.CheckLog()

		tl = ReloadLog(t, tl)
		fatalIfErr(t, tl.Log.Sequence())
		tl.CheckLog()
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
	if idx, err := ctlog.ParseExtensions(sct1.Extensions); err != nil {
		t.Errorf("couldn't parse extensions: %v", err)
	} else if idx != 1 {
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

	if sct1.SCTVersion != sct2.SCTVersion || sct1.LogID != sct2.LogID ||
		sct1.Timestamp != sct2.Timestamp || !bytes.Equal(sct1.Extensions, sct2.Extensions) {
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
}

func BenchmarkSequencer(b *testing.B) {
	tl := NewEmptyTestLog(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		const poolSize = 3000
		if i%poolSize == 0 && i != 0 {
			fatalIfErr(b, tl.Log.Sequence())
		}
		tl.Log.AddLeafToPool(&ctlog.LogEntry{Certificate: bytes.Repeat([]byte("A"), 2350)})
	}
}

var testLeaf, _ = base64.StdEncoding.DecodeString("MIIEJjCCAw6gAwIBAgISA9YVxv2Lcc/y6IhrW5svQmHPMA0GCSqGSIb3DQEBCwUAMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJSMzAeFw0yMzExMTUxMDE5MTFaFw0yNDAyMTMxMDE5MTBaMB0xGzAZBgNVBAMTEnJvbWUuY3QuZmlsaXBwby5pbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMufQMpi+5cCSw8a6D2se6bjTR6Vpcm5kr5b1UHaJZVdM4tOCy66d3iO9LcKYwIdXJJD1TbtzAuLlRCWa1HNlGSjggIUMIICEDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFIiqDtb1Rz6Y9iVID4JBRl36tE47MB8GA1UdIwQYMBaAFBQusxe3WFbLrlAJQOYfr52LFMLGMFUGCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL3IzLm8ubGVuY3Iub3JnMCIGCCsGAQUFBzAChhZodHRwOi8vcjMuaS5sZW5jci5vcmcvMB0GA1UdEQQWMBSCEnJvbWUuY3QuZmlsaXBwby5pbzATBgNVHSAEDDAKMAgGBmeBDAECATCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB2AEiw42vapkc0D+VqAvqdMOscUgHLVt0sgdm7v6s52IRzAAABi9K04WIAAAQDAEcwRQIhAIjFeq4LZpEUNCTtVu1s3yURyaX18TRp4qjt02A2FYHEAiBWQxxfEsyYUFuDOFIYSh6q6MA9m2YenRmL7FqzgpMvpAB2ADtTd3U+LbmAToswWwb+QDtn2E/D9Me9AA0tcm/h+tQXAAABi9K0418AAAQDAEcwRQIhAJfS1HrW24DPJJCzwZ+Xgo4jX/o6nsXNVRuOrrqoFjBmAiAi53R5tlmS94uXLnUyX6+ULDxwCuSRSb23iEidzugiVDANBgkqhkiG9w0BAQsFAAOCAQEAc0EXBRfCal3xyXZ60DJspRf66ulLpVii1BPvcf0PWWGC/MCjbY2xwz+1p6fePMSMrUJpOTtP5L52bZNQBptq6oKSOKGpVn8eIaVqNPeJsYCuzL5tKnzfhBoyIs9tqc8U7JwZuIyCIFsxd5eDNLSNyphX9+jxATorpFJ8RYibzjmBkDjRSl6T2f32Qy4AKy2FJe2yryJjdiDHqzT3SoTYcJp/2wWklYFMtBV/j4qTGyFiVdVZ1GQUhHvlw1iVqXLHe8cVQoSc+iStlDxeFWEuKnHRTtpfNz+KzP15R13C6CBswODDjqH2HCS2OKhyENB6SF7KhhD5/hMVyj6UWq9pDw==")
var testPrecert, _ = base64.StdEncoding.DecodeString("MIIDMzCCAhugAwIBAgISA9YVxv2Lcc/y6IhrW5svQmHPMA0GCSqGSIb3DQEBCwUAMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJSMzAeFw0yMzExMTUxMDE5MTFaFw0yNDAyMTMxMDE5MTBaMB0xGzAZBgNVBAMTEnJvbWUuY3QuZmlsaXBwby5pbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMufQMpi+5cCSw8a6D2se6bjTR6Vpcm5kr5b1UHaJZVdM4tOCy66d3iO9LcKYwIdXJJD1TbtzAuLlRCWa1HNlGSjggEhMIIBHTAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFIiqDtb1Rz6Y9iVID4JBRl36tE47MB8GA1UdIwQYMBaAFBQusxe3WFbLrlAJQOYfr52LFMLGMFUGCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0cDovL3IzLm8ubGVuY3Iub3JnMCIGCCsGAQUFBzAChhZodHRwOi8vcjMuaS5sZW5jci5vcmcvMB0GA1UdEQQWMBSCEnJvbWUuY3QuZmlsaXBwby5pbzATBgNVHSAEDDAKMAgGBmeBDAECATATBgorBgEEAdZ5AgQDAQH/BAIFADANBgkqhkiG9w0BAQsFAAOCAQEAk4K63mYRtOqH2LprGfBDIXnOXGt7wicdyBD2Zh5tkqMBB0XulcAi94IUfEOBSfIIzZ5lTh8WvAB6RxMGXYf8Qx4dHCP1McpMvkOJNEz9cHVjoBxx8asdAsV6d+av3MsK83n/fnN6looyUoDz09AZNvmlR74HCmpgLydMMv8ugdiPjRlYLaKy8wiA+HpX2rb4oWJ9kSD7dxuu6+NqPi4qWVsopQKBMcYEhCfQN26tcm2X3jebcwE3TFNxhK5RcRTWMO3i5AtaUZDT4bWUTFTHP8668wvCpI8MyfIlVdlUv3BOnyjvr/zpSBb/SfbyE0yiUBKhxl5z3+LImTNwxbc5sg==")
var testIntermediate, _ = base64.StdEncoding.DecodeString("MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAwWhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cPR5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdxsxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8ZutmNHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxgZ3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaAFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6WPTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wlikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQzCkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BImlJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1OyK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90IdshCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6ZvMldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqXnLRbwHOoq7hHwg==")
var testRoot, _ = base64.StdEncoding.DecodeString("MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygch77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6UA5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sWT8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyHB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UCB5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUvKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWnOlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTnjh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbwqHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CIrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkqhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZLubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KKNFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7UrTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdCjNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVcoyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPAmRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57demyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=")
