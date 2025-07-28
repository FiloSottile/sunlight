package sunlight_test

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"

	"filippo.io/sunlight"
	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/mod/sumdb/tlog"
)

func ExampleClient_Entries() {
	block, _ := pem.Decode([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4i7AmqGoGHsorn/eyclTMjrAnM0J
UUbyGJUxXqq1AjQ4qBC77wXkWt7s/HA8An2vrEBKIGQzqTjV8QIHrmpd4w==
-----END PUBLIC KEY-----`))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: "https://navigli2025h2.skylight.geomys.org/",
		PublicKey:        key,
		UserAgent:        "ExampleClient (changeme@example.com, +https://example.com)",
	})
	if err != nil {
		panic(err)
	}

	var start int64
	for {
		checkpoint, _, err := client.Checkpoint(context.TODO())
		if err != nil {
			panic(err)
		}
		for i, entry := range client.Entries(context.TODO(), checkpoint.Tree, start) {
			fmt.Printf("%d: %d %d %x\n", i, entry.LeafIndex, entry.Timestamp, entry.IssuerKeyHash)
			start = i + 1
		}
		if err := client.Err(); err != nil {
			panic(err)
		}
	}
}

func ExampleClient_CheckInclusion() {
	block, _ := pem.Decode([]byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4i7AmqGoGHsorn/eyclTMjrAnM0J
UUbyGJUxXqq1AjQ4qBC77wXkWt7s/HA8An2vrEBKIGQzqTjV8QIHrmpd4w==
-----END PUBLIC KEY-----`))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	certificate, _ := pem.Decode([]byte(`-----BEGIN CERTIFICATE-----
MIID0DCCA1WgAwIBAgISLJBonEz2NlVeQFEPlG5vsIrMMAoGCCqGSM49BAMDMFMx
CzAJBgNVBAYTAlVTMSAwHgYDVQQKExcoU1RBR0lORykgTGV0J3MgRW5jcnlwdDEi
MCAGA1UEAxMZKFNUQUdJTkcpIEZhbHNlIEZlbm5lbCBFNjAeFw0yNTA3MjcyMjA4
NDlaFw0yNTEwMjUyMjA4NDhaMCMxITAfBgNVBAMTGGhhcmRlcnJhZGlvZm1qdW1w
LnJhZC5pbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCLE1WbEwJ1Y+k3bj+vf
R4s6nDem8eZea0vZ8sgJqh13mm89lHZZTr5l/qRRFbcl6fL8LJNw0vapzr3rpnTu
7NGjggI3MIICMzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEG
CCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFFvoTvFTQNkRzVpfP8JF
v0YNc908MB8GA1UdIwQYMBaAFKF0GgZtULeGLUoswX60jYhJbM0WMDYGCCsGAQUF
BwEBBCowKDAmBggrBgEFBQcwAoYaaHR0cDovL3N0Zy1lNi5pLmxlbmNyLm9yZy8w
IwYDVR0RBBwwGoIYaGFyZGVycmFkaW9mbWp1bXAucmFkLmlvMBMGA1UdIAQMMAow
CAYGZ4EMAQIBMDEGA1UdHwQqMCgwJqAkoCKGIGh0dHA6Ly9zdGctZTYuYy5sZW5j
ci5vcmcvNzcuY3JsMIIBDQYKKwYBBAHWeQIEAgSB/gSB+wD5AHYA3Zk0/KXnJIDJ
Vmh9gTSZCEmySfe1adjHvKs/XMHzbmQAAAGYTiQDlAAABAMARzBFAiAZaM/o9pZJ
AoaMVTaHqM6aViSIjLam0CiEe8OK5M8RTAIhANS+35smBUCZvpM+zRNwSQ1siDDm
f2F8ayHSru9+BTeEAH8A5Pt3SiEkxYZAsYMvUKv63ISjiu1xke62aSI3ksv2KJEA
AAGYTiQDpAAIAAAFAATjOI4EAwBIMEYCIQC9ARnxeUgUL8Gkvl1lgKkuFVJaAOkv
TQ6H8sYzVcbliQIhAN5nTObp15PQSusjd0Qd+povk1DJ4tVA9rNKFEGOpTVoMAoG
CCqGSM49BAMDA2kAMGYCMQCuw26zAJbmCgvfsDu9ong073LppgwPWogX1DI050uS
scMeHBWmB0jXuic4zkVzVBQCMQD+IkFkLg8qOHNtipO+mtTCtdW8mEl7Ptb3yv04
ybky1bC4rbimZJIjvhnqMcMkf/I=
-----END CERTIFICATE-----`))

	client, err := sunlight.NewClient(&sunlight.ClientConfig{
		MonitoringPrefix: "https://navigli2025h2.skylight.geomys.org/",
		PublicKey:        key,
		UserAgent:        "ExampleClient (changeme@example.com, +https://example.com)",
	})
	if err != nil {
		panic(err)
	}

	checkpoint, _, err := client.Checkpoint(context.TODO())
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(certificate.Bytes)
	if err != nil {
		panic(err)
	}
	for _, sct := range cert.SCTList.SCTList {
		entry, proof, err := client.CheckInclusion(context.TODO(), checkpoint.Tree, sct.Val)
		if errors.Is(err, sunlight.ErrWrongLogID) {
			println("SCT log ID does not match public key, skipping")
			continue
		}
		if err != nil {
			panic(err)
		}
		println("Entry leaf index:", entry.LeafIndex)
		println("Entry timestamp:", entry.Timestamp)

		// There is no need to check the inclusion proof, but if provided to a third
		// party, it can be checked as follows.
		rh := tlog.RecordHash(entry.MerkleTreeLeaf())
		if err := tlog.CheckRecord(proof, checkpoint.N, checkpoint.Hash, entry.LeafIndex, rh); err != nil {
			panic(err)
		}
	}
}
