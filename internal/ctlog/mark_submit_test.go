package ctlog_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"filippo.io/sunlight/internal/ctlog"
	ct "github.com/google/certificate-transparency-go"
	ctasn1 "github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

var testMarkCertificateEKU = ctasn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 31}

func TestSubmitCertificateProfiles(t *testing.T) {
	t.Run("mark accepts mark EKU", func(t *testing.T) {
		tl := NewEmptyTestLog(t)
		tl.Config.CertificateProfile = ctlog.CertificateProfileMark
		chain := newTestChain(t, nil, []ctasn1.ObjectIdentifier{testMarkCertificateEKU})
		setTestRoots(t, tl, chain.root)

		if _, err := tl.LogClient().AddChain(context.Background(), []ct.ASN1Cert{
			{Data: chain.leaf}, {Data: chain.root},
		}); err != nil {
			t.Fatalf("AddChain returned error: %v", err)
		}
	})

	t.Run("mark rejects serverAuth without mark EKU", func(t *testing.T) {
		tl := NewEmptyTestLog(t)
		tl.Config.CertificateProfile = ctlog.CertificateProfileMark
		chain := newTestChain(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
		setTestRoots(t, tl, chain.root)

		if _, err := tl.LogClient().AddChain(context.Background(), []ct.ASN1Cert{
			{Data: chain.leaf}, {Data: chain.root},
		}); err == nil {
			t.Fatal("AddChain succeeded for serverAuth certificate in mark profile")
		}
	})

	t.Run("TLS rejects mark-only EKU", func(t *testing.T) {
		tl := NewEmptyTestLog(t)
		chain := newTestChain(t, nil, []ctasn1.ObjectIdentifier{testMarkCertificateEKU})
		setTestRoots(t, tl, chain.root)

		if _, err := tl.LogClient().AddChain(context.Background(), []ct.ASN1Cert{
			{Data: chain.leaf}, {Data: chain.root},
		}); err == nil {
			t.Fatal("AddChain succeeded for mark-only certificate in TLS profile")
		}
	})

	t.Run("unknown profile rejects mark-only EKU", func(t *testing.T) {
		tl := NewEmptyTestLog(t)
		tl.Config.CertificateProfile = "unknown"
		chain := newTestChain(t, nil, []ctasn1.ObjectIdentifier{testMarkCertificateEKU})
		setTestRoots(t, tl, chain.root)

		if _, err := tl.LogClient().AddChain(context.Background(), []ct.ASN1Cert{
			{Data: chain.leaf}, {Data: chain.root},
		}); err == nil {
			t.Fatal("AddChain succeeded for mark-only certificate with unknown profile")
		}
	})
}

type generatedChain struct {
	root []byte
	leaf []byte
}

func newTestChain(t *testing.T, extKeyUsages []x509.ExtKeyUsage, unknownExtKeyUsages []ctasn1.ObjectIdentifier) generatedChain {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fatalIfErr(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	fatalIfErr(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fatalIfErr(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "example.test"},
		NotBefore:             time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           extKeyUsages,
		UnknownExtKeyUsage:    unknownExtKeyUsages,
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.test"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, &leafKey.PublicKey, rootKey)
	fatalIfErr(t, err)

	return generatedChain{root: rootDER, leaf: leafDER}
}

func setTestRoots(t *testing.T, tl *TestLog, root []byte) {
	t.Helper()
	fatalIfErr(t, tl.Log.SetRootsFromPEM(t.Context(), pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: root,
	})))
}
