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

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

func TestMarkCertificates(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fatalIfErr(t, err)
	root := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	fatalIfErr(t, err)

	leaf := &x509.Certificate{
		SerialNumber:       big.NewInt(2),
		Subject:            pkix.Name{CommonName: "example.com"},
		NotBefore:          time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 31}},
	}
	markDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	fatalIfErr(t, err)

	leaf.SerialNumber = big.NewInt(3)
	leaf.UnknownExtKeyUsage = nil
	leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	tlsDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	fatalIfErr(t, err)

	submit := func(t *testing.T, mark bool, leafDER []byte) error {
		tl := NewEmptyTestLog(t)
		tl.Config.MarkCertificates = mark
		fatalIfErr(t, tl.Log.SetRootsFromPEM(t.Context(), pem.EncodeToMemory(
			&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})))
		_, err := tl.LogClient().AddChain(context.Background(), []ct.ASN1Cert{
			{Data: leafDER}, {Data: rootDER}})
		return err
	}

	if err := submit(t, true, markDER); err != nil {
		t.Errorf("mark log rejected mark certificate: %v", err)
	}
	if err := submit(t, true, tlsDER); err == nil {
		t.Error("mark log accepted TLS certificate")
	}
	if err := submit(t, false, markDER); err == nil {
		t.Error("TLS log accepted mark certificate")
	}
	if err := submit(t, false, tlsDER); err != nil {
		t.Errorf("TLS log rejected TLS certificate: %v", err)
	}
}
