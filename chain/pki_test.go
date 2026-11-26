package chain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"
	"time"
)

// The tests in this file and in verify_test.go make their certificates with
// crypto/x509, so they only cover what a well-behaved CA produces.

var (
	testNotBefore = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	testNotAfter  = time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)

	poisonExtension = pkix.Extension{
		Id:       asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3},
		Critical: true,
		Value:    []byte{0x05, 0x00},
	}
)

// A testCA is a certificate that issues other certificates.
type testCA struct {
	der  []byte
	cert *x509.Certificate
	key  crypto.Signer
}

func newKey(t testing.TB) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

var serial atomic.Int64

// issue returns a certificate for pub made from template and signed by ca.
// The template gets a serial number if it does not have one, so that a
// template can be issued twice with the same one.
func (ca *testCA) issue(t testing.TB, template *x509.Certificate, pub crypto.PublicKey) []byte {
	t.Helper()
	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(serial.Add(1))
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// newCA returns a CA with the given key, issued by parent, or self-signed if
// parent is nil. modify, if not nil, changes the template first.
func newCA(t testing.TB, name string, key crypto.Signer, parent *testCA, modify func(*x509.Certificate)) *testCA {
	t.Helper()
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             testNotBefore.AddDate(-1, 0, 0),
		NotAfter:              testNotAfter.AddDate(10, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if modify != nil {
		modify(template)
	}
	ca := &testCA{key: key}
	if parent == nil {
		template.SerialNumber = big.NewInt(serial.Add(1))
		parent = &testCA{cert: template, key: key}
	}
	ca.der = parent.issue(t, template, key.Public())
	var err error
	if ca.cert, err = x509.ParseCertificate(ca.der); err != nil {
		t.Fatal(err)
	}
	return ca
}

// leafTemplate returns the template of a server certificate.
func leafTemplate() *x509.Certificate {
	return &x509.Certificate{
		Subject:               pkix.Name{CommonName: "leaf.example"},
		DNSNames:              []string{"leaf.example"},
		NotBefore:             testNotBefore,
		NotAfter:              testNotAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
}

// A testPKI is a root, an intermediate it issued, and a Verifier that trusts
// the root and requires ServerAuth.
type testPKI struct {
	root, intermediate *testCA
	verifier           *Verifier
}

func newTestPKI(t testing.TB) *testPKI {
	t.Helper()
	p := &testPKI{}
	p.root = newCA(t, "Root", newKey(t), nil, nil)
	p.intermediate = newCA(t, "Intermediate", newKey(t), p.root, nil)
	roots := &Roots{}
	if err := roots.Add(p.root.der); err != nil {
		t.Fatal(err)
	}
	p.verifier = &Verifier{Roots: roots, ExtKeyUsage: ServerAuth}
	return p
}

// leaf returns a certificate issued by the intermediate from leafTemplate,
// after modify, if not nil, changed it.
func (p *testPKI) leaf(t testing.TB, modify func(*x509.Certificate)) []byte {
	t.Helper()
	template := leafTemplate()
	if modify != nil {
		modify(template)
	}
	return p.intermediate.issue(t, template, newKey(t).Public())
}

func keyHash(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}

// expect checks that err is the rejection with the given reason about the
// given certificate, or that it is nil if reason is empty.
func expect(t testing.TB, err error, reason string, certificate int) {
	t.Helper()
	if reason == "" {
		if err != nil {
			t.Errorf("rejected: %v", err)
		}
		return
	}
	var rejection *Error
	switch {
	case err == nil:
		t.Errorf("accepted, want %s", reason)
	case !errors.As(err, &rejection):
		t.Errorf("error is not an *Error: %v", err)
	case rejection.Reason != reason || rejection.Certificate != certificate:
		t.Errorf("rejected with %s for certificate %d, want %s for certificate %d: %v",
			rejection.Reason, rejection.Certificate, reason, certificate, err)
	}
}
