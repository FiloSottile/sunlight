package chain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"slices"
	"testing"
)

func TestRoots(t *testing.T) {
	p := newTestPKI(t)
	leaf := p.leaf(t, nil)

	t.Run("no roots", func(t *testing.T) {
		_, err := (&Verifier{}).Verify([][]byte{leaf, p.intermediate.der}, false)
		expect(t, err, "unknown-root", 1)
		_, err = (&Verifier{Roots: &Roots{}}).Verify([][]byte{leaf, p.intermediate.der, p.root.der}, false)
		expect(t, err, "unknown-root", 2)
	})

	t.Run("added twice", func(t *testing.T) {
		roots := &Roots{}
		for range 2 {
			if err := roots.Add(p.root.der); err != nil {
				t.Fatal(err)
			}
		}
		if n := len(roots.named(p.root.cert.RawSubject)); n != 1 {
			t.Errorf("%d trust anchors after adding the same one twice", n)
		}
	})

	t.Run("copied", func(t *testing.T) {
		roots := &Roots{}
		der := slices.Clone(p.root.der)
		if err := roots.Add(der); err != nil {
			t.Fatal(err)
		}
		clear(der)
		verified, err := (&Verifier{Roots: roots}).Verify([][]byte{leaf, p.intermediate.der}, false)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(verified.Chain[2], p.root.der) {
			t.Error("trust anchor changed with the slice it was added from")
		}
	})

	t.Run("malformed", func(t *testing.T) {
		for _, der := range [][]byte{
			nil,
			{0x30, 0x00},
			p.root.der[:len(p.root.der)-1],
			append(slices.Clone(p.root.der), 0),
		} {
			if err := (&Roots{}).Add(der); err == nil {
				t.Errorf("accepted %x", der)
			}
		}
	})

	t.Run("keys", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		expect(t, (&Roots{}).Add(newCA(t, "RSA", rsaKey, nil, nil).der), "", 0)

		_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		expect(t, (&Roots{}).Add(newCA(t, "Ed25519", ed25519Key, nil, nil).der), "unsupported-key", -1)
	})

	t.Run("signature algorithms", func(t *testing.T) {
		// A certificate for an ECDSA key that is signed with Ed25519.
		_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ed25519Root := newCA(t, "Ed25519", ed25519Key, nil, nil)
		expect(t, (&Roots{}).Add(newCA(t, "Cross-signed", newKey(t), ed25519Root, nil).der), "unsupported-sigalg", -1)

		// crypto/x509 does not sign with MD2, MD5, or SHA-224. The signature
		// of a trust anchor is not verified, so the OID of
		// sha256WithRSAEncryption is replaced with theirs in a certificate
		// that it did sign.
		rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatal(err)
		}
		root := newCA(t, "RSA", rsaKey, nil, nil).der
		oid := func(last int) []byte {
			der, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, last})
			if err != nil {
				t.Fatal(err)
			}
			return der
		}
		for _, tt := range []struct {
			name   string
			oid    []byte
			reason string
		}{
			{"md2WithRSAEncryption", oid(2), ""},
			{"md5WithRSAEncryption", oid(4), ""},
			{"sha224WithRSAEncryption", oid(14), ""},
			{"sha512-224WithRSAEncryption", oid(15), "unsupported-sigalg"},
		} {
			t.Run(tt.name, func(t *testing.T) {
				der := bytes.ReplaceAll(root, oid(11), tt.oid)
				if bytes.Equal(der, root) {
					t.Fatal("the certificate is not signed with sha256WithRSAEncryption")
				}
				expect(t, (&Roots{}).Add(der), tt.reason, -1)
			})
		}
	})

	t.Run("Precertificate Signing Certificate", func(t *testing.T) {
		precertificateSigning := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
		for _, known := range [][]x509.ExtKeyUsage{nil, {x509.ExtKeyUsageServerAuth}} {
			preissuer := newCA(t, "Preissuer", newKey(t), p.root, func(c *x509.Certificate) {
				c.ExtKeyUsage, c.UnknownExtKeyUsage = known, []asn1.ObjectIdentifier{precertificateSigning}
			})
			expect(t, (&Roots{}).Add(preissuer.der), "preissuer", -1)
		}
	})

	// Only the subject and the key of a trust anchor are used.

	t.Run("intermediate as a trust anchor", func(t *testing.T) {
		roots := &Roots{}
		if err := roots.Add(p.intermediate.der); err != nil {
			t.Fatal(err)
		}
		v := &Verifier{Roots: roots, ExtKeyUsage: ServerAuth}
		for _, chain := range [][][]byte{{leaf}, {leaf, p.intermediate.der}} {
			verified, err := v.Verify(chain, false)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.EqualFunc(verified.Chain, [][]byte{leaf, p.intermediate.der}, bytes.Equal) {
				t.Error("chain is not the leaf and the trust anchor")
			}
		}
		// The root that issued the trust anchor is not one.
		_, err := v.Verify([][]byte{leaf, p.intermediate.der, p.root.der}, false)
		expect(t, err, "unknown-root", 2)
	})

	t.Run("trust anchor that is not a CA", func(t *testing.T) {
		key := newKey(t)
		anchor := newCA(t, "Not a CA", key, nil, func(c *x509.Certificate) {
			c.BasicConstraintsValid, c.IsCA, c.KeyUsage = false, false, 0
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
			c.NotBefore, c.NotAfter = testNotBefore.AddDate(-30, 0, 0), testNotBefore.AddDate(-20, 0, 0)
		})
		roots := &Roots{}
		if err := roots.Add(anchor.der); err != nil {
			t.Fatal(err)
		}
		leaf := anchor.issue(t, leafTemplate(), newKey(t).Public())
		v := &Verifier{Roots: roots, ExtKeyUsage: ServerAuth}
		_, err := v.Verify([][]byte{leaf}, false)
		expect(t, err, "", 0)
		_, err = v.Verify([][]byte{leaf, anchor.der}, false)
		expect(t, err, "", 0)
	})

	t.Run("trust anchor on its own", func(t *testing.T) {
		roots := &Roots{}
		if err := roots.Add(p.root.der); err != nil {
			t.Fatal(err)
		}
		// The root has no extKeyUsage, like the leaf would need.
		_, err := (&Verifier{Roots: roots, ExtKeyUsage: ServerAuth}).Verify([][]byte{p.root.der}, false)
		expect(t, err, "eku", 0)
		verified, err := (&Verifier{Roots: roots}).Verify([][]byte{p.root.der}, false)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.EqualFunc(verified.Chain, [][]byte{p.root.der}, bytes.Equal) || !bytes.Equal(verified.Root, p.root.cert.RawSubject) {
			t.Error("chain is not the trust anchor alone")
		}
		_, err = (&Verifier{Roots: roots}).Verify([][]byte{p.root.der}, true)
		expect(t, err, "endpoint-mismatch", 0)
	})
}
