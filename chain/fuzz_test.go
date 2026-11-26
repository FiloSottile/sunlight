package chain

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
)

func FuzzVerify(f *testing.F) {
	p := newTestPKI(f)
	f.Add(p.leaf(f, nil), p.intermediate.der, false)
	f.Add(p.leaf(f, func(c *x509.Certificate) {
		c.ExtraExtensions = []pkix.Extension{poisonExtension}
	}), p.intermediate.der, true)
	f.Add(p.intermediate.der, p.root.der, false)

	f.Fuzz(func(t *testing.T, leaf, issuer []byte, precertificate bool) {
		chain := [][]byte{leaf, issuer}
		verified, err := p.verifier.Verify(chain, precertificate)
		if err != nil {
			var rejection *Error
			if !errors.As(err, &rejection) || rejection.Reason == "" {
				t.Fatalf("error is not an *Error with a Reason: %v", err)
			}
			return
		}
		if len(verified.Chain) < 2 || !bytes.Equal(verified.Chain[0], leaf) || !bytes.Equal(verified.Chain[1], issuer) {
			t.Fatal("verified chain is not the submitted one")
		}
		if p.verifier.Roots.get(verified.Chain[len(verified.Chain)-1]) == nil {
			t.Fatal("verified chain does not end with a trust anchor")
		}
		if (verified.TBSCertificate != nil) != precertificate {
			t.Fatal("TBSCertificate does not match precertificate")
		}
	})
}
