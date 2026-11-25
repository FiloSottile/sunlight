package chain

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	ecdsaKey := func(curve elliptic.Curve) func() crypto.Signer {
		return func() crypto.Signer {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}
	}
	rsaKey := func() crypto.Signer {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	for _, tt := range []struct {
		name string
		key  func() crypto.Signer
		alg  x509.SignatureAlgorithm
	}{
		{"ECDSA P-256", ecdsaKey(elliptic.P256()), x509.ECDSAWithSHA256},
		{"ECDSA P-384", ecdsaKey(elliptic.P384()), x509.ECDSAWithSHA384},
		{"ECDSA P-521", ecdsaKey(elliptic.P521()), x509.ECDSAWithSHA512},
		{"ECDSA P-256 with SHA-512", ecdsaKey(elliptic.P256()), x509.ECDSAWithSHA512},
		{"RSA", rsaKey, x509.SHA256WithRSA},
		{"RSA with SHA-512", rsaKey, x509.SHA512WithRSA},
		{"RSA-PSS", rsaKey, x509.SHA384WithRSAPSS},
	} {
		t.Run(tt.name, func(t *testing.T) {
			alg := func(c *x509.Certificate) { c.SignatureAlgorithm = tt.alg }
			root := newCA(t, "Root", tt.key(), nil, alg)
			intermediate := newCA(t, "Intermediate", tt.key(), root, alg)
			template := leafTemplate()
			template.SignatureAlgorithm = tt.alg
			leaf := intermediate.issue(t, template, newKey(t).Public())
			cert, err := x509.ParseCertificate(leaf)
			if err != nil {
				t.Fatal(err)
			}
			roots := &Roots{}
			if err := roots.Add(root.der); err != nil {
				t.Fatal(err)
			}
			v := &Verifier{Roots: roots, ExtKeyUsage: ServerAuth}

			// The trust anchor is in the result whether it was submitted or not.
			want := [][]byte{leaf, intermediate.der, root.der}
			for _, chain := range [][][]byte{want[:2], want} {
				verified, err := v.Verify(chain, false)
				if err != nil {
					t.Fatal(err)
				}
				if !slices.EqualFunc(verified.Chain, want, bytes.Equal) {
					t.Errorf("got a chain of %d certificates, want the submitted ones and the root", len(verified.Chain))
				}
				if !bytes.Equal(verified.Issuer, cert.RawIssuer) {
					t.Errorf("Issuer = %x, want %x", verified.Issuer, cert.RawIssuer)
				}
				if !bytes.Equal(verified.Root, root.cert.RawSubject) {
					t.Errorf("Root = %x, want %x", verified.Root, root.cert.RawSubject)
				}
				if !verified.NotBefore.Equal(cert.NotBefore) || !verified.NotAfter.Equal(cert.NotAfter) {
					t.Errorf("validity = %v to %v, want %v to %v", verified.NotBefore, verified.NotAfter, cert.NotBefore, cert.NotAfter)
				}
				if verified.SCTs || verified.TBSCertificate != nil || verified.IssuerKeyHash != [32]byte{} {
					t.Errorf("SCTs, TBSCertificate, or IssuerKeyHash set for a certificate without SCTs")
				}
			}
			if !bytes.Equal(want[2], root.der) {
				t.Error("Verify changed the slice it was passed")
			}
		})
	}
}

func TestVerifyDetails(t *testing.T) {
	p := newTestPKI(t)

	t.Run("issued by the root", func(t *testing.T) {
		leaf := p.root.issue(t, leafTemplate(), newKey(t).Public())
		verified, err := p.verifier.Verify([][]byte{leaf}, false)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.EqualFunc(verified.Chain, [][]byte{leaf, p.root.der}, bytes.Equal) {
			t.Error("chain is not the leaf and the root")
		}
	})

	t.Run("SCTs", func(t *testing.T) {
		leaf := p.leaf(t, func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
				Value: []byte{0x04, 0x02, 0x00, 0x00},
			}}
		})
		verified, err := p.verifier.Verify([][]byte{leaf, p.intermediate.der}, false)
		if err != nil {
			t.Fatal(err)
		}
		if !verified.SCTs {
			t.Error("SCTs is false for a certificate with an SCT list")
		}
	})

	t.Run("chain with spare capacity", func(t *testing.T) {
		// Adding the root to the result must not write to the array of the
		// slice that was passed.
		array := [][]byte{p.leaf(t, nil), p.intermediate.der, []byte("untouched")}
		if _, err := p.verifier.Verify(array[:2], false); err != nil {
			t.Fatal(err)
		}
		if string(array[2]) != "untouched" {
			t.Error("Verify wrote past the end of the chain")
		}
	})

	t.Run("concurrent", func(t *testing.T) {
		chain := [][]byte{p.leaf(t, nil), p.intermediate.der}
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				for range 20 {
					if _, err := p.verifier.Verify(chain, false); err != nil {
						t.Error(err)
					}
				}
			})
		}
		wg.Wait()
	})
}

// TestPrecertificate checks the TBSCertificate of the log entry against
// the one crypto/x509 makes when the same certificate is issued without the
// poison, which is what the Baseline Requirements, Section 7.1.2.9.1, require
// them to be.
func TestPrecertificate(t *testing.T) {
	p := newTestPKI(t)
	p.verifier.ExtKeyUsage = ""
	key := newKey(t).Public()
	padding := func(arc, n int) pkix.Extension {
		return pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, arc}, Value: bytes.Repeat([]byte{0x41}, n)}
	}

	// check issues template twice, with and without the poison as extension
	// number at of extra, and returns the sizes of the two TBSCertificates.
	check := func(t *testing.T, template *x509.Certificate, extra []pkix.Extension, at int) (precertificate, final int) {
		t.Helper()
		template.SerialNumber = big.NewInt(serial.Add(1))
		template.ExtraExtensions = extra
		want, err := x509.ParseCertificate(p.intermediate.issue(t, template, key))
		if err != nil {
			t.Fatal(err)
		}
		template.ExtraExtensions = slices.Insert(slices.Clone(extra), at, poisonExtension)
		pre := p.intermediate.issue(t, template, key)
		cert, err := x509.ParseCertificate(pre)
		if err != nil {
			t.Fatal(err)
		}

		verified, err := p.verifier.Verify([][]byte{pre, p.intermediate.der}, true)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(verified.TBSCertificate, want.RawTBSCertificate) {
			t.Errorf("TBSCertificate is not the one of the certificate\ngot:  %x\nwant: %x", verified.TBSCertificate, want.RawTBSCertificate)
		}
		if verified.IssuerKeyHash != keyHash(p.intermediate.cert) {
			t.Errorf("IssuerKeyHash is not the hash of the key of the intermediate")
		}
		if !slices.EqualFunc(verified.Chain, [][]byte{pre, p.intermediate.der, p.root.der}, bytes.Equal) {
			t.Errorf("chain is not the precertificate, the intermediate, and the root")
		}
		return len(cert.RawTBSCertificate), len(want.RawTBSCertificate)
	}

	t.Run("position", func(t *testing.T) {
		extra := []pkix.Extension{padding(1, 5), padding(2, 7)}
		for at := range len(extra) + 1 {
			check(t, leafTemplate(), extra, at)
		}
		check(t, leafTemplate(), nil, 0)
	})

	t.Run("issued by the root", func(t *testing.T) {
		template := leafTemplate()
		template.ExtraExtensions = []pkix.Extension{poisonExtension}
		pre := p.root.issue(t, template, key)
		verified, err := p.verifier.Verify([][]byte{pre}, true)
		if err != nil {
			t.Fatal(err)
		}
		if verified.IssuerKeyHash != keyHash(p.root.cert) {
			t.Errorf("IssuerKeyHash is not the hash of the key of the root")
		}
	})

	// Removing the poison changes the length of the extensions, of the field
	// that wraps them, and of the TBSCertificate. Go through the sizes at
	// which the encodings of those lengths get shorter.
	minimal := func() *x509.Certificate {
		return &x509.Certificate{NotBefore: testNotBefore, NotAfter: testNotAfter}
	}
	crossed := func(t *testing.T, boundary, from, to int) {
		t.Helper()
		var seen bool
		for n := from; n < to; n++ {
			precertificate, final := check(t, minimal(), []pkix.Extension{padding(1, n)}, n%2)
			seen = seen || precertificate >= boundary && final < boundary
		}
		if !seen {
			t.Errorf("no TBSCertificate went from %d bytes or more to less", boundary)
		}
	}
	t.Run("short lengths", func(t *testing.T) {
		crossed(t, 256, 0, 300)
	})
	t.Run("long lengths", func(t *testing.T) {
		_, size := check(t, minimal(), nil, 0)
		crossed(t, 65536, 65536-size-60, 65536-size+10)
	})

	t.Run("only the poison", func(t *testing.T) {
		// crypto/x509 adds an authorityKeyIdentifier unless the issuer has no
		// subjectKeyIdentifier.
		issuer := *p.intermediate.cert
		issuer.SubjectKeyId = nil
		ca := &testCA{cert: &issuer, key: p.intermediate.key}
		template := minimal()
		want, err := x509.ParseCertificate(ca.issue(t, template, key))
		if err != nil {
			t.Fatal(err)
		}
		if len(want.Extensions) != 0 {
			t.Fatalf("certificate has %d extensions, want none", len(want.Extensions))
		}
		template.ExtraExtensions = []pkix.Extension{poisonExtension}
		verified, err := p.verifier.Verify([][]byte{ca.issue(t, template, key), p.intermediate.der}, true)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(verified.TBSCertificate, want.RawTBSCertificate) {
			t.Errorf("TBSCertificate is not the one of the certificate\ngot:  %x\nwant: %x", verified.TBSCertificate, want.RawTBSCertificate)
		}
	})
}

func TestLeaf(t *testing.T) {
	p := newTestPKI(t)
	start, limit := testNotAfter.Add(-time.Hour), testNotAfter.Add(time.Hour)
	notAfter := func(at time.Time) func(*x509.Certificate) {
		return func(c *x509.Certificate) { c.NotAfter = at }
	}
	poison := func(c *x509.Certificate) { c.ExtraExtensions = []pkix.Extension{poisonExtension} }
	markCertificate := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 31}

	for _, tt := range []struct {
		name           string
		leaf           func(*x509.Certificate)
		verifier       func(*Verifier)
		precertificate bool
		reason         string
	}{
		{name: "no range"},

		{name: "NotAfter at the start of the range", leaf: notAfter(start),
			verifier: func(v *Verifier) { v.NotAfterStart, v.NotAfterLimit = start, limit }},
		{name: "NotAfter before the start of the range", leaf: notAfter(start.Add(-time.Second)),
			verifier: func(v *Verifier) { v.NotAfterStart, v.NotAfterLimit = start, limit }, reason: "not-after-range"},
		{name: "NotAfter before the limit of the range", leaf: notAfter(limit.Add(-time.Second)),
			verifier: func(v *Verifier) { v.NotAfterStart, v.NotAfterLimit = start, limit }},
		{name: "NotAfter at the limit of the range", leaf: notAfter(limit),
			verifier: func(v *Verifier) { v.NotAfterStart, v.NotAfterLimit = start, limit }, reason: "not-after-range"},
		{name: "start only", leaf: notAfter(start.Add(-time.Second)),
			verifier: func(v *Verifier) { v.NotAfterStart = start }, reason: "not-after-range"},
		{name: "limit only", leaf: notAfter(limit),
			verifier: func(v *Verifier) { v.NotAfterLimit = limit }, reason: "not-after-range"},
		{name: "expired long ago", leaf: func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2002, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
		{name: "not valid yet", leaf: func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2041, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
		{name: "NotAfter in 2050", leaf: notAfter(time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC)),
			verifier: func(v *Verifier) { v.NotAfterLimit = limit }, reason: "not-after-range"},

		{name: "no extKeyUsage", leaf: func(c *x509.Certificate) { c.ExtKeyUsage = nil }, reason: "eku"},
		{name: "another purpose", leaf: func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}, reason: "eku"},
		{name: "anyExtendedKeyUsage", leaf: func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		}, reason: "eku"},
		{name: "purpose among others", leaf: func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageServerAuth}
		}},
		{name: "no purpose required", leaf: func(c *x509.Certificate) { c.ExtKeyUsage = nil },
			verifier: func(v *Verifier) { v.ExtKeyUsage = "" }},
		{name: "mark certificate", leaf: func(c *x509.Certificate) {
			c.ExtKeyUsage, c.UnknownExtKeyUsage = nil, []asn1.ObjectIdentifier{markCertificate}
		}, verifier: func(v *Verifier) { v.ExtKeyUsage = BrandIndicatorForMessageIdentification }},
		{name: "server certificate for a mark certificate log",
			verifier: func(v *Verifier) { v.ExtKeyUsage = BrandIndicatorForMessageIdentification }, reason: "eku"},

		{name: "precertificate", leaf: poison, precertificate: true},
		{name: "precertificate as a certificate", leaf: poison, reason: "endpoint-mismatch"},
		{name: "certificate as a precertificate", precertificate: true, reason: "endpoint-mismatch"},
		{name: "poison that is not critical", leaf: func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: poisonExtension.Id, Value: poisonExtension.Value}}
		}, precertificate: true, reason: "poison-malformed"},
		{name: "poison that is not NULL", leaf: func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: poisonExtension.Id, Critical: true, Value: []byte{0x04, 0x00}}}
		}, precertificate: true, reason: "poison-malformed"},
		{name: "two poisons", leaf: func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{poisonExtension, poisonExtension}
		}, precertificate: true, reason: "ext-duplicate"},

		{name: "unknown critical extension", leaf: func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{0x05, 0x00}}}
		}},
		{name: "CA certificate", leaf: func(c *x509.Certificate) {
			c.IsCA, c.KeyUsage = true, x509.KeyUsageCertSign
		}},
		{name: "no subject alternative names", leaf: func(c *x509.Certificate) { c.DNSNames = nil }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := *p.verifier
			if tt.verifier != nil {
				tt.verifier(&v)
			}
			_, err := v.Verify([][]byte{p.leaf(t, tt.leaf), p.intermediate.der}, tt.precertificate)
			expect(t, err, tt.reason, 0)
		})
	}

	t.Run("key types", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.verifier.Verify([][]byte{p.intermediate.issue(t, leafTemplate(), &rsaKey.PublicKey), p.intermediate.der}, false)
		expect(t, err, "", 0)

		ed25519Key, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.verifier.Verify([][]byte{p.intermediate.issue(t, leafTemplate(), ed25519Key), p.intermediate.der}, false)
		expect(t, err, "unsupported-key", 0)
	})
}

func TestIntermediates(t *testing.T) {
	p := newTestPKI(t)
	poison := func(c *x509.Certificate) { c.ExtraExtensions = []pkix.Extension{poisonExtension} }
	purposes := func(purposes ...x509.ExtKeyUsage) func(*x509.Certificate) {
		return func(c *x509.Certificate) { c.ExtKeyUsage = purposes }
	}
	precertificateSigning := func(c *x509.Certificate) {
		c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}}
	}

	for _, tt := range []struct {
		name           string
		intermediate   func(*x509.Certificate)
		leaf           func(*x509.Certificate)
		verifier       func(*Verifier)
		precertificate bool
		reason         string
	}{
		{name: "plain"},

		{name: "no basicConstraints", intermediate: func(c *x509.Certificate) {
			c.BasicConstraintsValid, c.IsCA = false, false
		}, reason: "not-ca"},
		{name: "basicConstraints without cA", intermediate: func(c *x509.Certificate) { c.IsCA = false }, reason: "not-ca"},
		{name: "server certificate", intermediate: func(c *x509.Certificate) {
			*c = *leafTemplate()
			c.Subject.CommonName = "issuer.example"
		}, reason: "not-ca"},
		{name: "keyUsage without keyCertSign", intermediate: func(c *x509.Certificate) {
			c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign
		}, reason: "no-certsign"},
		{name: "no keyUsage", intermediate: func(c *x509.Certificate) { c.KeyUsage = 0 }},

		{name: "extKeyUsage with the purpose", intermediate: purposes(x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth)},
		{name: "extKeyUsage with anyExtendedKeyUsage", intermediate: purposes(x509.ExtKeyUsageAny)},
		{name: "extKeyUsage without the purpose", intermediate: purposes(x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageClientAuth),
			reason: "eku-nesting"},
		{name: "extKeyUsage without the purpose, none required", intermediate: purposes(x509.ExtKeyUsageEmailProtection),
			verifier: func(v *Verifier) { v.ExtKeyUsage = "" }},
		{name: "extKeyUsage for another log", intermediate: purposes(x509.ExtKeyUsageServerAuth),
			leaf: func(c *x509.Certificate) {
				c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 31}}
			},
			verifier: func(v *Verifier) { v.ExtKeyUsage = BrandIndicatorForMessageIdentification }, reason: "eku-nesting"},

		{name: "Precertificate Signing Certificate", intermediate: precertificateSigning,
			leaf: poison, precertificate: true, reason: "preissuer"},
		{name: "Precertificate Signing Certificate, no purpose required", intermediate: precertificateSigning,
			leaf: poison, precertificate: true, verifier: func(v *Verifier) { v.ExtKeyUsage = "" }, reason: "preissuer"},
		{name: "certificate issued by a Precertificate Signing Certificate", intermediate: precertificateSigning,
			reason: "eku-nesting"},

		// Things that are not checked.
		{name: "expired", intermediate: func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2002, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
		{name: "name constraints", intermediate: func(c *x509.Certificate) {
			c.PermittedDNSDomainsCritical, c.PermittedDNSDomains = true, []string{"other.example"}
		}},
		{name: "unknown critical extension", intermediate: func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{0x05, 0x00}}}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			intermediate := newCA(t, "Other Intermediate", newKey(t), p.root, tt.intermediate)
			template := leafTemplate()
			if tt.leaf != nil {
				tt.leaf(template)
			}
			leaf := intermediate.issue(t, template, newKey(t).Public())

			v := *p.verifier
			if tt.verifier != nil {
				tt.verifier(&v)
			}
			_, err := v.Verify([][]byte{leaf, intermediate.der}, tt.precertificate)
			expect(t, err, tt.reason, 1)
		})
	}

	t.Run("path length", func(t *testing.T) {
		// The intermediate is not allowed to issue CAs, and that is not
		// checked.
		limited := newCA(t, "Limited", newKey(t), p.root, func(c *x509.Certificate) { c.MaxPathLenZero = true })
		below := newCA(t, "Below", newKey(t), limited, nil)
		leaf := below.issue(t, leafTemplate(), newKey(t).Public())
		_, err := p.verifier.Verify([][]byte{leaf, below.der, limited.der}, false)
		expect(t, err, "", 0)
	})

	t.Run("the purpose is excluded further up", func(t *testing.T) {
		upper := newCA(t, "Upper", newKey(t), p.root, purposes(x509.ExtKeyUsageEmailProtection))
		lower := newCA(t, "Lower", newKey(t), upper, nil)
		leaf := lower.issue(t, leafTemplate(), newKey(t).Public())
		_, err := p.verifier.Verify([][]byte{leaf, lower.der, upper.der}, false)
		expect(t, err, "eku-nesting", 2)
	})

	t.Run("Ed25519", func(t *testing.T) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		intermediate := newCA(t, "Ed25519", key, p.root, nil)
		leaf := intermediate.issue(t, leafTemplate(), newKey(t).Public())
		// The signature algorithm of the leaf is the first thing that is not
		// supported.
		_, err = p.verifier.Verify([][]byte{leaf, intermediate.der}, false)
		expect(t, err, "unsupported-sigalg", 0)
	})
}

// TestLongExtKeyUsage checks that verifying a chain does not allocate for
// every purpose in an extKeyUsage extension, which is read before any
// signature is verified and can be almost as long as the request.
func TestLongExtKeyUsage(t *testing.T) {
	p := newTestPKI(t)
	chain := func(extra int) [][]byte {
		// The required purpose comes after all the others.
		purposes := func(c *x509.Certificate) {
			c.ExtKeyUsage, c.UnknownExtKeyUsage = nil, nil
			for i := range extra {
				c.UnknownExtKeyUsage = append(c.UnknownExtKeyUsage, asn1.ObjectIdentifier{1, 2, 3, i})
			}
			c.UnknownExtKeyUsage = append(c.UnknownExtKeyUsage, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})
		}
		intermediate := newCA(t, "Other Intermediate", newKey(t), p.root, purposes)
		template := leafTemplate()
		purposes(template)
		return [][]byte{intermediate.issue(t, template, newKey(t).Public()), intermediate.der}
	}
	allocs := func(chain [][]byte) float64 {
		return testing.AllocsPerRun(10, func() {
			if _, err := p.verifier.Verify(chain, false); err != nil {
				t.Fatal(err)
			}
		})
	}
	if short, long := allocs(chain(0)), allocs(chain(1000)); long > short+100 {
		t.Errorf("%v allocations with 1000 more purposes in each certificate, %v without", long, short)
	}
}

func TestChain(t *testing.T) {
	p := newTestPKI(t)
	leaf := p.leaf(t, nil)
	// A hierarchy with other names, and one with the same names and other
	// keys.
	otherRoot := newCA(t, "Other Root", newKey(t), nil, nil)
	otherIntermediate := newCA(t, "Other Intermediate", newKey(t), otherRoot, nil)
	same := newTestPKI(t)
	sameLeaf := same.leaf(t, nil)
	// An intermediate with the name of the real one, also issued by the root,
	// that did not sign the leaf.
	impostor := newCA(t, "Intermediate", newKey(t), p.root, nil)
	// Another self-signed certificate with the name and the key of the root,
	// which is not a trust anchor.
	reissued := newCA(t, "Root", p.root.key, nil, nil)

	var eleven [][]byte
	for i := range 11 {
		eleven = append(eleven, []byte{byte(i)})
	}

	for _, tt := range []struct {
		name        string
		chain       [][]byte
		reason      string
		certificate int
	}{
		{"root omitted", [][]byte{leaf, p.intermediate.der}, "", 0},
		{"root included", [][]byte{leaf, p.intermediate.der, p.root.der}, "", 0},

		{"empty", nil, "empty-chain", -1},
		{"eleven certificates", eleven, "chain-too-long", -1},
		{"leaf twice", [][]byte{leaf, leaf, p.intermediate.der}, "duplicate-cert", 1},
		{"intermediate twice", [][]byte{leaf, p.intermediate.der, p.intermediate.der}, "duplicate-cert", 2},
		{"root twice", [][]byte{leaf, p.intermediate.der, p.root.der, p.root.der}, "duplicate-cert", 3},
		{"not a certificate", [][]byte{[]byte("leaf"), p.intermediate.der}, "outer-not-der", 0},

		{"no intermediate", [][]byte{leaf}, "unknown-root", 0},
		{"intermediate first", [][]byte{p.intermediate.der, leaf}, "eku", 0},
		{"unrelated certificate after the leaf", [][]byte{leaf, otherIntermediate.der, p.intermediate.der}, "name-mismatch", 0},
		{"unrelated certificate after the intermediate", [][]byte{leaf, p.intermediate.der, otherIntermediate.der}, "name-mismatch", 1},
		{"another root", [][]byte{leaf, p.intermediate.der, otherRoot.der}, "name-mismatch", 1},
		{"intermediate with the same name and another key", [][]byte{leaf, impostor.der}, "bad-signature", 0},

		{"root with the same name and another key, omitted", [][]byte{sameLeaf, same.intermediate.der}, "bad-signature", 1},
		{"root with the same name and another key, included", [][]byte{sameLeaf, same.intermediate.der, same.root.der}, "bad-signature", 2},

		// The root is looked up for the reissued certificate. It can't be
		// added to a chain it is already in.
		{"reissued root", [][]byte{leaf, p.intermediate.der, reissued.der}, "", 0},
		{"reissued root before the root", [][]byte{leaf, p.intermediate.der, reissued.der, p.root.der}, "", 0},
		{"reissued root after the root", [][]byte{leaf, p.intermediate.der, p.root.der, reissued.der}, "duplicate-cert", 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.verifier.Verify(tt.chain, false)
			expect(t, err, tt.reason, tt.certificate)
		})
	}

	t.Run("two trust anchors with the same name and key", func(t *testing.T) {
		// The one that is not in the chain is the one that is added to it.
		for _, anchors := range [][][]byte{{p.root.der, reissued.der}, {reissued.der, p.root.der}} {
			roots := &Roots{}
			for _, der := range anchors {
				if err := roots.Add(der); err != nil {
					t.Fatal(err)
				}
			}
			again := newCA(t, "Root", p.root.key, nil, nil)
			chain := [][]byte{leaf, p.intermediate.der, p.root.der, again.der}
			verified, err := (&Verifier{Roots: roots, ExtKeyUsage: ServerAuth}).Verify(chain, false)
			if err != nil {
				t.Fatal(err)
			}
			if want := append(slices.Clone(chain), reissued.der); !slices.EqualFunc(verified.Chain, want, bytes.Equal) {
				t.Error("chain is not the submitted one and the trust anchor that was not in it")
			}
		}
	})

	t.Run("root with another name", func(t *testing.T) {
		leaf := otherIntermediate.issue(t, leafTemplate(), newKey(t).Public())
		_, err := p.verifier.Verify([][]byte{leaf, otherIntermediate.der}, false)
		expect(t, err, "unknown-root", 1)
		_, err = p.verifier.Verify([][]byte{leaf, otherIntermediate.der, otherRoot.der}, false)
		expect(t, err, "unknown-root", 2)
	})
}

// TestVerificationOrder checks that signatures are verified from the trust
// anchor down, so that the key of a certificate is not used before the
// certificate is known to be signed by its issuer.
func TestVerificationOrder(t *testing.T) {
	p := newTestPKI(t)
	corrupt := func(der []byte) []byte {
		der = slices.Clone(der)
		der[len(der)-1] ^= 1
		return der
	}
	leaf := p.leaf(t, nil)

	_, err := p.verifier.Verify([][]byte{corrupt(leaf), p.intermediate.der}, false)
	expect(t, err, "bad-signature", 0)
	_, err = p.verifier.Verify([][]byte{leaf, corrupt(p.intermediate.der)}, false)
	expect(t, err, "bad-signature", 1)
	_, err = p.verifier.Verify([][]byte{corrupt(leaf), corrupt(p.intermediate.der)}, false)
	expect(t, err, "bad-signature", 1)
	_, err = p.verifier.Verify([][]byte{leaf, corrupt(p.intermediate.der), p.root.der}, false)
	expect(t, err, "bad-signature", 1)
	_, err = p.verifier.Verify([][]byte{corrupt(leaf), corrupt(p.intermediate.der), p.root.der}, false)
	expect(t, err, "bad-signature", 1)

	lower := newCA(t, "Lower", newKey(t), p.intermediate, nil)
	leaf = lower.issue(t, leafTemplate(), newKey(t).Public())
	_, err = p.verifier.Verify([][]byte{corrupt(leaf), corrupt(lower.der), corrupt(p.intermediate.der)}, false)
	expect(t, err, "bad-signature", 2)
	_, err = p.verifier.Verify([][]byte{corrupt(leaf), corrupt(lower.der), p.intermediate.der, p.root.der}, false)
	expect(t, err, "bad-signature", 1)
}

func TestBlockedKeys(t *testing.T) {
	p := newTestPKI(t)
	leaf := p.leaf(t, nil)
	cert, err := x509.ParseCertificate(leaf)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := keyHash(newCA(t, "Unrelated", newKey(t), nil, nil).cert)

	for _, tt := range []struct {
		name        string
		blocked     [32]byte
		chain       [][]byte
		reason      string
		certificate int
	}{
		{"unrelated key", unrelated, [][]byte{leaf, p.intermediate.der, p.root.der}, "", 0},
		{"leaf", keyHash(cert), [][]byte{leaf, p.intermediate.der}, "blocked-key", 0},
		{"intermediate", keyHash(p.intermediate.cert), [][]byte{leaf, p.intermediate.der}, "blocked-key", 1},
		{"root, omitted", keyHash(p.root.cert), [][]byte{leaf, p.intermediate.der}, "blocked-key", 1},
		{"root, included", keyHash(p.root.cert), [][]byte{leaf, p.intermediate.der, p.root.der}, "blocked-key", 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := *p.verifier
			v.BlockedKeys = [][32]byte{unrelated, tt.blocked}
			_, err := v.Verify(tt.chain, false)
			expect(t, err, tt.reason, tt.certificate)
		})
	}

	t.Run("key certified by a blocked key", func(t *testing.T) {
		// The holder of a blocked key can give the CA a certificate for
		// another key, and issue with that.
		rollover := newCA(t, "Intermediate", newKey(t), p.intermediate, nil)
		leaf := rollover.issue(t, leafTemplate(), newKey(t).Public())
		chain := [][]byte{leaf, rollover.der, p.intermediate.der}
		_, err := p.verifier.Verify(chain, false)
		expect(t, err, "", 0)
		v := *p.verifier
		v.BlockedKeys = [][32]byte{keyHash(p.intermediate.cert)}
		_, err = v.Verify(chain, false)
		expect(t, err, "blocked-key", 2)
	})
}
