package chain

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"
	"time"
)

// maxChainLength is the maximum number of certificates in a submission.
const maxChainLength = 10

// An ExtKeyUsage is an extended key usage purpose. It is the contents octets
// of the DER encoding of the OID of the purpose.
type ExtKeyUsage string

const (
	// ServerAuth is id-kp-serverAuth, 1.3.6.1.5.5.7.3.1.
	ServerAuth ExtKeyUsage = "\x2b\x06\x01\x05\x05\x07\x03\x01"

	// BrandIndicatorForMessageIdentification is
	// id-kp-BrandIndicatorforMessageIdentification, 1.3.6.1.5.5.7.3.31, the
	// purpose of mark certificates.
	BrandIndicatorForMessageIdentification ExtKeyUsage = "\x2b\x06\x01\x05\x05\x07\x03\x1f"
)

// A Verifier verifies the chains submitted to a log.
//
// A Verifier can be used by multiple goroutines at the same time, as long as
// its fields are not modified.
type Verifier struct {
	// Roots are the trust anchors of the log.
	Roots *Roots

	// NotAfterStart and NotAfterLimit, if not zero, are the bounds of the
	// interval [NotAfterStart, NotAfterLimit) in which the NotAfter of the
	// leaf must fall.
	NotAfterStart, NotAfterLimit time.Time

	// ExtKeyUsage, if not empty, is the extended key usage purpose that the
	// leaf must have, and that the extKeyUsage extensions of its issuers must
	// allow.
	ExtKeyUsage ExtKeyUsage

	// BlockedKeys are the SHA-256 hashes of the SubjectPublicKeyInfo of keys
	// that must not appear anywhere in a chain, including in its trust
	// anchor.
	BlockedKeys [][32]byte
}

// Verified is a chain accepted by a [Verifier].
type Verified struct {
	// Chain is the DER encoding of the certificates of the chain, from the
	// leaf to the trust anchor. The trust anchor is included even if it was
	// not submitted.
	Chain [][]byte

	// Issuer is the DER encoding of the issuer field of the leaf, and Root
	// that of the subject field of the trust anchor.
	Issuer, Root []byte

	// NotBefore and NotAfter are the validity period of the leaf.
	NotBefore, NotAfter time.Time

	// SCTs reports whether the leaf has a Signed Certificate Timestamp list
	// extension.
	SCTs bool

	// TBSCertificate and IssuerKeyHash are set for precertificates. They are
	// the tbs_certificate and the issuer_key_hash of the log entry, as
	// defined in RFC 6962, Section 3.2:
	// the TBSCertificate of the leaf without the poison extension, and the
	// SHA-256 hash of the SubjectPublicKeyInfo of its issuer.
	TBSCertificate []byte
	IssuerKeyHash  [32]byte
}

// An Error is the reason a chain was rejected.
type Error struct {
	// Reason identifies the check that failed. It is one of the identifiers
	// in the package documentation. It has low cardinality.
	Reason string

	// Certificate is the index in the chain of the certificate that failed
	// the check, or -1 if the check is not about a single certificate.
	Certificate int

	// Detail describes the failure.
	Detail string
}

func (e *Error) Error() string {
	if e.Certificate < 0 {
		return "chain: " + e.Detail
	}
	return fmt.Sprintf("chain: certificate %d: %s", e.Certificate, e.Detail)
}

func reject(reason, format string, args ...any) *Error {
	return &Error{Reason: reason, Certificate: -1, Detail: fmt.Sprintf(format, args...)}
}

// at records that e is about certificate i of the chain.
func (e *Error) at(i int) *Error {
	e.Certificate = i
	return e
}

// Verify verifies a chain submitted to the log. The chain is a list of DER
// certificates starting with the leaf, like the one in the request.
//
// The leaf has to be a certificate if precertificate is false, like for the
// add-chain endpoint, and a precertificate if it is true, like for the
// add-pre-chain endpoint.
//
// If the chain is rejected, the error is an [*Error]. The result shares
// memory with chain and with the [Verifier].
func (v *Verifier) Verify(chain [][]byte, precertificate bool) (*Verified, error) {
	// Chain.

	if len(chain) == 0 {
		return nil, reject("empty-chain", "no certificates")
	}
	if len(chain) > maxChainLength {
		return nil, reject("chain-too-long", "%d certificates", len(chain))
	}
	for i := range chain {
		for j := range i {
			if bytes.Equal(chain[i], chain[j]) {
				return nil, reject("duplicate-cert", "same certificate as %d", j).at(i)
			}
		}
	}

	// If the last certificate is a trust anchor, clip it off.
	// Otherwise, the trust anchor is looked up after the issuers are checked.
	leafAndIntermediates := chain
	var anchor *trustAnchor
	if last := len(chain) - 1; last > 0 {
		if anchor = v.Roots.get(chain[last]); anchor != nil {
			leafAndIntermediates = chain[:last]
		}
	}

	// Leaf and intermediates.

	certs := make([]*certificate, len(leafAndIntermediates))
	for i, der := range leafAndIntermediates {
		c, err := parseCertificate(der)
		if err != nil {
			return nil, err.at(i)
		}
		certs[i] = c
	}

	// Blocked keys. These are keys that someone other than the CA might
	// hold, so they are rejected before anything is verified with them.

	for i, c := range certs {
		if v.blocked(c.spki) {
			return nil, reject("blocked-key", "blocked key").at(i)
		}
	}

	// Leaf.

	leaf := certs[0]
	notBefore, notAfter, err := leaf.parseValidity()
	if err != nil {
		return nil, err.at(0)
	}
	if !v.NotAfterStart.IsZero() && notAfter.Before(v.NotAfterStart) ||
		!v.NotAfterLimit.IsZero() && !notAfter.Before(v.NotAfterLimit) {
		return nil, reject("not-after-range", "NotAfter %v is outside the range of the log",
			notAfter.Format(time.RFC3339)).at(0)
	}
	if v.ExtKeyUsage != "" {
		purposes, err := leaf.keyPurposes()
		if err != nil {
			return nil, err.at(0)
		}
		if !purposes.has(v.ExtKeyUsage) {
			return nil, reject("eku", "extKeyUsage without the required purpose").at(0)
		}
	}
	if leaf.poison.present && (!leaf.poison.critical || !bytes.Equal(leaf.poison.value, []byte{0x05, 0x00})) {
		return nil, reject("poison-malformed", "malformed poison extension").at(0)
	}
	if leaf.poison.present && !precertificate {
		return nil, reject("endpoint-mismatch", "precertificate submitted as a certificate").at(0)
	}
	if !leaf.poison.present && precertificate {
		return nil, reject("endpoint-mismatch", "certificate submitted as a precertificate").at(0)
	}

	verified := &Verified{
		Chain:     chain,
		Issuer:    leaf.issuer,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		SCTs:      leaf.scts,
	}

	// A trust anchor submitted on its own has nothing above it to be
	// verified with.
	if len(chain) == 1 && !precertificate {
		if a := v.Roots.get(chain[0]); a != nil {
			verified.Root = a.subject
			return verified, nil
		}
	}

	// Intermediates.

	for i := 1; i < len(certs); i++ {
		c := certs[i]
		if !bytes.Equal(certs[i-1].issuer, c.subject) {
			return nil, reject("name-mismatch", "issuer is not the subject of certificate %d", i).at(i - 1)
		}
		if err := c.checkCA(); err != nil {
			return nil, err.at(i)
		}
		purposes, err := c.keyPurposes()
		if err != nil {
			return nil, err.at(i)
		}
		if i == 1 && precertificate && purposes.has(precertificateSigning) {
			return nil, reject("preissuer", "Precertificate Signing Certificates are not supported").at(i)
		}
		if v.ExtKeyUsage != "" && c.extKeyUsage.present &&
			!purposes.has(v.ExtKeyUsage) && !purposes.has(anyExtendedKeyUsage) {
			return nil, reject("eku-nesting", "extKeyUsage without the required purpose").at(i)
		}
		if c.key, err = parsePublicKey(c.spki); err != nil {
			return nil, err.at(i)
		}
	}

	// Trust anchor.

	top := len(certs) - 1
	if anchor != nil {
		if !bytes.Equal(certs[top].issuer, anchor.subject) {
			return nil, reject("name-mismatch", "issuer is not the subject of certificate %d", top+1).at(top)
		}
		if v.blocked(anchor.spki) {
			return nil, reject("blocked-key", "blocked key").at(top + 1)
		}
		if err := checkSignature(certs[top], anchor.key); err != nil {
			return nil, err.at(top)
		}
	} else {
		// More than one trust anchor can have the subject. The first one
		// that verifies the signature is used. One that is already among the
		// submitted certificates is passed over, or it would be in the chain
		// twice.
		err := reject("unknown-root", "issuer is not a trust anchor")
		for _, a := range v.Roots.named(certs[top].issuer) {
			if v.blocked(a.spki) {
				err = reject("blocked-key", "trust anchor with a blocked key")
				continue
			}
			if i := slices.IndexFunc(chain, func(der []byte) bool { return bytes.Equal(der, a.raw) }); i >= 0 {
				err = reject("duplicate-cert", "trust anchor is already in the chain as certificate %d", i)
				continue
			}
			if err = checkSignature(certs[top], a.key); err == nil {
				anchor = a
				break
			}
		}
		if anchor == nil {
			return nil, err.at(top)
		}
		verified.Chain = append(slices.Clip(chain), anchor.raw)
	}
	verified.Root = anchor.subject

	// Signatures. The one by the trust anchor was verified above. The others
	// are verified from the top, so that each key is used only after the
	// certificate it comes from has been verified.

	for i := top - 1; i >= 0; i-- {
		if err := checkSignature(certs[i], certs[i+1].key); err != nil {
			return nil, err.at(i)
		}
	}

	// Precertificates.

	if precertificate {
		verified.TBSCertificate = leaf.tbsWithoutPoison()
		issuer := anchor.spki
		if len(certs) > 1 {
			issuer = certs[1].spki
		}
		verified.IssuerKeyHash = sha256.Sum256(issuer)
	}
	return verified, nil
}

// blocked reports whether a SubjectPublicKeyInfo is in BlockedKeys.
func (v *Verifier) blocked(spki []byte) bool {
	return slices.Contains(v.BlockedKeys, sha256.Sum256(spki))
}
