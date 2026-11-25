package chain

import (
	"bytes"
	"crypto"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Roots is a set of trust anchors.
//
// The zero value is an empty set. A Roots must not be modified while a
// [Verifier] is using it.
type Roots struct {
	byCertificate map[string]*trustAnchor
	bySubject     map[string][]*trustAnchor
}

// A trustAnchor is a certificate that chains are accepted for. Only its
// subject and its public key are used.
type trustAnchor struct {
	raw     []byte
	subject []byte // Name, with its header
	spki    []byte // SubjectPublicKeyInfo, with its header
	key     crypto.PublicKey
}

// Add adds a DER certificate to the set.
//
// The certificate does not need to be self-signed. Nothing about it is checked
// except that it has a subject, a public key that can be used to verify
// signatures, and a signature algorithm that is RSA or ECDSA, and that it is
// not a Precertificate Signing Certificate. The signature is not verified, and
// it can also be RSA with MD2, MD5, or SHA-224.
func (r *Roots) Add(der []byte) error {
	if r.get(der) != nil {
		return nil
	}

	// Trust anchors are certificates the log chose to accept, some of them
	// decades old, so only the fields that are used and the ones before them
	// need to be well-formed. See parseCertificate for the structure.
	a := &trustAnchor{raw: bytes.Clone(der)}
	input := cryptobyte.String(a.raw)
	var cert, tbs, signature, algorithm, subject, spki, wrapper, extensions cryptobyte.String
	var present bool
	if !input.ReadASN1(&cert, cryptobyte_asn1.SEQUENCE) || !input.Empty() ||
		!cert.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) ||
		!tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) || // version
		!tbs.SkipASN1(cryptobyte_asn1.INTEGER) || // serialNumber
		!tbs.ReadASN1(&signature, cryptobyte_asn1.SEQUENCE) ||
		!signature.ReadASN1(&algorithm, cryptobyte_asn1.OBJECT_IDENTIFIER) ||
		!tbs.SkipASN1(cryptobyte_asn1.SEQUENCE) || // issuer
		!tbs.SkipASN1(cryptobyte_asn1.SEQUENCE) || // validity
		!tbs.ReadASN1Element(&subject, cryptobyte_asn1.SEQUENCE) ||
		!tbs.ReadASN1Element(&spki, cryptobyte_asn1.SEQUENCE) ||
		!tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(1).ContextSpecific()) || // issuerUniqueID
		!tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(2).ContextSpecific()) || // subjectUniqueID
		!tbs.ReadOptionalASN1(&wrapper, &present, cryptobyte_asn1.Tag(3).Constructed().ContextSpecific()) ||
		present && !wrapper.ReadASN1(&extensions, cryptobyte_asn1.SEQUENCE) {
		return reject("tbs-malformed", "malformed trust anchor")
	}
	key, err := parsePublicKey(spki)
	if err != nil {
		return err
	}
	// The trust anchor is part of the logged chain, in which every
	// certificate has to be signed with RSA or ECDSA. Its signature is not
	// verified, so with RSA the hash can also be MD2, MD5, or SHA-224, and
	// the parameters of RSASSA-PSS are not looked at.
	switch oid := string(algorithm); oid {
	case oidMD2WithRSAEncryption, oidMD5WithRSAEncryption, oidSHA224WithRSAEncryption, oidRSASSAPSS:
	default:
		if _, ok := signatureAlgorithms[oid]; !ok {
			return reject("unsupported-sigalg", "unsupported signature algorithm")
		}
	}
	// A Precertificate Signing Certificate can't be a trust anchor. The log
	// entry of a precertificate it issues is made with the name and the key of
	// its own issuer, which is not known for a trust anchor. See RFC 6962,
	// Section 3.2, and keyPurposes for the structure of extKeyUsage.
	for !extensions.Empty() {
		var ext, id, value, purposes, purpose cryptobyte.String
		if !extensions.ReadASN1(&ext, cryptobyte_asn1.SEQUENCE) ||
			!ext.ReadASN1(&id, cryptobyte_asn1.OBJECT_IDENTIFIER) ||
			!ext.SkipOptionalASN1(cryptobyte_asn1.BOOLEAN) || // critical
			!ext.ReadASN1(&value, cryptobyte_asn1.OCTET_STRING) {
			return reject("ext-malformed", "malformed trust anchor extension")
		}
		if string(id) != oidExtKeyUsage {
			continue
		}
		if !value.ReadASN1(&purposes, cryptobyte_asn1.SEQUENCE) {
			return reject("ext-malformed", "malformed trust anchor extKeyUsage")
		}
		for !purposes.Empty() {
			if !purposes.ReadASN1(&purpose, cryptobyte_asn1.OBJECT_IDENTIFIER) {
				return reject("ext-malformed", "malformed trust anchor extKeyUsage")
			}
			if string(purpose) == string(precertificateSigning) {
				return reject("preissuer", "Precertificate Signing Certificate as a trust anchor")
			}
		}
	}
	a.subject, a.spki, a.key = subject, spki, key

	if r.byCertificate == nil {
		r.byCertificate = make(map[string]*trustAnchor)
		r.bySubject = make(map[string][]*trustAnchor)
	}
	r.byCertificate[string(a.raw)] = a
	r.bySubject[string(a.subject)] = append(r.bySubject[string(a.subject)], a)
	return nil
}

// get returns the trust anchor with the given encoding, if there is one.
func (r *Roots) get(der []byte) *trustAnchor {
	if r == nil {
		return nil
	}
	return r.byCertificate[string(der)]
}

// named returns the trust anchors with the given subject, in the order they
// were added.
func (r *Roots) named(subject []byte) []*trustAnchor {
	if r == nil {
		return nil
	}
	return r.bySubject[string(subject)]
}
