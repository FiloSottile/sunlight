package chain

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Contents octets of the OIDs of the extensions that are interpreted.
const (
	oidBasicConstraints = "\x55\x1d\x13"                             // 2.5.29.19
	oidKeyUsage         = "\x55\x1d\x0f"                             // 2.5.29.15
	oidExtKeyUsage      = "\x55\x1d\x25"                             // 2.5.29.37
	oidPoison           = "\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x03" // 1.3.6.1.4.1.11129.2.4.3
	oidSCTList          = "\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x02" // 1.3.6.1.4.1.11129.2.4.2
)

// The extended key usage purposes that have a meaning of their own.
const (
	anyExtendedKeyUsage   ExtKeyUsage = "\x55\x1d\x25\x00"                         // 2.5.29.37.0
	precertificateSigning ExtKeyUsage = "\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x04" // 1.3.6.1.4.1.11129.2.4.4
)

// A certificate is a submitted certificate, split into the parts that are
// looked at. The byte slices alias raw.
type certificate struct {
	raw []byte

	tbs       []byte // TBSCertificate, with its header
	algorithm signatureAlgorithm
	signature []byte

	issuer   []byte // Name, with its header
	validity []byte // Validity, without its header
	subject  []byte // Name, with its header
	spki     []byte // SubjectPublicKeyInfo, with its header

	basicConstraints extension
	keyUsage         extension
	extKeyUsage      extension
	poison           extension
	scts             bool // has a SignedCertificateTimestampList extension

	// The contents of the TBSCertificate before the extensions field, and of
	// the Extensions before and after the poison extension.
	tbsFields, beforePoison, afterPoison []byte

	// key is the public key in spki. It is set once the certificate is
	// known to be a CA.
	key crypto.PublicKey
}

// An extension is one of the extensions that are interpreted.
type extension struct {
	present  bool
	critical bool
	value    []byte // contents of extnValue
}

// parseCertificate parses a submitted certificate.
//
// It checks that the Certificate is DER all the way to the fields of the
// TBSCertificate and to the list of extensions, with nothing left over at any
// level. Of the contents of the fields, it only looks at the version, the
// signature algorithm, and the public key algorithm.
func parseCertificate(der []byte) (*certificate, *Error) {
	c := &certificate{raw: der}
	input := cryptobyte.String(der)

	// Certificate  ::=  SEQUENCE  {
	//     tbsCertificate       TBSCertificate,
	//     signatureAlgorithm   AlgorithmIdentifier,
	//     signatureValue       BIT STRING  }
	var cert, tbs, signatureAlgorithm, signature cryptobyte.String
	if !input.ReadASN1(&cert, cryptobyte_asn1.SEQUENCE) ||
		!cert.ReadASN1Element(&tbs, cryptobyte_asn1.SEQUENCE) ||
		!cert.ReadASN1Element(&signatureAlgorithm, cryptobyte_asn1.SEQUENCE) ||
		!cert.ReadASN1(&signature, cryptobyte_asn1.BIT_STRING) || len(signature) == 0 {
		return nil, reject("outer-not-der", "malformed Certificate")
	}
	if !input.Empty() {
		return nil, reject("trailing-data", "data after the Certificate")
	}
	if !cert.Empty() {
		return nil, reject("outer-extra-field", "data after signatureValue")
	}
	if signature[0] != 0 {
		return nil, reject("sig-bitstring-padding", "signatureValue is not a whole number of bytes")
	}
	c.tbs, c.signature = tbs, signature[1:]

	// TBSCertificate  ::=  SEQUENCE  {
	//     version         [0]  EXPLICIT Version DEFAULT v1,
	//     serialNumber         CertificateSerialNumber,
	//     signature            AlgorithmIdentifier,
	//     issuer               Name,
	//     validity             Validity,
	//     subject              Name,
	//     subjectPublicKeyInfo SubjectPublicKeyInfo,
	//     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
	//     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
	//     extensions      [3]  EXPLICIT Extensions OPTIONAL  }
	var fields cryptobyte.String
	if !tbs.ReadASN1(&fields, cryptobyte_asn1.SEQUENCE) {
		return nil, reject("tbs-malformed", "malformed TBSCertificate")
	}
	allFields := fields
	var version int
	var innerAlgorithm, issuer, validity, subject, spki cryptobyte.String
	if !fields.ReadOptionalASN1Integer(&version, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), 0) ||
		!fields.SkipASN1(cryptobyte_asn1.INTEGER) ||
		!fields.ReadASN1Element(&innerAlgorithm, cryptobyte_asn1.SEQUENCE) ||
		!fields.ReadASN1Element(&issuer, cryptobyte_asn1.SEQUENCE) ||
		!fields.ReadASN1(&validity, cryptobyte_asn1.SEQUENCE) ||
		!fields.ReadASN1Element(&subject, cryptobyte_asn1.SEQUENCE) ||
		!fields.ReadASN1Element(&spki, cryptobyte_asn1.SEQUENCE) ||
		!fields.SkipOptionalASN1(cryptobyte_asn1.Tag(1).ContextSpecific()) ||
		!fields.SkipOptionalASN1(cryptobyte_asn1.Tag(2).ContextSpecific()) {
		return nil, reject("tbs-malformed", "malformed TBSCertificate")
	}
	if version < 0 || version > 2 {
		return nil, reject("tbs-malformed", "unknown version")
	}
	c.issuer, c.validity, c.subject, c.spki = issuer, validity, subject, spki

	// The outer signatureAlgorithm is not signed. Requiring it to be the same
	// bytes as the inner one leaves a single way to encode it.
	if !bytes.Equal(signatureAlgorithm, innerAlgorithm) {
		return nil, reject("sigalg-mismatch", "signatureAlgorithm differs from the signature field of the TBSCertificate")
	}
	var ok bool
	if c.algorithm, ok = parseSignatureAlgorithm(signatureAlgorithm); !ok {
		return nil, reject("unsupported-sigalg", "unsupported signature algorithm")
	}
	if oid, ok := publicKeyAlgorithm(spki); !ok {
		return nil, reject("tbs-malformed", "malformed subjectPublicKeyInfo")
	} else if oid != oidRSAEncryption && oid != oidECPublicKey {
		return nil, reject("unsupported-key", "unsupported public key algorithm")
	}

	// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
	//
	// Extension  ::=  SEQUENCE  {
	//     extnID      OBJECT IDENTIFIER,
	//     critical    BOOLEAN DEFAULT FALSE,
	//     extnValue   OCTET STRING  }
	c.tbsFields = allFields[:len(allFields)-len(fields)]
	var wrapper, extensions cryptobyte.String
	var present bool
	if !fields.ReadOptionalASN1(&wrapper, &present, cryptobyte_asn1.Tag(3).Constructed().ContextSpecific()) ||
		!fields.Empty() {
		return nil, reject("tbs-malformed", "malformed TBSCertificate")
	}
	if !present {
		return c, nil
	}
	if version != 2 {
		return nil, reject("tbs-malformed", "extensions in a certificate that is not v3")
	}
	if !wrapper.ReadASN1(&extensions, cryptobyte_asn1.SEQUENCE) || !wrapper.Empty() {
		return nil, reject("tbs-malformed", "malformed extensions")
	}
	allExtensions := extensions
	for !extensions.Empty() {
		start := len(allExtensions) - len(extensions)
		var ext, id, value cryptobyte.String
		var critical bool
		if !extensions.ReadASN1(&ext, cryptobyte_asn1.SEQUENCE) ||
			!ext.ReadASN1(&id, cryptobyte_asn1.OBJECT_IDENTIFIER) ||
			ext.PeekASN1Tag(cryptobyte_asn1.BOOLEAN) && !ext.ReadASN1Boolean(&critical) ||
			!ext.ReadASN1(&value, cryptobyte_asn1.OCTET_STRING) ||
			!ext.Empty() {
			return nil, reject("ext-malformed", "malformed extension")
		}
		end := len(allExtensions) - len(extensions)

		var e *extension
		switch string(id) {
		case oidBasicConstraints:
			e = &c.basicConstraints
		case oidKeyUsage:
			e = &c.keyUsage
		case oidExtKeyUsage:
			e = &c.extKeyUsage
		case oidPoison:
			e = &c.poison
			c.beforePoison, c.afterPoison = allExtensions[:start], allExtensions[end:]
		case oidSCTList:
			c.scts = true
			continue
		default:
			continue
		}
		if e.present {
			return nil, reject("ext-duplicate", "duplicate extension")
		}
		*e = extension{present: true, critical: critical, value: value}
	}
	return c, nil
}

// parseValidity returns the validity period of c.
//
// The two Times are read like crypto/x509 does: besides the forms required by
// RFC 5280, Section 4.1.2.5, a UTCTime can lack the seconds, and both types
// can have a numeric time zone offset instead of Z.
func (c *certificate) parseValidity() (notBefore, notAfter time.Time, err *Error) {
	// Validity  ::=  SEQUENCE  {
	//     notBefore      Time,
	//     notAfter       Time  }
	//
	// Time  ::=  CHOICE  {
	//     utcTime        UTCTime,
	//     generalTime    GeneralizedTime  }
	validity := cryptobyte.String(c.validity)
	for _, t := range []*time.Time{&notBefore, &notAfter} {
		var ok bool
		switch {
		case validity.PeekASN1Tag(cryptobyte_asn1.UTCTime):
			ok = validity.ReadASN1UTCTime(t)
		case validity.PeekASN1Tag(cryptobyte_asn1.GeneralizedTime):
			ok = validity.ReadASN1GeneralizedTime(t)
		}
		if !ok {
			return time.Time{}, time.Time{}, reject("validity-encoding", "malformed validity")
		}
	}
	if !validity.Empty() {
		return time.Time{}, time.Time{}, reject("validity-encoding", "malformed validity")
	}
	return notBefore, notAfter, nil
}

// A purposeList is the contents of an ExtKeyUsageSyntax, a sequence of OIDs.
//
// It is searched where it is, instead of being decoded into a slice, because
// it is read before any signature is verified, and it can be almost as long
// as the request.
type purposeList []byte

// has reports whether purpose is in the list.
func (l purposeList) has(purpose ExtKeyUsage) bool {
	list := cryptobyte.String(l)
	var id cryptobyte.String
	for list.ReadASN1(&id, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		if string(id) == string(purpose) {
			return true
		}
	}
	return false
}

// keyPurposes returns the purposes in the extKeyUsage extension of c, or an
// empty list if c does not have the extension.
func (c *certificate) keyPurposes() (purposeList, *Error) {
	if !c.extKeyUsage.present {
		return nil, nil
	}
	// ExtKeyUsageSyntax  ::=  SEQUENCE SIZE (1..MAX) OF KeyPurposeId
	//
	// KeyPurposeId  ::=  OBJECT IDENTIFIER
	value := cryptobyte.String(c.extKeyUsage.value)
	var list cryptobyte.String
	if !value.ReadASN1(&list, cryptobyte_asn1.SEQUENCE) || !value.Empty() {
		return nil, reject("ext-malformed", "malformed extKeyUsage")
	}
	purposes := purposeList(list)
	for !list.Empty() {
		if !list.SkipASN1(cryptobyte_asn1.OBJECT_IDENTIFIER) {
			return nil, reject("ext-malformed", "malformed extKeyUsage")
		}
	}
	return purposes, nil
}

// checkCA checks that c is allowed to sign certificates: that it has a
// basicConstraints extension with cA set and, if it has a keyUsage extension,
// that it includes keyCertSign. See RFC 5280, Section 6.1.4, steps (k) and (n).
func (c *certificate) checkCA() *Error {
	if !c.basicConstraints.present {
		return reject("not-ca", "no basicConstraints")
	}
	// BasicConstraints  ::=  SEQUENCE  {
	//     cA                      BOOLEAN DEFAULT FALSE,
	//     pathLenConstraint       INTEGER (0..MAX) OPTIONAL  }
	value := cryptobyte.String(c.basicConstraints.value)
	var constraints cryptobyte.String
	var isCA bool
	if !value.ReadASN1(&constraints, cryptobyte_asn1.SEQUENCE) || !value.Empty() ||
		constraints.PeekASN1Tag(cryptobyte_asn1.BOOLEAN) && !constraints.ReadASN1Boolean(&isCA) ||
		!constraints.SkipOptionalASN1(cryptobyte_asn1.INTEGER) ||
		!constraints.Empty() {
		return reject("ext-malformed", "malformed basicConstraints")
	}
	if !isCA {
		return reject("not-ca", "basicConstraints without cA")
	}

	if !c.keyUsage.present {
		return nil
	}
	// KeyUsage  ::=  BIT STRING  {
	//     digitalSignature        (0),
	//     ...
	//     keyCertSign             (5),
	//     ...  }
	value = cryptobyte.String(c.keyUsage.value)
	var usage asn1.BitString
	if !value.ReadASN1BitString(&usage) || !value.Empty() {
		return reject("ext-malformed", "malformed keyUsage")
	}
	if usage.At(5) == 0 {
		return reject("no-certsign", "keyUsage without keyCertSign")
	}
	return nil
}

// tbsWithoutPoison returns the TBSCertificate of c with the poison extension
// removed, as defined in RFC 6962, Section 3.2.
//
// Only the lengths of the three elements that enclose the extension are
// encoded anew. Every other byte is copied. If the poison is the only
// extension, the extensions field is left out, because Extensions can't be
// empty.
func (c *certificate) tbsWithoutPoison() []byte {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(c.tbsFields)
		if len(c.beforePoison) == 0 && len(c.afterPoison) == 0 {
			return
		}
		b.AddASN1(cryptobyte_asn1.Tag(3).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddBytes(c.beforePoison)
				b.AddBytes(c.afterPoison)
			})
		})
	})
	return b.BytesOrPanic()
}
