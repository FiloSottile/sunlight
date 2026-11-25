package chain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func init() {
	// SHA-1 signatures have to be verified, and crypto/sha1 panics in FIPS
	// 140-3 enforced mode. Fail at startup rather than on a submission.
	if fips140.Enforced() {
		panic("chain: verifying SHA-1 signatures is not possible with GODEBUG=fips140=only")
	}
}

// Limits on the RSA keys of issuers and trust anchors.
const (
	minRSAModulusBits = 1024
	maxRSAModulusBits = 8192
	maxRSAExponent    = 1<<31 - 1
)

type scheme int

const (
	rsaPKCS1v15 scheme = iota + 1
	rsaPSS
	ecdsaScheme
)

// A signatureAlgorithm is a signature scheme and the hash it is used with.
type signatureAlgorithm struct {
	scheme scheme
	hash   crypto.Hash
}

// signatureAlgorithms are the algorithms that are identified by their OID
// alone, by the contents octets of the OID.
var signatureAlgorithms = map[string]signatureAlgorithm{
	"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05": {rsaPKCS1v15, crypto.SHA1},   // sha1WithRSAEncryption
	"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b": {rsaPKCS1v15, crypto.SHA256}, // sha256WithRSAEncryption
	"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c": {rsaPKCS1v15, crypto.SHA384}, // sha384WithRSAEncryption
	"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d": {rsaPKCS1v15, crypto.SHA512}, // sha512WithRSAEncryption
	"\x2a\x86\x48\xce\x3d\x04\x01":         {ecdsaScheme, crypto.SHA1},   // ecdsa-with-SHA1
	"\x2a\x86\x48\xce\x3d\x04\x03\x02":     {ecdsaScheme, crypto.SHA256}, // ecdsa-with-SHA256
	"\x2a\x86\x48\xce\x3d\x04\x03\x03":     {ecdsaScheme, crypto.SHA384}, // ecdsa-with-SHA384
	"\x2a\x86\x48\xce\x3d\x04\x03\x04":     {ecdsaScheme, crypto.SHA512}, // ecdsa-with-SHA512
}

const oidRSASSAPSS = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a" // 1.2.840.113549.1.1.10

// Signature algorithms that only a trust anchor can have, because its
// signature is not verified.
const (
	oidMD2WithRSAEncryption    = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x02" // 1.2.840.113549.1.1.2
	oidMD5WithRSAEncryption    = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04" // 1.2.840.113549.1.1.4
	oidSHA224WithRSAEncryption = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0e" // 1.2.840.113549.1.1.14
)

// pssParameters are the accepted encodings of RSASSA-PSS-params, the same
// ones crypto/x509 accepts: MGF1 with the same hash as the message, a salt as
// long as the hash, and the default trailer field. For each hash, the first
// encoding is the one in the Baseline Requirements, Section 7.1.3.2.1.
var pssParameters = func() map[string]crypto.Hash {
	m := make(map[string]crypto.Hash)
	for _, h := range []struct {
		hash crypto.Hash
		oid  string // DER encoding of the OID
		size string // length of the digest
	}{
		{crypto.SHA256, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01", "\x20"},
		{crypto.SHA384, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02", "\x30"},
		{crypto.SHA512, "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03", "\x40"},
	} {
		// RSASSA-PSS-params  ::=  SEQUENCE  {
		//     hashAlgorithm      [0] HashAlgorithm DEFAULT sha1Identifier,
		//     maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1Identifier,
		//     saltLength         [2] INTEGER DEFAULT 20,
		//     trailerField       [3] INTEGER DEFAULT 1  }
		//
		// The parameters of the hash AlgorithmIdentifiers can be NULL or
		// absent (RFC 4055, Section 2.1), and the trailer field can be
		// present with its default value (RFC 4055, Section 3.1).
		const mgf1 = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08"
		hashNULL := "\xa0\x0f\x30\x0d" + h.oid + "\x05\x00"
		hashAbsent := "\xa0\x0d\x30\x0b" + h.oid
		mgfNULL := "\xa1\x1c\x30\x1a" + mgf1 + "\x30\x0d" + h.oid + "\x05\x00"
		mgfAbsent := "\xa1\x1a\x30\x18" + mgf1 + "\x30\x0b" + h.oid
		salt := "\xa2\x03\x02\x01" + h.size
		trailer := "\xa3\x03\x02\x01\x01"
		for _, params := range []string{
			"\x30\x34" + hashNULL + mgfNULL + salt,
			"\x30\x32" + hashNULL + mgfAbsent + salt,
			"\x30\x32" + hashAbsent + mgfNULL + salt,
			"\x30\x30" + hashAbsent + mgfAbsent + salt,
			"\x30\x39" + hashNULL + mgfNULL + salt + trailer,
			"\x30\x37" + hashNULL + mgfAbsent + salt + trailer,
			"\x30\x37" + hashAbsent + mgfNULL + salt + trailer,
			"\x30\x35" + hashAbsent + mgfAbsent + salt + trailer,
		} {
			m[params] = h.hash
		}
	}
	return m
}()

// parseSignatureAlgorithm returns the signature algorithm identified by a
// DER AlgorithmIdentifier.
//
// What follows the OID is only looked at for RSASSA-PSS, where it selects the
// hash. For the other algorithms it has no effect on verification.
func parseSignatureAlgorithm(der []byte) (signatureAlgorithm, bool) {
	// AlgorithmIdentifier  ::=  SEQUENCE  {
	//     algorithm               OBJECT IDENTIFIER,
	//     parameters              ANY DEFINED BY algorithm OPTIONAL  }
	input := cryptobyte.String(der)
	var identifier, oid cryptobyte.String
	if !input.ReadASN1(&identifier, cryptobyte_asn1.SEQUENCE) ||
		!identifier.ReadASN1(&oid, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return signatureAlgorithm{}, false
	}
	if string(oid) == oidRSASSAPSS {
		hash, ok := pssParameters[string(identifier)]
		return signatureAlgorithm{rsaPSS, hash}, ok
	}
	alg, ok := signatureAlgorithms[string(oid)]
	return alg, ok
}

// Contents octets of the OIDs of the public key algorithms and curves.
const (
	oidRSAEncryption = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" // 1.2.840.113549.1.1.1
	oidECPublicKey   = "\x2a\x86\x48\xce\x3d\x02\x01"         // 1.2.840.10045.2.1
	oidSecp256r1     = "\x2a\x86\x48\xce\x3d\x03\x01\x07"     // 1.2.840.10045.3.1.7
	oidSecp384r1     = "\x2b\x81\x04\x00\x22"                 // 1.3.132.0.34
	oidSecp521r1     = "\x2b\x81\x04\x00\x23"                 // 1.3.132.0.35
)

// publicKeyAlgorithm returns the contents octets of the algorithm OID of a
// DER SubjectPublicKeyInfo.
func publicKeyAlgorithm(spki []byte) (oid string, ok bool) {
	input := cryptobyte.String(spki)
	var info, algorithm, id cryptobyte.String
	if !input.ReadASN1(&info, cryptobyte_asn1.SEQUENCE) ||
		!info.ReadASN1(&algorithm, cryptobyte_asn1.SEQUENCE) ||
		!algorithm.ReadASN1(&id, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return "", false
	}
	return string(id), true
}

// parsePublicKey parses the DER SubjectPublicKeyInfo of an issuer or of a
// trust anchor. It returns an *rsa.PublicKey or an *ecdsa.PublicKey.
//
// The encoding has to be the one in the Baseline Requirements, Section
// 7.1.3.1, with nothing added: these keys are used, so there is no reason to
// accept one that might be read differently elsewhere.
func parsePublicKey(spki []byte) (crypto.PublicKey, *Error) {
	// SubjectPublicKeyInfo  ::=  SEQUENCE  {
	//     algorithm            AlgorithmIdentifier,
	//     subjectPublicKey     BIT STRING  }
	input := cryptobyte.String(spki)
	var info, algorithm, oid, key cryptobyte.String
	if !input.ReadASN1(&info, cryptobyte_asn1.SEQUENCE) || !input.Empty() ||
		!info.ReadASN1(&algorithm, cryptobyte_asn1.SEQUENCE) ||
		!algorithm.ReadASN1(&oid, cryptobyte_asn1.OBJECT_IDENTIFIER) ||
		!info.ReadASN1(&key, cryptobyte_asn1.BIT_STRING) || !info.Empty() ||
		len(key) == 0 || key[0] != 0 {
		return nil, reject("key-malformed", "malformed subjectPublicKeyInfo")
	}
	key = key[1:]

	switch string(oid) {
	case oidRSAEncryption:
		// The parameters are NULL (RFC 3279, Section 2.3.1).
		//
		// RSAPublicKey  ::=  SEQUENCE  {
		//     modulus            INTEGER,
		//     publicExponent     INTEGER  }
		var null, rsaKey cryptobyte.String
		n, e := new(big.Int), new(big.Int)
		if !algorithm.ReadASN1(&null, cryptobyte_asn1.NULL) || len(null) != 0 || !algorithm.Empty() ||
			!key.ReadASN1(&rsaKey, cryptobyte_asn1.SEQUENCE) || !key.Empty() ||
			!rsaKey.ReadASN1Integer(n) ||
			!rsaKey.ReadASN1Integer(e) ||
			!rsaKey.Empty() {
			return nil, reject("key-malformed", "malformed RSA public key")
		}
		if n.Sign() <= 0 || n.Bit(0) == 0 ||
			n.BitLen() < minRSAModulusBits || n.BitLen() > maxRSAModulusBits {
			return nil, reject("unsupported-key", "unsupported RSA modulus")
		}
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > maxRSAExponent || e.Bit(0) == 0 {
			return nil, reject("unsupported-key", "unsupported RSA public exponent")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil

	case oidECPublicKey:
		// The parameters are the OID of a named curve, and the key is an
		// uncompressed point (RFC 5480, Sections 2.1.1 and 2.2).
		var namedCurve cryptobyte.String
		if !algorithm.ReadASN1(&namedCurve, cryptobyte_asn1.OBJECT_IDENTIFIER) || !algorithm.Empty() {
			return nil, reject("key-malformed", "malformed EC parameters")
		}
		var curve elliptic.Curve
		switch string(namedCurve) {
		case oidSecp256r1:
			curve = elliptic.P256()
		case oidSecp384r1:
			curve = elliptic.P384()
		case oidSecp521r1:
			curve = elliptic.P521()
		default:
			return nil, reject("unsupported-key", "unsupported curve")
		}
		ecKey, err := ecdsa.ParseUncompressedPublicKey(curve, key)
		if err != nil {
			return nil, reject("key-malformed", "malformed EC public key")
		}
		return ecKey, nil

	default:
		return nil, reject("unsupported-key", "unsupported public key algorithm")
	}
}

// checkSignature verifies the signature on c with the key of its issuer.
//
// The signature has to be in the only form its algorithm allows, or anyone
// could make another certificate out of c. crypto/rsa and crypto/ecdsa take
// care of that.
//
// An ECDSA signature (r, s) has a twin (r, n - s). That is the one other
// certificate that can be made out of c.
func checkSignature(c *certificate, key crypto.PublicKey) *Error {
	h := c.algorithm.hash.New()
	h.Write(c.tbs)
	digest := h.Sum(nil)

	switch key := key.(type) {
	case *rsa.PublicKey:
		var err error
		switch c.algorithm.scheme {
		case rsaPKCS1v15:
			err = rsa.VerifyPKCS1v15(key, c.algorithm.hash, digest, c.signature)
		case rsaPSS:
			err = rsa.VerifyPSS(key, c.algorithm.hash, digest, c.signature,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		default:
			return reject("bad-signature", "signature algorithm does not match the RSA key of the issuer")
		}
		if err != nil {
			return reject("bad-signature", "invalid RSA signature")
		}
	case *ecdsa.PublicKey:
		if c.algorithm.scheme != ecdsaScheme {
			return reject("bad-signature", "signature algorithm does not match the ECDSA key of the issuer")
		}
		if !ecdsa.VerifyASN1(key, digest, c.signature) {
			return reject("bad-signature", "invalid ECDSA signature")
		}
	default:
		return reject("bad-signature", "unsupported issuer key")
	}
	return nil
}
