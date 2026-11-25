// Package chain verifies certificate chains submitted to a Certificate
// Transparency log. It is ONLY suited to that job. It would be extremely
// insecure if used in any other context.
//
// This library ensures that:
//
//   - every logged entry has a signature chain to an accepted root;
//   - each issued certificate can only be logged once (or twice for ECDSA
//     certificates) without control of an issuer key;
//   - the NotAfter, EKU, and key type restrictions are respected.
//
// It is also designed to be robust to denial of service attacks from entities
// that don't control an issuer private key.
//
// However, it does not:
//
//   - do any path building, because RFC 6962 clients send a full chain;
//   - check anything about the correctness of the certificates beyond what
//     is needed for the goals above.
//
// The checks are listed below in the order they are made. The identifier after
// each one is the Reason of the [Error] it produces.
//
// # Chain
//
//   - It has one to ten certificates (empty-chain, chain-too-long).
//   - No certificate appears twice (duplicate-cert).
//
// The first certificate is the leaf. If the last one is byte for byte a trust
// anchor, it is the trust anchor of the chain. Otherwise, the trust anchor is
// looked up by the issuer of the last certificate, and added to the chain. The
// certificates between the leaf and the trust anchor are the intermediates.
//
// # Leaf and intermediates
//
//   - It is a DER SEQUENCE of a TBSCertificate, an AlgorithmIdentifier, and a
//     BIT STRING (outer-not-der), with nothing else in it (outer-extra-field)
//     or after it (trailing-data).
//   - The BIT STRING has no unused bits (sig-bitstring-padding).
//   - The TBSCertificate is a DER SEQUENCE of the fields of RFC 5280, Section
//     4.1, and nothing else. The version is 1 to 3, and only version 3 has
//     extensions (tbs-malformed). The contents of the serial number, of the
//     names, and of the unique identifiers are not looked at.
//   - The AlgorithmIdentifier is the same bytes as the signature field of the
//     TBSCertificate (sigalg-mismatch).
//   - The signature algorithm is RSA PKCS #1 v1.5 or ECDSA with SHA-1,
//     SHA-256, SHA-384, or SHA-512, or RSASSA-PSS in one of the encodings
//     that crypto/x509 accepts (unsupported-sigalg). Except for RSASSA-PSS,
//     what follows the OID in the AlgorithmIdentifier is ignored.
//   - The public key algorithm is rsaEncryption or id-ecPublicKey
//     (unsupported-key).
//   - Each extension is an OID, an optional BOOLEAN that is 0x00 or 0xFF, and
//     an OCTET STRING (ext-malformed).
//   - basicConstraints, keyUsage, extKeyUsage, and the precertificate poison
//     appear at most once (ext-duplicate). All other extensions are ignored,
//     whether critical or repeated.
//   - The public key is not in [Verifier.BlockedKeys] (blocked-key).
//
// # Leaf
//
//   - The validity is two UTCTime or GeneralizedTime values that crypto/x509
//     can read, which includes UTCTime without seconds and time zone offsets
//     (validity-encoding).
//   - NotAfter is between [Verifier.NotAfterStart] and
//     [Verifier.NotAfterLimit] (not-after-range). NotBefore is not checked.
//   - extKeyUsage lists [Verifier.ExtKeyUsage] (eku). anyExtendedKeyUsage is
//     not enough.
//   - The poison extension, if present, is critical and NULL
//     (poison-malformed). It is present if the chain is verified as a
//     precertificate, and absent otherwise (endpoint-mismatch).
//
// The public key of the leaf is not parsed.
//
// # Intermediates
//
//   - Its subject is the same bytes as the issuer of the previous certificate
//     (name-mismatch).
//   - basicConstraints has cA set (not-ca) and keyUsage, if present, has
//     keyCertSign (no-certsign).
//   - If the leaf is a precertificate, its issuer is not a Precertificate
//     Signing Certificate (preissuer). They are not supported.
//   - extKeyUsage, if present, lists [Verifier.ExtKeyUsage] or
//     anyExtendedKeyUsage (eku-nesting).
//   - The public key is RSA with a modulus of 1024 to 8192 bits and an odd
//     exponent from 3 to 2^31-1, or ECDSA on P-256, P-384, or P-521
//     (unsupported-key), encoded as in the Baseline Requirements, Section
//     7.1.3.1, and no other way (key-malformed).
//
// These extensions are decoded strictly (ext-malformed). The validity, name
// constraints, policies, and path length constraints of intermediates are not
// checked.
//
// # Trust anchor
//
//   - Its subject is the same bytes as the issuer of the last certificate
//     (unknown-root if it was looked up, name-mismatch if it was submitted).
//   - Its public key is not in [Verifier.BlockedKeys] (blocked-key).
//   - If it was looked up, it is not one of the submitted certificates
//     (duplicate-cert).
//
// Nothing else about a trust anchor is checked, and only its subject and its
// public key are used. [Roots.Add] rejects certificates with a public key that
// an intermediate could not have, certificates signed with anything other than
// RSA or ECDSA, and Precertificate Signing Certificates. Their signature is not
// verified, so it can also be RSA with MD2, MD5, or SHA-224.
//
// A trust anchor submitted on its own, and not as a precertificate, is accepted
// if it passes the checks on the leaf.
//
// # Signatures
//
//   - Each certificate is verified with the key of the next one, starting
//     from the trust anchor (bad-signature).
//
// crypto/rsa and crypto/ecdsa only accept one form of a signature: for RSA,
// less than the modulus and encoded in as many bytes as the modulus; for ECDSA,
// the DER encoding of two positive integers less than the group order. The only
// signature malleability is ECDSA with n-s in place of s.
package chain
