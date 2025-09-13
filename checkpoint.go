// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at
// https://go.googlesource.com/go/+/refs/heads/master/LICENSE.

package sunlight

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"filippo.io/torchwood"
	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
)

// NewRFC6962Verifier constructs a new [note.Verifier] that verifies a RFC 6962
// TreeHeadSignature formatted according to c2sp.org/static-ct-api.
func NewRFC6962Verifier(name string, key crypto.PublicKey) (note.Verifier, error) {
	if !isValidName(name) {
		return nil, fmt.Errorf("invalid name %q", name)
	}

	pkix, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	keyID := sha256.Sum256(pkix)

	v := &verifier{}
	v.name = name
	v.hash = keyHash(name, append([]byte{0x05}, keyID[:]...))
	v.verify = func(msg, sig []byte) (ok bool) {
		c, err := ParseCheckpoint(string(msg))
		if err != nil {
			return false
		}
		if c.Extension != "" {
			return false
		}

		// Parse the RFC6962NoteSignature.
		var timestamp uint64
		var hashAlg, sigAlg uint8
		var signature []byte
		s := cryptobyte.String(sig)
		if !s.ReadUint64(&timestamp) ||
			!s.ReadUint8(&hashAlg) || hashAlg != 4 || !s.ReadUint8(&sigAlg) ||
			!s.ReadUint16LengthPrefixed((*cryptobyte.String)(&signature)) ||
			!s.Empty() {
			return false
		}

		sth := ct.SignedTreeHead{
			Version:        ct.V1,
			TreeSize:       uint64(c.N),
			Timestamp:      timestamp,
			SHA256RootHash: ct.SHA256Hash(c.Hash),
		}
		sthBytes, err := ct.SerializeSTHSignatureInput(sth)
		if err != nil {
			return false
		}

		digest := sha256.Sum256(sthBytes)
		switch key := key.(type) {
		case *rsa.PublicKey:
			if sigAlg != 1 {
				return false
			}
			return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) == nil
		case *ecdsa.PublicKey:
			if sigAlg != 3 {
				return false
			}
			return ecdsa.VerifyASN1(key, digest[:], signature)
		default:
			return false
		}
	}

	return v, nil
}

type verifier struct {
	name   string
	hash   uint32
	verify func(msg, sig []byte) bool
}

func (v *verifier) Name() string                { return v.name }
func (v *verifier) KeyHash() uint32             { return v.hash }
func (v *verifier) Verify(msg, sig []byte) bool { return v.verify(msg, sig) }

func isValidName(name string) bool {
	return name != "" && utf8.ValidString(name) &&
		strings.IndexFunc(name, unicode.IsSpace) < 0 &&
		!strings.Contains(name, "+")
}

func keyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}

func RFC6962SignatureTimestamp(sig note.Signature) (int64, error) {
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Base64)
	if err != nil {
		return 0, err
	}
	var timestamp uint64
	s := cryptobyte.String(sigBytes)
	if !s.Skip(4 /* key hash */) || !s.ReadUint64(&timestamp) ||
		timestamp > math.MaxInt64 {
		return 0, errors.New("malformed RFC 6962 TreeHeadSignature")
	}
	return int64(timestamp), nil
}

// Backwards compatibility shims for functionality that was originally
// duplicated from [torchwood] and that's not Sunlight specific.

//go:fix inline
type Checkpoint = torchwood.Checkpoint

//go:fix inline
func ParseCheckpoint(text string) (Checkpoint, error) {
	return torchwood.ParseCheckpoint(text)
}

//go:fix inline
func FormatCheckpoint(c Checkpoint) string {
	return c.String()
}
