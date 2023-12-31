// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at
// https://go.googlesource.com/go/+/refs/heads/master/LICENSE.

package tlogx

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// NewTilesForSize is like [tlog.NewTiles] but only lists the largest partial
// tile for each coordinate.
//
// This makes only the tree of size newTreeSize retrievable, and not the trees
// of sizes oldTreeSize+1 to newTreeSize-1 (until the relevant full tiles are
// available), assuming tiles for oldTreeSize were similarly generated.
//
// NewTilesForSize also doesn't return tiles that have not grown since
// oldTreeSize; it's unclear why [tlog.NewTiles] does.
func NewTilesForSize(h int, oldTreeSize, newTreeSize int64) []tlog.Tile {
	if h <= 0 {
		panic(fmt.Sprintf("NewTilesForSize: invalid height %d", h))
	}
	var tiles []tlog.Tile
	for level := 0; newTreeSize>>(h*level) > 0; level++ {
		oldN := oldTreeSize >> (h * level)
		newN := newTreeSize >> (h * level)
		if oldN == newN {
			continue
		}
		for n := oldN >> h; n < newN>>h; n++ {
			tiles = append(tiles, tlog.Tile{H: h, L: int(level), N: n, W: 1 << h})
		}
		n := newN >> h
		if w := int(newN - n<<h); w > 0 {
			tiles = append(tiles, tlog.Tile{H: h, L: int(level), N: n, W: w})
		}
	}
	return tiles
}

const maxCheckpointSize = 1e6

type Checkpoint struct {
	Origin    string
	N         int64
	Hash      tlog.Hash
	Extension string
}

func ParseCheckpoint(text string) (Checkpoint, error) {
	// This is an extended version of tlog.ParseTree.
	//
	// A checkpoint looks like:
	//
	//	example.com/origin
	//	2
	//	nND/nri/U0xuHUrYSy0HtMeal2vzD9V4k/BO79C+QeI=
	//
	// It can be followed by extra extension lines.

	if strings.Count(text, "\n") < 3 || len(text) > maxCheckpointSize {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}
	if !strings.HasSuffix(text, "\n") {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}

	lines := strings.SplitN(text, "\n", 4)

	n, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || n < 0 || lines[1] != strconv.FormatInt(n, 10) {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}

	h, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(h) != tlog.HashSize {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}

	rest := lines[3]
	for rest != "" {
		before, after, found := strings.Cut(rest, "\n")
		if before == "" || !found {
			return Checkpoint{}, errors.New("malformed checkpoint")
		}
		rest = after
	}

	var hash tlog.Hash
	copy(hash[:], h)
	return Checkpoint{lines[0], n, hash, lines[3]}, nil
}

func MarshalCheckpoint(c Checkpoint) string {
	return fmt.Sprintf("%s\n%d\n%s\n%s",
		c.Origin, c.N, base64.StdEncoding.EncodeToString(c.Hash[:]), c.Extension)
}

type verifier struct {
	name   string
	hash   uint32
	verify func(msg, sig []byte) bool
}

func (v *verifier) Name() string                { return v.name }
func (v *verifier) KeyHash() uint32             { return v.hash }
func (v *verifier) Verify(msg, sig []byte) bool { return v.verify(msg, sig) }

// NewInjectedSigner constructs a new InjectedSigner that produces
// note signatures bearing the provided fixed value.
func NewInjectedSigner(name string, alg uint8, key, sig []byte) (*InjectedSigner, error) {
	if !isValidName(name) {
		return nil, fmt.Errorf("invalid name %q", name)
	}

	s := &InjectedSigner{}
	s.name = name
	s.hash = keyHash(name, append([]byte{alg}, key...))
	s.sign = func(msg []byte) ([]byte, error) {
		return sig, nil
	}
	s.verify = func(msg, s []byte) bool {
		return bytes.Equal(s, sig)
	}

	return s, nil
}

type InjectedSigner struct {
	verifier
	sign func([]byte) ([]byte, error)
}

var _ note.Signer = &InjectedSigner{}

func (s *InjectedSigner) Sign(msg []byte) ([]byte, error) { return s.sign(msg) }
func (s *InjectedSigner) Verifier() note.Verifier         { return &s.verifier }

// NewRFC6962Verifier constructs a new RFC6962Verifier that verifies a RFC 6962
// TreeHeadSignature formatted per c2sp.org/checkpoint.
func NewRFC6962Verifier(name string, key crypto.PublicKey) (*RFC6962Verifier, error) {
	if !isValidName(name) {
		return nil, fmt.Errorf("invalid name %q", name)
	}

	pkix, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	keyID := sha256.Sum256(pkix)

	v := &RFC6962Verifier{}
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

		defer func() {
			if ok && v.Timestamp != nil {
				v.Timestamp(timestamp)
			}
		}()

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
			return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) == nil
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

type RFC6962Verifier struct {
	verifier

	// Timestamp, if not nil, is called with the timestamp extracted from any
	// valid verified signature.
	Timestamp func(uint64)
}

var _ note.Verifier = &RFC6962Verifier{}

// isValidName reports whether name is valid.
// It must be non-empty and not have any Unicode spaces or pluses.
func isValidName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

func keyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}
