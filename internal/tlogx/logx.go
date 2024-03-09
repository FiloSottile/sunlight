// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found at
// https://go.googlesource.com/go/+/refs/heads/master/LICENSE.

package tlogx

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

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
//
// Upstreamed as https://go.dev/cl/570295.
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
