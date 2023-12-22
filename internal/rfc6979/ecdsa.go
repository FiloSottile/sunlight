// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rfc6979

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"errors"
	"math/big"
	"sync"

	"filippo.io/bigmod"
	"filippo.io/nistec"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// randomPoint returns a random scalar and the corresponding point using the
// procedure given in FIPS 186-4, Appendix B.5.2 (rejection sampling).
//
// rand is a function that fills the provided buffer with random bytes
// completely, or returns an error.
//
// This function can be used with ReadFull(rand.Reader) for key generation, or
// as step (h) of Section 3.2 of RFC 6979 for nonce generation. Note that the
// latter doesn't treat the RNG as a continuous stream of bytes but as a source
// to draw discrete buffers from, hence rand not being an io.Reader.
func randomPoint[Point nistPoint[Point]](c *nistCurve[Point], rand func([]byte) error) (k *bigmod.Nat, p Point, err error) {
	k = bigmod.NewNat()
	for {
		b := make([]byte, c.N.Size())
		if err = rand(b); err != nil {
			return
		}

		// Right shift the bytes buffer to match the bit length of N. It would
		// be safer and easier to mask off the extra bits on the left, but this
		// is what RFC 6979 does, and doing it consistently lets us properly
		// test it. (These might be the most dangerous lines in the package and
		// maybe in the library: a single bit of bias in the selection of nonces
		// would likely lead to key recovery.)
		if excess := len(b)*8 - c.N.BitLen(); excess > 0 {
			// Just to be safe, assert that this only happens for the one curve that
			// doesn't have a round number of bits.
			if excess != 0 && c.curve.Params().Name != "P-521" {
				panic("ecdsa: internal error: unexpectedly masking off bits")
			}
			b = rightShift(b, excess)
		}

		// FIPS 186-4 makes us check k <= N - 2 and then add one.
		// RFC 6979 makes us check 0 < k <= N - 1.
		// The two are strictly equivalent (except that we are about reproducing
		// RFC 6979 bit-by-bit for determinism and testability).
		// None of this matters anyway because the chance of selecting
		// zero is cryptographically negligible.
		if _, err = k.SetBytes(b, c.N); err == nil && k.IsZero() == 0 {
			break
		}

		if testingOnlyRejectionSamplingLooped != nil {
			testingOnlyRejectionSamplingLooped()
		}
	}

	p, err = c.newPoint().ScalarBaseMult(k.Bytes(c.N))
	return
}

// testingOnlyRejectionSamplingLooped is called when rejection sampling in
// randomPoint rejects a candidate for being higher than the modulus.
var testingOnlyRejectionSamplingLooped func()

// rfc6979DRBG is the candidate generation function for randomPoint defined by
// RFC 6979, Section 3.2. If rnd is empty, the signature will be deterministic.
func rfc6979DRBG[Point nistPoint[Point]](c *nistCurve[Point], x *ecdsa.PrivateKey,
	h1 *bigmod.Nat, hash crypto.Hash) func([]byte) error {

	// V = 0x01 0x01 0x01 ... 0x01
	V := make([]byte, hash.Size())
	for i := range V {
		V[i] = 0x01
	}

	// K = 0x00 0x00 0x00 ... 0x00
	K := make([]byte, hash.Size())

	// K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
	h := hmac.New(hash.New, K)
	h.Write(V)
	h.Write([]byte{0x00})
	h.Write(x.D.FillBytes(make([]byte, c.N.Size())))
	h.Write(h1.Bytes(c.N))
	K = h.Sum(K[:0])

	// V = HMAC_K(V)
	h = hmac.New(hash.New, K)
	h.Write(V)
	V = h.Sum(V[:0])

	firstLoop := true
	return func(b []byte) error {
		if firstLoop {
			// K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
			h.Reset()
			h.Write(V)
			h.Write([]byte{0x01})
			h.Write(x.D.FillBytes(make([]byte, c.N.Size())))
			h.Write(h1.Bytes(c.N))
			K = h.Sum(K[:0])

			firstLoop = false
		} else {
			// K = HMAC_K(V || 0x00)
			h.Reset()
			h.Write(V)
			h.Write([]byte{0x00})
			K = h.Sum(K[:0])
		}

		// V = HMAC_K(V)
		h = hmac.New(hash.New, K)
		h.Write(V)
		V = h.Sum(V[:0])

		tlen := 0
		for tlen < len(b) {
			// V = HMAC_K(V)
			// T = T || V
			h.Reset()
			h.Write(V)
			V = h.Sum(V[:0])
			tlen += copy(b[tlen:], V)
		}
		return nil
	}
}

func Sign(priv *ecdsa.PrivateKey, digest []byte, hash crypto.Hash) ([]byte, error) {
	switch priv.Curve.Params() {
	case elliptic.P256().Params():
		return signNISTEC(p256(), priv, digest, hash)
	case elliptic.P384().Params():
		return signNISTEC(p384(), priv, digest, hash)
	case elliptic.P521().Params():
		return signNISTEC(p521(), priv, digest, hash)
	default:
		return nil, errors.New("ecdsa: unsupported curve")
	}
}

func signNISTEC[Point nistPoint[Point]](c *nistCurve[Point], priv *ecdsa.PrivateKey, digest []byte, hash crypto.Hash) (sig []byte, err error) {
	// SEC 1, Version 2.0, Section 4.1.3

	e := bigmod.NewNat()
	hashToNat(c, e, digest)

	k, R, err := randomPoint(c, rfc6979DRBG(c, priv, e, hash))
	if err != nil {
		return nil, err
	}

	// kInv = k⁻¹
	kInv := bigmod.NewNat()
	// Calculate the inverse of s in GF(N) using Fermat's method
	// (exponentiation modulo P - 2, per Euler's theorem)
	kInv.Exp(k, c.nMinus2, c.N)

	Rx, err := R.BytesX()
	if err != nil {
		return nil, err
	}
	r, err := bigmod.NewNat().SetOverflowingBytes(Rx, c.N)
	if err != nil {
		return nil, err
	}

	// The spec wants us to retry here, but the chance of hitting this condition
	// on a large prime-order group like the NIST curves we support is
	// cryptographically negligible. If we hit it, something is awfully wrong.
	if r.IsZero() == 1 {
		return nil, errors.New("ecdsa: internal error: r is zero")
	}

	s, err := bigmod.NewNat().SetBytes(priv.D.Bytes(), c.N)
	if err != nil {
		return nil, err
	}
	s.Mul(r, c.N)
	s.Add(e, c.N)
	s.Mul(kInv, c.N)

	// Again, the chance of this happening is cryptographically negligible.
	if s.IsZero() == 1 {
		return nil, errors.New("ecdsa: internal error: s is zero")
	}

	return encodeSignature(r.Bytes(c.N), s.Bytes(c.N))
}

func encodeSignature(r, s []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.Bytes()
}

// addASN1IntBytes encodes in ASN.1 a positive integer represented as
// a big-endian byte slice with zero or more leading zeroes.
func addASN1IntBytes(b *cryptobyte.Builder, bytes []byte) {
	for len(bytes) > 0 && bytes[0] == 0 {
		bytes = bytes[1:]
	}
	if len(bytes) == 0 {
		b.SetError(errors.New("invalid integer"))
		return
	}
	b.AddASN1(asn1.INTEGER, func(c *cryptobyte.Builder) {
		if bytes[0]&0x80 != 0 {
			c.AddUint8(0)
		}
		c.AddBytes(bytes)
	})
}

// hashToNat sets e to the left-most bits of hash, according to
// SEC 1, Section 4.1.3, point 5 and Section 4.1.4, point 3.
func hashToNat[Point nistPoint[Point]](c *nistCurve[Point], e *bigmod.Nat, hash []byte) {
	if size := c.N.Size(); len(hash) >= size {
		hash = hash[:size]
		if excess := len(hash)*8 - c.N.BitLen(); excess > 0 {
			hash = rightShift(hash, excess)
		}
	}
	_, err := e.SetOverflowingBytes(hash, c.N)
	if err != nil {
		panic("ecdsa: internal error: truncated hash is too long")
	}
}

// rightShift implements the right shift necessary for bits2int.
//
// ECDSA asks us to take the left-most log2(N) bits of hash, and use them as
// an integer modulo N. This is the absolute worst of all worlds: we still
// have to reduce, because the result might still overflow N, but to take
// the left-most bits for P-521 we have to do a right shift.
func rightShift(b []byte, shift int) []byte {
	if shift >= 8 {
		panic("ecdsa: internal error: tried to shift by more than 8 bits")
	}
	b = bytes.Clone(b)
	for i := len(b) - 1; i >= 0; i-- {
		b[i] >>= shift
		if i > 0 {
			b[i] |= b[i-1] << (8 - shift)
		}
	}
	return b
}

type nistCurve[Point nistPoint[Point]] struct {
	newPoint func() Point
	curve    elliptic.Curve
	N        *bigmod.Modulus
	nMinus2  []byte
}

// nistPoint is a generic constraint for the nistec Point types.
type nistPoint[T any] interface {
	Bytes() []byte
	BytesX() ([]byte, error)
	SetBytes([]byte) (T, error)
	Add(T, T) T
	ScalarMult(T, []byte) (T, error)
	ScalarBaseMult([]byte) (T, error)
}

var p256Once sync.Once
var _p256 *nistCurve[*nistec.P256Point]

func p256() *nistCurve[*nistec.P256Point] {
	p256Once.Do(func() {
		_p256 = &nistCurve[*nistec.P256Point]{
			newPoint: func() *nistec.P256Point { return nistec.NewP256Point() },
		}
		precomputeParams(_p256, elliptic.P256())
	})
	return _p256
}

var p384Once sync.Once
var _p384 *nistCurve[*nistec.P384Point]

func p384() *nistCurve[*nistec.P384Point] {
	p384Once.Do(func() {
		_p384 = &nistCurve[*nistec.P384Point]{
			newPoint: func() *nistec.P384Point { return nistec.NewP384Point() },
		}
		precomputeParams(_p384, elliptic.P384())
	})
	return _p384
}

var p521Once sync.Once
var _p521 *nistCurve[*nistec.P521Point]

func p521() *nistCurve[*nistec.P521Point] {
	p521Once.Do(func() {
		_p521 = &nistCurve[*nistec.P521Point]{
			newPoint: func() *nistec.P521Point { return nistec.NewP521Point() },
		}
		precomputeParams(_p521, elliptic.P521())
	})
	return _p521
}

func precomputeParams[Point nistPoint[Point]](c *nistCurve[Point], curve elliptic.Curve) {
	params := curve.Params()
	c.curve = curve
	var err error
	c.N, err = bigmod.NewModulusFromBig(params.N)
	if err != nil {
		panic(err)
	}
	c.nMinus2 = new(big.Int).Sub(params.N, big.NewInt(2)).Bytes()
}
