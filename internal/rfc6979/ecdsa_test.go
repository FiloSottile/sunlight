// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rfc6979

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"filippo.io/bigmod"
)

func testAllCurves(t *testing.T, f func(*testing.T, elliptic.Curve)) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}
	if testing.Short() {
		tests = tests[:1]
	}
	for _, test := range tests {
		curve := test.curve
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f(t, curve)
		})
	}
}

func TestSignAndVerifyASN1(t *testing.T) {
	testAllCurves(t, testSignAndVerifyASN1)
}

func testSignAndVerifyASN1(t *testing.T, c elliptic.Curve) {
	priv, _ := ecdsa.GenerateKey(c, rand.Reader)

	message := []byte("testing")
	hashed := sha256.Sum256(message)
	sig, err := Sign(priv, hashed[:], crypto.SHA256)
	if err != nil {
		t.Errorf("error signing: %s", err)
		return
	}

	if !ecdsa.VerifyASN1(&priv.PublicKey, hashed[:], sig) {
		t.Errorf("VerifyASN1 failed")
	}

	hashed[0] ^= 0xff
	if ecdsa.VerifyASN1(&priv.PublicKey, hashed[:], sig) {
		t.Errorf("VerifyASN1 always works!")
	}
}

func fromHex(s string) *big.Int {
	r, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex")
	}
	return r
}

func TestZeroHashSignature(t *testing.T) {
	testAllCurves(t, testZeroHashSignature)
}

func testZeroHashSignature(t *testing.T, curve elliptic.Curve) {
	zeroHash := make([]byte, crypto.SHA256.Size())

	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	// Sign a hash consisting of all zeros.
	sig, err := Sign(privKey, zeroHash, crypto.SHA256)
	if err != nil {
		panic(err)
	}

	// Confirm that it can be verified.
	if !ecdsa.VerifyASN1(&privKey.PublicKey, zeroHash, sig) {
		t.Errorf("zero hash signature verify failed for %T", curve)
	}
}

func TestRandomPoint(t *testing.T) {
	t.Run("P-256", func(t *testing.T) { testRandomPoint(t, p256()) })
	t.Run("P-384", func(t *testing.T) { testRandomPoint(t, p384()) })
	t.Run("P-521", func(t *testing.T) { testRandomPoint(t, p521()) })
}

func testRandomPoint[Point nistPoint[Point]](t *testing.T, c *nistCurve[Point]) {
	t.Cleanup(func() { testingOnlyRejectionSamplingLooped = nil })
	var loopCount int
	testingOnlyRejectionSamplingLooped = func() { loopCount++ }

	// A sequence of all ones will generate 2^N-1, which should be rejected.
	// (Unless, for example, we are masking too many bits.)
	var looped bool
	if k, p, err := randomPoint(c, func(b []byte) error {
		if !looped {
			for i := range b {
				b[i] = 0xff
			}
			looped = true
			return nil
		}
		_, err := rand.Read(b)
		return err
	}); err != nil {
		t.Fatal(err)
	} else if k.IsZero() == 1 {
		t.Error("k is zero")
	} else if p.Bytes()[0] != 4 {
		t.Error("p is infinity")
	}
	if loopCount == 0 {
		t.Error("overflow was not rejected")
	}
	loopCount = 0

	// A sequence of all zeroes will generate zero, which should be rejected.
	looped = false
	if k, p, err := randomPoint(c, func(b []byte) error {
		if !looped {
			for i := range b {
				b[i] = 0x00
			}
			looped = true
			return nil
		}
		_, err := rand.Read(b)
		return err
	}); err != nil {
		t.Fatal(err)
	} else if k.IsZero() == 1 {
		t.Error("k is zero")
	} else if p.Bytes()[0] != 4 {
		t.Error("p is infinity")
	}
	if loopCount == 0 {
		t.Error("zero was not rejected")
	}
	loopCount = 0

	// P-256 has a 2⁻³² chance of randomly hitting a rejection. For P-224 it's
	// 2⁻¹¹², for P-384 it's 2⁻¹⁹⁴, and for P-521 it's 2⁻²⁶², so if we hit in
	// tests, something is horribly wrong. (For example, we are masking the
	// wrong bits.)
	if c.curve == elliptic.P256() {
		return
	}
	if k, p, err := randomPoint(c, func(b []byte) error {
		_, err := rand.Read(b)
		return err
	}); err != nil {
		t.Fatal(err)
	} else if k.IsZero() == 1 {
		t.Error("k is zero")
	} else if p.Bytes()[0] != 4 {
		t.Error("p is infinity")
	}
	if loopCount > 0 {
		t.Error("unexpected rejection")
	}
}

func TestHashToNat(t *testing.T) {
	t.Run("P-256", func(t *testing.T) { testHashToNat(t, p256()) })
	t.Run("P-384", func(t *testing.T) { testHashToNat(t, p384()) })
	t.Run("P-521", func(t *testing.T) { testHashToNat(t, p521()) })
}

func testHashToNat[Point nistPoint[Point]](t *testing.T, c *nistCurve[Point]) {
	for l := 0; l < 600; l++ {
		h := bytes.Repeat([]byte{0xff}, l)
		hashToNat(c, bigmod.NewNat(), h)
	}
}

func TestRFC6979(t *testing.T) {
	// TODO: generate test vectors for additional randomness.
	// TODO: tests for reduction happening in bits2octets.
	// TODO: vectors with leading zeroes.
	t.Run("P-256", func(t *testing.T) {
		// This vector was bruteforced to find a message that causes the
		// generation of k to loop. It was checked against
		// github.com/codahale/rfc6979 (https://go.dev/play/p/FK5-fmKf7eK),
		// OpenSSL 3.2.0 (https://github.com/openssl/openssl/pull/23130),
		// and python-ecdsa:
		//
		//    ecdsa.keys.SigningKey.from_secret_exponent(
		//        0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721,
		//        ecdsa.curves.curve_by_name("NIST256p"), hashlib.sha256).sign_deterministic(
		//        b"wv[vnX", hashlib.sha256, lambda r, s, order: print(hex(r), hex(s)))
		//
		testRFC6979(t, elliptic.P256(), crypto.SHA256,
			"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
			"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
			"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
			"wv[vnX",
			"EFD9073B652E76DA1B5A019C0E4A2E3FA529B035A6ABB91EF67F0ED7A1F21234",
			"3DB4706C9D9F4A4FE13BB5E08EF0FAB53A57DBAB2061C83A35FA411C68D2BA33")

		// The remaining vectors are from RFC 6979.
		testRFC6979(t, elliptic.P256(), crypto.SHA256,
			"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
			"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
			"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
			"sample",
			"EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
			"F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
		testRFC6979(t, elliptic.P256(), crypto.SHA384,
			"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
			"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
			"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
			"sample",
			"0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719",
			"4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954")
		testRFC6979(t, elliptic.P256(), crypto.SHA512,
			"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
			"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
			"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
			"sample",
			"8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00",
			"2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE")
		testRFC6979(t, elliptic.P256(), crypto.SHA256,
			"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
			"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
			"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
			"test",
			"F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
			"019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083")
		testRFC6979(t, elliptic.P256(), crypto.SHA384,
			"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
			"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
			"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
			"test",
			"83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6",
			"8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C")
		testRFC6979(t, elliptic.P256(), crypto.SHA512,
			"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
			"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
			"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
			"test",
			"461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04",
			"39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55")
	})
	t.Run("P-384", func(t *testing.T) {
		testRFC6979(t, elliptic.P384(), crypto.SHA256,
			"6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
			"EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
			"8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
			"sample",
			"21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD",
			"F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0")
		testRFC6979(t, elliptic.P384(), crypto.SHA256,
			"6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
			"EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
			"8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
			"test",
			"6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB51D451559F918EEDAF2293BE5B475CC8F0188636B",
			"2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D51AB373F9845C0514EEFB14024787265")
	})
	t.Run("P-521", func(t *testing.T) {
		testRFC6979(t, elliptic.P521(), crypto.SHA256,
			"0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
			"1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4",
			"0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5",
			"sample",
			"1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7",
			"04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC")
		testRFC6979(t, elliptic.P521(), crypto.SHA256,
			"0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
			"1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4",
			"0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5",
			"test",
			"00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D8071042EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656AA8",
			"0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694E86")
	})
}

func testRFC6979(t *testing.T, curve elliptic.Curve, hash crypto.Hash, D, X, Y, msg, r, s string) {
	priv := &ecdsa.PrivateKey{
		D: fromHex(D),
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     fromHex(X),
			Y:     fromHex(Y),
		},
	}
	h := hash.New()
	h.Write([]byte(msg))
	sig, err := Sign(priv, h.Sum(nil), hash)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := encodeSignature(fromHex(r).Bytes(), fromHex(s).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, expected) {
		t.Errorf("signature mismatch:\n got: %x\nwant: %x", sig, expected)
	}
}

func benchmarkAllCurves(b *testing.B, f func(*testing.B, elliptic.Curve)) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}
	for _, test := range tests {
		curve := test.curve
		b.Run(test.name, func(b *testing.B) {
			f(b, curve)
		})
	}
}

func BenchmarkSign(b *testing.B) {
	benchmarkAllCurves(b, func(b *testing.B, curve elliptic.Curve) {
		r := bufio.NewReaderSize(rand.Reader, 1<<15)
		priv, err := ecdsa.GenerateKey(curve, r)
		if err != nil {
			b.Fatal(err)
		}
		hashed := []byte("testing")

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			sig, err := Sign(priv, hashed, crypto.SHA256)
			if err != nil {
				b.Fatal(err)
			}
			// Prevent the compiler from optimizing out the operation.
			hashed[0] = sig[0]
		}
	})
}
