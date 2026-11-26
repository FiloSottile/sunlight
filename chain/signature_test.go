package chain

import (
	"crypto"
	"encoding/hex"
	"testing"
)

// The encodings of the Baseline Requirements, version 2.3.0, Sections
// 7.1.3.1 and 7.1.3.2.

func TestSignatureAlgorithms(t *testing.T) {
	for _, tt := range []struct {
		der    string
		scheme scheme
		hash   crypto.Hash
	}{
		{"300d06092a864886f70d01010b0500", rsaPKCS1v15, crypto.SHA256},
		{"300d06092a864886f70d01010c0500", rsaPKCS1v15, crypto.SHA384},
		{"300d06092a864886f70d01010d0500", rsaPKCS1v15, crypto.SHA512},
		{"304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120", rsaPSS, crypto.SHA256},
		{"304106092a864886f70d01010a3034a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130", rsaPSS, crypto.SHA384},
		{"304106092a864886f70d01010a3034a00f300d06096086480165030402030500a11c301a06092a864886f70d010108300d06096086480165030402030500a203020140", rsaPSS, crypto.SHA512},
		{"300a06082a8648ce3d040302", ecdsaScheme, crypto.SHA256},
		{"300a06082a8648ce3d040303", ecdsaScheme, crypto.SHA384},
		{"300a06082a8648ce3d040304", ecdsaScheme, crypto.SHA512},
	} {
		der, err := hex.DecodeString(tt.der)
		if err != nil {
			t.Fatal(err)
		}
		alg, ok := parseSignatureAlgorithm(der)
		if !ok {
			t.Errorf("%s: not accepted", tt.der)
		} else if alg.scheme != tt.scheme || alg.hash != tt.hash {
			t.Errorf("%s: got scheme %d with %v, want scheme %d with %v", tt.der, alg.scheme, alg.hash, tt.scheme, tt.hash)
		}
	}
	// Eight encodings for each of the three hashes.
	if len(pssParameters) != 24 {
		t.Errorf("%d RSASSA-PSS-params encodings, want 24", len(pssParameters))
	}
}

func TestPublicKeyAlgorithms(t *testing.T) {
	for _, tt := range []struct {
		der  string
		want string
	}{
		{"300d06092a864886f70d0101010500", "\x30\x0d\x06\x09" + oidRSAEncryption + "\x05\x00"},
		{"301306072a8648ce3d020106082a8648ce3d030107", "\x30\x13\x06\x07" + oidECPublicKey + "\x06\x08" + oidSecp256r1},
		{"301006072a8648ce3d020106052b81040022", "\x30\x10\x06\x07" + oidECPublicKey + "\x06\x05" + oidSecp384r1},
		{"301006072a8648ce3d020106052b81040023", "\x30\x10\x06\x07" + oidECPublicKey + "\x06\x05" + oidSecp521r1},
	} {
		if got := hex.EncodeToString([]byte(tt.want)); got != tt.der {
			t.Errorf("got %s, want %s", got, tt.der)
		}
	}
}
