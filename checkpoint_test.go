package sunlight

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func TestRFC6962InjectedSigner(t *testing.T) {
	sig, err := base64.StdEncoding.DecodeString("BAMASDBGAiEAnaHGuwnyyHWvrfgEn3qtl1j2heMzocku6ZAItYD75m8CIQCpotlpH5GEPEfMMzky72BCuIl14FB65t5SWZ91vgTQOg==")
	if err != nil {
		t.Fatal(err)
	}
	sthBytes := []byte(`{
		"sha256_root_hash": "l+XrWXWRyp4SmATORgTfz4CcYS/VlE7CeTuWI0FAk3o=",
		"timestamp": 1588741228371,
		"tree_head_signature": "BAMASDBGAiEAnaHGuwnyyHWvrfgEn3qtl1j2heMzocku6ZAItYD75m8CIQCpotlpH5GEPEfMMzky72BCuIl14FB65t5SWZ91vgTQOg==",
		"tree_size": 90785920
	}`)
	var sth ct.SignedTreeHead
	if err := json.Unmarshal(sthBytes, &sth); err != nil {
		t.Fatal(err)
	}
	key, err := ct.PublicKeyFromB64("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESYlKFDLLFmA9JScaiaNnqlU8oWDytxIYMfswHy9Esg0aiX+WnP/yj4O0ViEHtLwbmOQeSWBGkIu9YK9CLeer+g==")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := ct.NewSignatureVerifier(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifySTHSignature(sth); err != nil {
		t.Fatal(err)
	}
	s, err := NewRFC6962InjectedSigner("example.com", key, sig, int64(sth.Timestamp))
	if err != nil {
		t.Fatal(err)
	}
	c := &Checkpoint{
		Origin: "example.com",
		Tree: tlog.Tree{
			N:    int64(sth.TreeSize),
			Hash: tlog.Hash(sth.SHA256RootHash),
		},
	}
	n, err := note.Sign(&note.Note{Text: c.String()}, s)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewRFC6962Verifier("example.com", key)
	if err != nil {
		t.Fatal(err)
	}
	nn, err := note.Open([]byte(n), note.VerifierList(v))
	if err != nil {
		t.Fatal(err)
	}
	tt, err := RFC6962SignatureTimestamp(nn.Sigs[0])
	if err != nil {
		t.Fatal(err)
	}
	if tt != int64(sth.Timestamp) {
		t.Fatalf("got timestamp %d, want %d", tt, sth.Timestamp)
	}
}
