package sunlight_test

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"filippo.io/sunlight"
	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
)

func ExampleClient() {
	prefix := "https://tuscolo2025h2.skylight.geomys.org/"
	name := "tuscolo2025h2.sunlight.geomys.org"
	keyPEM := []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEK9d4GGtzbkwwsYpEtvnU9KKgZr67
MsGlB7mnF8DW9bHnngHzPzXPbdo7n+FyCwSDYqEHbal1Z0CCVyZD6wQ/ow==
-----END PUBLIC KEY-----`)

	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	var start int64
	hc := &http.Client{Timeout: 5 * time.Second}
	for {
		res, err := hc.Get(prefix + "checkpoint")
		if err != nil {
			panic(err)
		}
		signedCheckpoint, err := io.ReadAll(res.Body)
		if err != nil {
			panic(err)
		}
		res.Body.Close()

		verifier, err := sunlight.NewRFC6962Verifier(name, key)
		if err != nil {
			panic(err)
		}
		n, err := note.Open(signedCheckpoint, note.VerifierList(verifier))
		if err != nil {
			panic(err)
		}

		checkpoint, err := torchwood.ParseCheckpoint(n.Text)
		if err != nil {
			panic(err)
		}
		if checkpoint.Origin != name {
			panic("origin mismatch")
		}

		client, err := sunlight.NewClient(prefix, nil)
		if err != nil {
			panic(err)
		}
		for i, entry := range client.Entries(checkpoint.Tree, start) {
			fmt.Println(i, entry)
			start = i + 1
		}
		if err := client.Err(); err != nil {
			panic(err)
		}
	}
}
