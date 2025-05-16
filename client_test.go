package sunlight_test

import (
	"context"
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
	prefix := "https://navigli2025h2.skylight.geomys.org/"
	name := "navigli2025h2.sunlight.geomys.org"
	keyPEM := []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4i7AmqGoGHsorn/eyclTMjrAnM0J
UUbyGJUxXqq1AjQ4qBC77wXkWt7s/HA8An2vrEBKIGQzqTjV8QIHrmpd4w==
-----END PUBLIC KEY-----`)

	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	var start int64
	hc := &http.Client{Timeout: 10 * time.Second}
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

		client, err := sunlight.NewClient(prefix, &sunlight.ClientConfig{
			UserAgent: "ExampleClient (changeme@example.com, +https://example.com)",
		})
		if err != nil {
			panic(err)
		}
		for i, entry := range client.Entries(context.Background(), checkpoint.Tree, start) {
			fmt.Printf("%d: %d %d %x\n", i, entry.LeafIndex, entry.Timestamp, entry.IssuerKeyHash)
			start = i + 1
		}
		if err := client.Err(); err != nil {
			panic(err)
		}
	}
}
