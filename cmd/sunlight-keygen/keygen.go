package main

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"

	"filippo.io/keygen"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/mod/sumdb/note"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: sunlight-keygen <name> <seed file>")
	}

	seed, err := os.ReadFile(os.Args[2])
	if err != nil {
		log.Fatal("failed to load seed:", err)
	}

	ecdsaSecret := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, seed, []byte("sunlight"), []byte("ECDSA P-256 log key")), ecdsaSecret); err != nil {
		log.Fatal("failed to derive ECDSA secret:", err)
	}
	k, err := keygen.ECDSA(elliptic.P256(), ecdsaSecret)
	if err != nil {
		log.Fatal("failed to generate ECDSA key:", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		log.Fatal("failed to marshal public key from private key for display:", err)
	}

	logID := sha256.Sum256(spki)

	publicKey := base64.StdEncoding.EncodeToString(spki)

	ed25519Secret := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, seed, []byte("sunlight"), []byte("Ed25519 log key")), ed25519Secret); err != nil {
		log.Fatal("failed to derive Ed25519 key:", err)
	}
	wk := ed25519.NewKeyFromSeed(ed25519Secret).Public().(ed25519.PublicKey)

	v, err := note.NewEd25519VerifierKey(os.Args[1], wk)
	if err != nil {
		log.Fatal("failed to create verifier key:", err)
	}

	fmt.Printf("Log ID: %s\n", base64.StdEncoding.EncodeToString(logID[:]))
	fmt.Printf("ECDSA public key: %s\n", publicKey)
	fmt.Printf("Ed25519 public key: %s\n", base64.StdEncoding.EncodeToString(wk))
	fmt.Printf("Witness verifier key: %s\n", v)
}
