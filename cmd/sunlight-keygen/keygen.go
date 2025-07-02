package main

import (
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"

	"filippo.io/keygen"
	"filippo.io/sunlight/internal/immutable"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/mod/sumdb/note"
)

func main() {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	fileFlag := fs.String("f", "", "path to the seed file")
	prefixFlag := fs.String("prefix", "", "submission prefix for the log, to output a witness verifier key")
	fs.Parse(os.Args[1:])
	if fs.NArg() != 0 || *fileFlag == "" {
		fmt.Fprintln(os.Stderr, "usage: sunlight-keygen -f <seed file>")
		fs.PrintDefaults()
		os.Exit(2)
	}

	if _, err := os.Stat(*fileFlag); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Creating new immutable seed file at: %s\n", *fileFlag)
		seed := make([]byte, 32)
		rand.Read(seed)
		f, err := os.OpenFile(*fileFlag, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
		if err != nil {
			log.Fatal("failed to create seed file:", err)
		}
		if _, err := f.Write(seed); err != nil {
			log.Fatal("failed to write seed file:", err)
		}
		immutable.Set(f)
		if err := f.Close(); err != nil {
			log.Fatal("failed to close seed file:", err)
		}
	}

	seed, err := os.ReadFile(*fileFlag)
	if err != nil {
		log.Fatal("failed to load seed:", err)
	}
	if len(seed) != 32 {
		log.Fatal("seed file must be exactly 32 bytes")
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

	ecPubKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))

	ed25519Secret := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, seed, []byte("sunlight"), []byte("Ed25519 log key")), ed25519Secret); err != nil {
		log.Fatal("failed to derive Ed25519 key:", err)
	}
	wk := ed25519.NewKeyFromSeed(ed25519Secret).Public().(ed25519.PublicKey)

	edPubKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: wk}))

	fmt.Printf("Log ID: %s\n", base64.StdEncoding.EncodeToString(logID[:]))
	if *prefixFlag != "" {
		prefix, err := url.Parse(*prefixFlag)
		if err != nil {
			log.Fatal("failed to parse submission prefix:", err)
		}
		if prefix.Scheme == "" || prefix.Host == "" {
			log.Fatal("submission prefix must be a valid URL with scheme and host")
		}
		v, err := note.NewEd25519VerifierKey(prefix.Host+prefix.Path, wk)
		if err != nil {
			log.Fatal("failed to create verifier key:", err)
		}
		fmt.Printf("Verifier key: %s\n", v)
	}
	fmt.Printf("ECDSA public key:\n%s", ecPubKey)
	fmt.Printf("Ed25519 public key:\n%s", edPubKey)
}
