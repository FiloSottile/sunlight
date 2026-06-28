package main

import (
	"cmp"
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
	"filippo.io/mldsa"
	"filippo.io/sunlight/internal/immutable"
	"filippo.io/torchwood"
	"golang.org/x/crypto/hkdf"
)

func main() {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	fileFlag := fs.String("f", "", "path to the seed file")
	logFlag := fs.String("log", "", "submission prefix for the log")
	prefixFlag := fs.String("prefix", "", "legacy flag name for -log")
	witnessFlag := fs.String("witness", "", "witness name")
	fs.Parse(os.Args[1:])
	if fs.NArg() != 0 || *fileFlag == "" {
		fmt.Fprintln(os.Stderr, "usage: sunlight-keygen -f <seed file> [-log <submission prefix> | -witness <witness name>]")
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

	if *witnessFlag != "" {
		ed25519Secret := make([]byte, ed25519.SeedSize)
		if _, err := io.ReadFull(hkdf.New(sha256.New, seed, []byte("sunlight Ed25519 witness key"),
			[]byte(*witnessFlag)), ed25519Secret); err != nil {
			log.Fatal("failed to derive Ed25519 key:", err)
		}
		wk := ed25519.NewKeyFromSeed(ed25519Secret)
		s, err := torchwood.NewCosignatureSigner(*witnessFlag, wk)
		if err != nil {
			log.Fatal("failed to create witness signer:", err)
		}
		fmt.Printf("Witness vkey (Ed25519): %s\n", s.Verifier())

		mldsaSecret := make([]byte, mldsa.PrivateKeySize)
		if _, err := io.ReadFull(hkdf.New(sha256.New, seed, []byte("sunlight ML-DSA-44 witness key"),
			[]byte(*witnessFlag)), mldsaSecret); err != nil {
			log.Fatal("failed to derive ML-DSA-44 key:", err)
		}
		mk, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), mldsaSecret)
		if err != nil {
			log.Fatal("failed to generate ML-DSA-44 key:", err)
		}
		s, err = torchwood.NewCosignatureSigner(*witnessFlag, mk)
		if err != nil {
			log.Fatal("failed to create witness signer:", err)
		}
		fmt.Printf("Witness vkey (ML-DSA-44): %s\n", s.Verifier())

		return
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
	fmt.Printf("Log ID: %s\n", base64.StdEncoding.EncodeToString(logID[:]))

	ecPubKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	fmt.Printf("ECDSA public key:\n%s", ecPubKey)

	if *prefixFlag != "" || *logFlag != "" {
		mldsaSecret := make([]byte, mldsa.PrivateKeySize)
		if _, err := io.ReadFull(hkdf.New(sha256.New, seed, []byte("sunlight"), []byte("ML-DSA-44 log key")), mldsaSecret); err != nil {
			log.Fatal("failed to derive ML-DSA-44 key:", err)
		}
		mldsaKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), mldsaSecret)
		if err != nil {
			log.Fatal("failed to generate ML-DSA-44 key:", err)
		}
		wk := mldsaKey.PublicKey()

		prefix, err := url.Parse(cmp.Or(*logFlag, *prefixFlag))
		if err != nil {
			log.Fatal("failed to parse submission prefix:", err)
		}
		if prefix.Scheme == "" || prefix.Host == "" {
			log.Fatal("submission prefix must be a valid URL with scheme and host")
		}

		v, err := torchwood.NewCosignatureVerifierFromKey(prefix.Host+prefix.Path, wk)
		if err != nil {
			log.Fatal("failed to create verifier key:", err)
		}
		fmt.Printf("ML-DSA-44 verifier key: %s\n", v)
	}
}
