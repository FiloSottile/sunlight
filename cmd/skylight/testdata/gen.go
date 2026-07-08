//go:build ignore

// Gen generates the static testdata served by the skylight webtest tests: a
// single tree shared by all the configured logs, and a witness directory.
//
// The output is deterministic (fixed key, fixed tree, no randomness), so
// running it again after changing it produces reviewable diffs.
//
// Run it from the cmd/skylight directory:
//
//	go run testdata/gen.go
package main

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"filippo.io/sunlight"
	"filippo.io/torchwood"
	ct "github.com/google/certificate-transparency-go"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const (
	origin   = "rome2026h1.example.org"
	origin2  = "milan2026h1.example.org"
	treeSize = 300
	// timestamp is 2025-12-31T00:00:00Z, before the log's NotAfterLimit of
	// 2026-01-01T00:00:00Z. The log is sunset (past NotAfterLimit plus one
	// week), so /health accepts an arbitrarily old final checkpoint.
	timestamp = 1767139200000
)

func main() {
	// A fixed private key, so the generated signature is stable. The scalar is
	// reduced modulo the P-256 order, and ECDSA signing with a nil random
	// source is deterministic.
	scalar := sha256.Sum256([]byte("skylight test log key"))
	d := new(big.Int).SetBytes(scalar[:])
	d.Mod(d, elliptic.P256().Params().N)
	key := &ecdsa.PrivateKey{D: d}
	key.Curve = elliptic.P256()
	key.X, key.Y = key.Curve.ScalarBaseMult(d.Bytes())

	treeHash := tlog.Hash(sha256.Sum256([]byte("skylight test tree root")))

	sthBytes, err := ct.SerializeSTHSignatureInput(ct.SignedTreeHead{
		Version:        ct.V1,
		TreeSize:       treeSize,
		Timestamp:      timestamp,
		SHA256RootHash: ct.SHA256Hash(treeHash),
	})
	if err != nil {
		log.Fatal(err)
	}
	digest := sha256.Sum256(sthBytes)
	sig, err := key.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}
	var b cryptobyte.Builder
	b.AddUint8(4 /* hash = sha256 */)
	b.AddUint8(3 /* signature = ecdsa */)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(sig)
	})
	treeHeadSignature, err := b.Bytes()
	if err != nil {
		log.Fatal(err)
	}
	signer, err := sunlight.NewRFC6962InjectedSigner(origin, key.Public(), treeHeadSignature, timestamp)
	if err != nil {
		log.Fatal(err)
	}
	checkpoint, err := note.Sign(&note.Note{Text: torchwood.Checkpoint{
		Origin: origin,
		Tree:   tlog.Tree{N: treeSize, Hash: treeHash},
	}.String()}, signer)
	if err != nil {
		log.Fatal(err)
	}

	pkix, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		log.Fatal(err)
	}
	logID := sha256.Sum256(pkix)

	logV3, err := json.MarshalIndent(map[string]any{
		"description":      origin,
		"friendly_name":    "rome2026h1",
		"submission_url":   "https://rome2026h1.example.org/",
		"monitoring_url":   "https://rome2026h1.example.org/",
		"log_id":           logID[:],
		"key":              pkix,
		"mmd":              60,
		"log_spec":         "static-ct-api",
		"mmd_seconds":      60,
		"tls_only":         true,
		"intended_use":     "test",
		"status":           "readonly",
		"status_timestamp": "2026-01-08T00:00:00Z",
		"temporal_interval": map[string]string{
			"start_inclusive": "2025-07-01T00:00:00Z",
			"end_exclusive":   "2026-01-01T00:00:00Z",
		},
		"final_tree_head": map[string]any{
			"sha256_root_hash": treeHash[:],
			"tree_size":        treeSize,
			"timestamp":        timestamp,
		},
		"submission_endpoint": map[string]string{"url": "https://rome2026h1.example.org/"},
		"monitoring_endpoint": map[string]string{"url": "https://rome2026h1.example.org/"},
		"log_software":        map[string]string{"name": "sunlight", "version": "test"},
	}, "", "    ")
	if err != nil {
		log.Fatal(err)
	}

	issuer := []byte("fake issuer certificate for the skylight tests\n")
	issuerHash := sha256.Sum256(issuer)

	write("tree/checkpoint", checkpoint)
	write("tree/log.v3.json", append(logV3, '\n'))
	write("tree/tile/0/000", []byte("fake full level 0 tile\n"))
	write("tree/tile/0/001.p/44", []byte("fake partial level 0 tile\n"))
	write("tree/tile/1/000.p/1", []byte("fake partial level 1 tile\n"))
	write("tree/tile/data/000", gzipped("fake full data tile\n"))
	write("tree/tile/data/001.p/44", gzipped("fake partial data tile\n"))
	write("tree/tile/names/000", gzipped("[\"example.org\"]\n"))
	write("tree/issuer/"+hex.EncodeToString(issuerHash[:]), issuer)

	// The witness stores the checkpoints of the logs it observes, addressed by
	// the hex-encoded SHA-256 of their origin, and full mirrored logs under
	// mirror/ per c2sp.org/tlog-mirror. Mirrored logs use c2sp.org/tlog-tiles
	// paths: entry bundles live at tile/entries/, and are stored
	// gzip-compressed like data tiles.
	originHash := sha256.Sum256([]byte(origin))
	witnessed := hex.EncodeToString(originHash[:])
	write("witness/"+witnessed+"/checkpoint", checkpoint)
	write("witness/mirror/"+witnessed+"/checkpoint", checkpoint)
	// Decoy files that no request path should map to: the per-origin paths of
	// unknown origins must not collapse to the directory roots.
	write("witness/checkpoint", []byte("decoy, must never be served\n"))
	write("witness/mirror/checkpoint", []byte("decoy, must never be served\n"))
	write("witness/mirror/"+witnessed+"/tile/0/000", []byte("fake mirrored level 0 tile\n"))
	write("witness/mirror/"+witnessed+"/tile/entries/000", gzipped("fake mirrored entry bundle\n"))
	write("witness/mirror/"+witnessed+"/tile/entries/001.p/44", gzipped("fake mirrored partial entry bundle\n"))

	// A second witness, observing a different log and not operating as a
	// mirror, to exercise serving multiple witnesses from one Skylight.
	origin2Hash := sha256.Sum256([]byte(origin2))
	witnessed2 := hex.EncodeToString(origin2Hash[:])
	write("witness2/"+witnessed2+"/checkpoint", []byte("fake checkpoint for "+origin2+"\n"))

	fmt.Printf("origin hash: %s\n", witnessed)
	fmt.Printf("origin2 hash: %s\n", witnessed2)
	fmt.Printf("issuer hash: %s\n", hex.EncodeToString(issuerHash[:]))
}

func write(name string, data []byte) {
	path := filepath.Join("testdata", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o666); err != nil {
		log.Fatal(err)
	}
}

func gzipped(data string) []byte {
	buf := &bytes.Buffer{}
	w := gzip.NewWriter(buf)
	if _, err := w.Write([]byte(data)); err != nil {
		log.Fatal(err)
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}
	return buf.Bytes()
}
