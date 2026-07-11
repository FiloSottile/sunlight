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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
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
	// The witness.v0.json and mirror.v0.json metadata files list the cosigner
	// verifier keys /health uses to verify the served checkpoints. The keys are
	// derived from fixed seeds, and the cosignatures carry a fixed timestamp
	// (which /health doesn't check), so the output stays deterministic.
	witnessCosigner := newCosigner("witness.example.org", "skylight test witness key")
	witness2Cosigner := newCosigner("witness2.example.org", "skylight test witness2 key")
	mirrorCosigner := newCosigner("mirror.example.org", "skylight test mirror key")
	witnessV0, err := json.MarshalIndent(map[string]any{
		"name":           "witness.example.org",
		"submission_url": "https://witness-submit.example.org/",
		"monitoring_url": "https://witness.example.org/",
		"verifier_keys":  []string{witnessCosigner.Verifier().String()},
		"software":       map[string]string{"name": "sunlight", "version": "test"},
	}, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	mirrorV0, err := json.MarshalIndent(map[string]any{
		"name":           "mirror.example.org",
		"submission_url": "https://witness-submit.example.org/mirror/",
		"monitoring_url": "https://witness.example.org/mirror/",
		"verifier_keys":  []string{mirrorCosigner.Verifier().String()},
		"software":       map[string]string{"name": "sunlight", "version": "test"},
	}, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	witness2V0, err := json.MarshalIndent(map[string]any{
		"name":           "witness2.example.org",
		"submission_url": "https://witness2-submit.example.org/",
		"monitoring_url": "https://witness2.example.org/",
		"verifier_keys":  []string{witness2Cosigner.Verifier().String()},
		"software":       map[string]string{"name": "sunlight", "version": "test"},
	}, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	write("witness/witness.v0.json", append(witnessV0, '\n'))
	write("witness/mirror/mirror.v0.json", append(mirrorV0, '\n'))
	write("witness2/witness.v0.json", append(witness2V0, '\n'))

	// The witness checkpoint doubles as the pending checkpoint of the mirrored
	// log, so it must be cosigned and at least as large as the mirror tree.
	witnessCheckpoint, err := note.Sign(&note.Note{Text: torchwood.Checkpoint{
		Origin: origin,
		Tree:   tlog.Tree{N: treeSize, Hash: treeHash},
	}.String()}, signer, witnessCosigner)
	if err != nil {
		log.Fatal(err)
	}
	originHash := sha256.Sum256([]byte(origin))
	witnessed := hex.EncodeToString(originHash[:])
	write("witness/"+witnessed+"/checkpoint", witnessCheckpoint)

	// The mirror serves a real tree with real hash tiles, so /health can verify
	// the right-edge tiles against the cosigned mirror checkpoint.
	hashes := map[int64]tlog.Hash{}
	hr := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, x := range indexes {
			h, ok := hashes[x]
			if !ok {
				return nil, fmt.Errorf("missing stored hash %d", x)
			}
			out[i] = h
		}
		return out, nil
	})
	for i := range int64(treeSize) {
		stored, err := tlog.StoredHashes(i, fmt.Appendf(nil, "record %d", i), hr)
		if err != nil {
			log.Fatal(err)
		}
		base := tlog.StoredHashIndex(0, i)
		for j, h := range stored {
			hashes[base+int64(j)] = h
		}
	}
	mirrorTreeHash, err := tlog.TreeHash(treeSize, hr)
	if err != nil {
		log.Fatal(err)
	}
	for _, tile := range tlog.NewTiles(torchwood.TileHeight, 0, treeSize) {
		data, err := tlog.ReadTileData(tile, hr)
		if err != nil {
			log.Fatal(err)
		}
		write("witness/mirror/"+witnessed+"/"+torchwood.TilePath(tile), data)
	}
	mirrorCheckpoint, err := note.Sign(&note.Note{Text: torchwood.Checkpoint{
		Origin: origin,
		Tree:   tlog.Tree{N: treeSize, Hash: mirrorTreeHash},
	}.String()}, mirrorCosigner)
	if err != nil {
		log.Fatal(err)
	}
	write("witness/mirror/"+witnessed+"/checkpoint", mirrorCheckpoint)

	// Decoy files that no request path should map to: the per-origin paths of
	// unknown origins must not collapse to the directory roots.
	write("witness/checkpoint", []byte("decoy, must never be served\n"))
	write("witness/mirror/checkpoint", []byte("decoy, must never be served\n"))
	write("witness/mirror/"+witnessed+"/tile/entries/000", gzipped("fake mirrored entry bundle\n"))
	write("witness/mirror/"+witnessed+"/tile/entries/001.p/44", gzipped("fake mirrored partial entry bundle\n"))

	// A second witness, observing a different log and not operating as a
	// mirror, to exercise serving multiple witnesses from one Skylight.
	origin2Hash := sha256.Sum256([]byte(origin2))
	witnessed2 := hex.EncodeToString(origin2Hash[:])
	checkpoint2, err := note.Sign(&note.Note{Text: torchwood.Checkpoint{
		Origin: origin2,
		Tree:   tlog.Tree{N: treeSize, Hash: treeHash},
	}.String()}, witness2Cosigner)
	if err != nil {
		log.Fatal(err)
	}
	write("witness2/"+witnessed2+"/checkpoint", checkpoint2)

	fmt.Printf("origin hash: %s\n", witnessed)
	fmt.Printf("origin2 hash: %s\n", witnessed2)
	fmt.Printf("issuer hash: %s\n", hex.EncodeToString(issuerHash[:]))
}

// fixedTimeCosigner is a note.Signer producing c2sp.org/tlog-cosignature
// Ed25519 cosignatures like [torchwood.CosignatureSigner], except with a fixed
// timestamp, so the generated testdata is deterministic.
type fixedTimeCosigner struct {
	*torchwood.CosignatureSigner
	key ed25519.PrivateKey
}

func (s *fixedTimeCosigner) Sign(msg []byte) ([]byte, error) {
	const t = timestamp / 1000
	m := fmt.Sprintf("cosignature/v1\ntime %d\n%s", t, msg)
	sig := binary.BigEndian.AppendUint64(make([]byte, 0, 8+ed25519.SignatureSize), t)
	return append(sig, ed25519.Sign(s.key, []byte(m))...), nil
}

// newCosigner derives a cosigner key from a fixed seed.
func newCosigner(name, seed string) *fixedTimeCosigner {
	seedHash := sha256.Sum256([]byte(seed))
	key := ed25519.NewKeyFromSeed(seedHash[:])
	s, err := torchwood.NewCosignatureSigner(name, key)
	if err != nil {
		log.Fatal(err)
	}
	return &fixedTimeCosigner{s, key}
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
