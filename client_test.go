package sunlight

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/tlog"
)

type testTileReader struct {
	t                         *testing.T
	noDataTiles, noNamesTiles bool
}

var _ torchwood.TileReader = &testTileReader{}

func (tr *testTileReader) ReadTiles(ctx context.Context, tiles []tlog.Tile) (data [][]byte, err error) {
	for _, t := range tiles {
		if t.L == -1 && tr.noDataTiles {
			return nil, fmt.Errorf("refusing to read tile %s due to noDataTiles setting", TilePath(t))
		}
		if t.L == -2 && tr.noNamesTiles {
			return nil, fmt.Errorf("refusing to read tile %s due to noNamesTiles setting", TilePath(t))
		}
		path := TilePath(t)
		path = filepath.Join("testdata", "navigli2025h2", path)
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read tile %s: %w", path, err)
		}
		data = append(data, b)
	}
	return data, nil
}

func (tr *testTileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {}

func (tr *testTileReader) ReadEndpoint(ctx context.Context, endpoint string) ([]byte, error) {
	return nil, fmt.Errorf("testTileReader: ReadEndpoint not implemented")
}

func NewTestClient(t *testing.T, config *ClientConfig) (*Client, *testTileReader) {
	tileReader := &testTileReader{t: t}
	client, err := torchwood.NewClient(tileReader, torchwood.WithCutEntry(cutEntry))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return &Client{c: client, r: tileReader, cc: config}, tileReader
}

const partialCount = 256*3 + 10
const allCount = 256 * 4

func TestUnauthenticatedTrimmedEntries(t *testing.T) {
	t.Run("names", func(t *testing.T) {
		t.Parallel()
		client, tr := NewTestClient(t, &ClientConfig{})
		tr.noNamesTiles = true
		testUnauthenticatedTrimmedEntries(t, client)
	})
	t.Run("data", func(t *testing.T) {
		t.Parallel()
		client, tr := NewTestClient(t, &ClientConfig{})
		tr.noDataTiles = true
		testUnauthenticatedTrimmedEntries(t, client)
	})
}

func testUnauthenticatedTrimmedEntries(t *testing.T, client *Client) {
	var allEntries []*TrimmedEntry
	var index int64
	for i, e := range client.UnauthenticatedTrimmedEntries(t.Context(), 0, allCount) {
		if i != index {
			t.Errorf("expected entry index %d, got %d", index, i)
		}
		allEntries = append(allEntries, e)
		index++
	}
	if err := client.Err(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(allEntries) != allCount {
		t.Fatalf("expected %d entries, got %d", allCount, len(allEntries))
	}

	compareRange := func(t *testing.T, start, end int64) {
		var gotEntries []*TrimmedEntry
		index := start
		for i, e := range client.UnauthenticatedTrimmedEntries(t.Context(), start, end) {
			if i != index {
				t.Errorf("expected entry index %d, got %d", index, i)
			}
			gotEntries = append(gotEntries, e)
			index++
		}
		if err := client.Err(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(gotEntries) != int(end-start) {
			t.Fatalf("expected %d entries, got %d", end-start, len(gotEntries))
		}
		if !reflect.DeepEqual(allEntries[start:end], gotEntries) {
			t.Errorf("entries from %d to %d do not match expected entries", start, end)
		}
	}
	if testing.Short() {
		for _, n := range []int64{0, 1, 255, 256, 257, partialCount - 1} {
			t.Run(fmt.Sprintf("%d:%d", n, allCount), func(t *testing.T) {
				compareRange(t, n, allCount)
			})
			t.Run(fmt.Sprintf("%d:%d", n, partialCount), func(t *testing.T) {
				compareRange(t, n, partialCount)
			})
		}
		for _, n := range []int64{partialCount, partialCount + 1, allCount - 1} {
			t.Run(fmt.Sprintf("%d:%d", n, allCount), func(t *testing.T) {
				compareRange(t, n, allCount)
			})
		}
		return
	}
	for n := range allCount {
		t.Run(fmt.Sprintf("%d:%d", n, allCount), func(t *testing.T) {
			compareRange(t, int64(n), allCount)
		})
	}
	for n := range partialCount {
		t.Run(fmt.Sprintf("%d:%d", n, partialCount), func(t *testing.T) {
			compareRange(t, int64(n), partialCount)
		})
	}
}

// A mapTileReader serves tiles from memory, by their path.
type mapTileReader map[string][]byte

func (m mapTileReader) ReadTiles(ctx context.Context, tiles []tlog.Tile) (data [][]byte, err error) {
	for _, t := range tiles {
		b, ok := m[TilePath(t)]
		if !ok {
			return nil, fmt.Errorf("tile %s not found", TilePath(t))
		}
		data = append(data, b)
	}
	return data, nil
}

func (m mapTileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {}

func (m mapTileReader) ReadEndpoint(ctx context.Context, endpoint string) ([]byte, error) {
	return nil, fmt.Errorf("mapTileReader: ReadEndpoint not implemented")
}

// TestUnauthenticatedTrimmedEntriesCount checks that a tile is only used if it
// holds the entries it is expected to, whether it is a names tile or one of
// the data tiles that are read when there are no names tiles.
func TestUnauthenticatedTrimmedEntriesCount(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	namesTile := func(lines ...string) mapTileReader {
		var tile []byte
		for _, line := range lines {
			tile = append(tile, line+"\n"...)
		}
		return mapTileReader{"tile/names/000.p/3": tile}
	}
	dataTile := func(indexes ...int64) mapTileReader {
		var tile []byte
		for _, i := range indexes {
			tile = AppendTileLeaf(tile, &LogEntry{Certificate: certificate, LeafIndex: i, Timestamp: i})
		}
		return mapTileReader{"tile/data/000.p/3": tile}
	}
	for _, tt := range []struct {
		name  string
		tiles mapTileReader
		// yielded is the number of entries yielded before the error, if any.
		// A names tile is checked before any entry is yielded, a data tile as
		// it is read.
		yielded int
		ok      bool
	}{
		{"names tile", namesTile(`{"Timestamp":0}`, `{"Timestamp":1}`, `{"Timestamp":2}`), 3, true},
		{"empty names tile", namesTile(), 0, false},
		{"short names tile", namesTile(`{"Timestamp":0}`, `{"Timestamp":1}`), 0, false},
		{"long names tile", namesTile(`{"Timestamp":0}`, `{"Timestamp":1}`, `{"Timestamp":2}`, `{"Timestamp":3}`), 0, false},
		{"names tile with a null entry", namesTile(`{"Timestamp":0}`, `null`, `{"Timestamp":2}`), 0, false},

		{"data tile", dataTile(0, 1, 2), 3, true},
		{"empty data tile", dataTile(), 0, false},
		{"short data tile", dataTile(0, 1), 2, false},
		{"long data tile", dataTile(0, 1, 2, 3), 3, false},
		{"data tile with another entry", dataTile(0, 1, 3), 2, false},
		{"data tile of other entries", dataTile(1, 2, 3), 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tc, err := torchwood.NewClient(tt.tiles, torchwood.WithCutEntry(cutEntry))
			if err != nil {
				t.Fatal(err)
			}
			client := &Client{c: tc, r: tt.tiles, cc: &ClientConfig{}}

			var next int64
			for i, e := range client.UnauthenticatedTrimmedEntries(t.Context(), 0, 3) {
				if i != next || e == nil || e.Timestamp != i {
					t.Fatalf("got entry %d (%+v), expected entry %d", i, e, next)
				}
				next++
			}
			if next != int64(tt.yielded) {
				t.Errorf("got %d entries, expected %d", next, tt.yielded)
			}
			if err := client.Err(); (err == nil) != tt.ok {
				t.Errorf("got error %v", err)
			}
		})
	}
}

// TestUnauthenticatedTrimmedEntriesFallback checks that an entry that names
// can't be extracted from is yielded with only its timestamp when reading data
// tiles, like it is in a names tile.
func TestUnauthenticatedTrimmedEntriesFallback(t *testing.T) {
	var tile []byte
	tile = AppendTileLeaf(tile, &LogEntry{Certificate: []byte("not a certificate"), LeafIndex: 0, Timestamp: 1000})
	tile = AppendTileLeaf(tile, &LogEntry{Certificate: []byte("not a certificate"), LeafIndex: 1, Timestamp: 1001})
	tiles := mapTileReader{"tile/data/000.p/2": tile}
	tc, err := torchwood.NewClient(tiles, torchwood.WithCutEntry(cutEntry))
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{c: tc, r: tiles, cc: &ClientConfig{}}

	var got []*TrimmedEntry
	for _, e := range client.UnauthenticatedTrimmedEntries(t.Context(), 0, 2) {
		got = append(got, e)
	}
	if err := client.Err(); err != nil {
		t.Fatal(err)
	}
	if want := []*TrimmedEntry{{Timestamp: 1000}, {Timestamp: 1001}}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestCheckInclusion(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	logID := sha256.Sum256(spki)

	// A log with a certificate, a precertificate, and another certificate.
	entries := []*LogEntry{
		{Certificate: []byte("certificate"), LeafIndex: 0, Timestamp: 1000},
		{Certificate: []byte("tbs"), IsPrecert: true, IssuerKeyHash: [32]byte{1},
			PreCertificate: []byte("precertificate"), LeafIndex: 1, Timestamp: 1001},
		{Certificate: []byte("other certificate"), LeafIndex: 2, Timestamp: 1002},
	}
	var dataTile, hashTile []byte
	var hashes []tlog.Hash
	for _, e := range entries {
		dataTile = AppendTileLeaf(dataTile, e)
		h := tlog.RecordHash(e.MerkleTreeLeaf())
		hashTile = append(hashTile, h[:]...)
		hashes = append(hashes, h)
	}
	tree := tlog.Tree{N: 3, Hash: tlog.NodeHash(tlog.NodeHash(hashes[0], hashes[1]), hashes[2])}
	tiles := mapTileReader{"tile/data/000.p/3": dataTile, "tile/0/000.p/3": hashTile}
	tc, err := torchwood.NewClient(tiles, torchwood.WithCutEntry(cutEntry))
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{c: tc, r: tiles, cc: &ClientConfig{PublicKey: key.Public()}}

	// sct is the fields of a SignedCertificateTimestamp.
	type sct struct {
		version         uint8
		id              [32]byte
		timestamp       int64
		leafIndex       int64
		hashAlg, sigAlg uint8
		signed          []byte
		trailing        []byte
	}
	encode := func(s sct) []byte {
		t.Helper()
		extensions, err := MarshalExtensions(Extensions{LeafIndex: s.leafIndex})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(s.signed)
		signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		var b cryptobyte.Builder
		b.AddUint8(s.version)
		b.AddBytes(s.id[:])
		b.AddUint64(uint64(s.timestamp))
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(extensions) })
		b.AddUint8(s.hashAlg)
		b.AddUint8(s.sigAlg)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(signature) })
		b.AddBytes(s.trailing)
		return b.BytesOrPanic()
	}
	valid := func(e *LogEntry) sct {
		return sct{id: logID, timestamp: e.Timestamp, leafIndex: e.LeafIndex,
			hashAlg: 4, sigAlg: 3, signed: e.MerkleTreeLeaf()}
	}

	for _, e := range entries {
		got, proof, err := client.CheckInclusion(t.Context(), tree, encode(valid(e)))
		if err != nil {
			t.Fatalf("entry %d: %v", e.LeafIndex, err)
		}
		if !reflect.DeepEqual(got, e) {
			t.Errorf("entry %d: got %+v, want %+v", e.LeafIndex, got, e)
		}
		rh := tlog.RecordHash(e.MerkleTreeLeaf())
		if err := tlog.CheckRecord(proof, tree.N, tree.Hash, e.LeafIndex, rh); err != nil {
			t.Errorf("entry %d: %v", e.LeafIndex, err)
		}
	}

	for _, tt := range []struct {
		name   string
		modify func(s *sct)
	}{
		{"version", func(s *sct) { s.version = 1 }},
		{"log ID", func(s *sct) { s.id[0] ^= 1 }},
		{"timestamp", func(s *sct) { s.timestamp++ }},
		{"leaf index", func(s *sct) { s.leafIndex = 2 }},
		{"leaf index beyond the tree", func(s *sct) { s.leafIndex = 3 }},
		{"hash algorithm", func(s *sct) { s.hashAlg = 2 }},
		{"signature algorithm", func(s *sct) { s.sigAlg = 1 }},
		{"signed data", func(s *sct) { s.signed = entries[1].MerkleTreeLeaf() }},
		{"trailing data", func(s *sct) { s.trailing = []byte{0} }},
	} {
		s := valid(entries[0])
		tt.modify(&s)
		_, _, err := client.CheckInclusion(t.Context(), tree, encode(s))
		if err == nil {
			t.Errorf("%s: SCT was accepted", tt.name)
		}
		if wrongLogID := errors.Is(err, ErrWrongLogID); wrongLogID != (tt.name == "log ID") {
			t.Errorf("%s: got %v", tt.name, err)
		}
	}
	truncated := encode(valid(entries[0]))
	for n := range len(truncated) {
		if _, _, err := client.CheckInclusion(t.Context(), tree, truncated[:n]); err == nil {
			t.Errorf("SCT truncated to %d bytes was accepted", n)
		}
	}
}
