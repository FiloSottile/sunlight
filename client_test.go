package sunlight

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"filippo.io/torchwood"
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
