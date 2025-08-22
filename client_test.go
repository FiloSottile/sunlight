package sunlight

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

type testTileReader struct {
	t                         *testing.T
	noDataTiles, noNamesTiles bool
}

var _ torchwood.TileReaderWithContext = &testTileReader{}

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

func NewTestClient(t *testing.T, config *ClientConfig) (*Client, *testTileReader) {
	tileReader := &testTileReader{t: t}
	client, err := torchwood.NewClient(tileReader, torchwood.WithCutEntry(cutEntry))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return &Client{c: client, f: nil, r: tileReader, cc: config}, tileReader
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
	for n := range allCount {
		t.Run(fmt.Sprintf("%d:%d", n, allCount), func(t *testing.T) {
			t.Parallel()
			compareRange(t, int64(n), allCount)
		})
	}
	for n := range partialCount {
		t.Run(fmt.Sprintf("%d:%d", n, partialCount), func(t *testing.T) {
			t.Parallel()
			compareRange(t, int64(n), partialCount)
		})
	}
}
