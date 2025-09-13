package main

import (
	"context"
	"io/fs"

	"filippo.io/sunlight"
	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

// TODO: consider moving this to torchwood.

func NewTiles(ctx context.Context, tr torchwood.TileReaderWithContext, old tlog.Tree,
	entries []tlog.Hash) (new tlog.Tree, tiles []tlog.Tile, data [][]byte, err error) {
	hashReader := torchwood.TileHashReaderWithContext(ctx, old, tr)
	hashReader = &hashReaderOverlay{
		HashReader: hashReader,
		overlays:   make(map[int64]tlog.Hash),
	}

	for i, h := range entries {
		n := old.N + int64(i)
		newHashes, err := tlog.StoredHashesForRecordHash(n, h, hashReader)
		if err != nil {
			return tlog.Tree{}, nil, nil, err
		}
		baseIdx := tlog.StoredHashIndex(0, n)
		for j, nh := range newHashes {
			idx := baseIdx + int64(j)
			hashReader.(*hashReaderOverlay).overlays[idx] = nh
		}
	}

	n := old.N + int64(len(entries))
	tiles = tlog.NewTiles(torchwood.TileHeight, old.N, n)
	data = make([][]byte, len(tiles))
	for i, tile := range tiles {
		d, err := tlog.ReadTileData(tile, hashReader)
		if err != nil {
			return tlog.Tree{}, nil, nil, err
		}
		data[i] = d
	}

	h, err := tlog.TreeHash(n, hashReader)
	if err != nil {
		return tlog.Tree{}, nil, nil, err
	}
	return tlog.Tree{N: n, Hash: h}, tiles, data, nil
}

type hashReaderOverlay struct {
	tlog.HashReader
	overlays map[int64]tlog.Hash
}

var _ tlog.HashReader = (*hashReaderOverlay)(nil)

func (h *hashReaderOverlay) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	results := make([]tlog.Hash, len(indexes))
	remaining := make([]int64, 0, len(indexes))
	for i, idx := range indexes {
		if v, ok := h.overlays[idx]; ok {
			results[i] = v
		} else {
			remaining = append(remaining, idx)
		}
	}
	if len(remaining) == 0 {
		return results, nil
	}
	fetched, err := h.HashReader.ReadHashes(remaining)
	if err != nil {
		return nil, err
	}
	j := 0
	for i, idx := range indexes {
		if _, ok := h.overlays[idx]; !ok {
			results[i] = fetched[j]
			j++
		}
	}
	return results, nil
}

type localTileReader struct{ fs.FS }

func (l localTileReader) ReadTiles(ctx context.Context, tiles []tlog.Tile) (data [][]byte, err error) {
	data = make([][]byte, len(tiles))
	for i, tile := range tiles {
		d, err := fs.ReadFile(l.FS, sunlight.TilePath(tile))
		if err != nil {
			return nil, err
		}
		data[i] = d
	}
	return data, nil
}

func (l localTileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {}
