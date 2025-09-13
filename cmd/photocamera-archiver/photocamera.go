// Command photocamera-archiver creates an archive of a Static Certificate
// Transparency log, by compressing tiles into zip files, each containing a
// subtree 16,777,216 entries wide (65,536 level -1 and 0 tiles, 256 level 1
// tiles, and 1 level 2 tile). The checkpoint, JSON metadata, and level 3+ tiles
// are left uncompressed. The zip files are stored at tile/zip/<N>.zip.
// Unnecessary partial tiles at levels 3+ are also removed.
//
// After running this tool, archive the following files and directories:
//
//   - checkpoint
//   - log.v3.json
//   - tile/zip/
//   - tile/3/
//   - tile/4/ (if present)
//   - issuer/
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"

	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/stdlog"
	"filippo.io/torchwood"
	"github.com/klauspost/compress/zip"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

func main() {
	logger := slog.New(stdlog.Handler)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	root, err := os.OpenRoot(".")
	if err != nil {
		fatalError(logger, "failed to open local directory", "err", err)
	}
	if err := root.MkdirAll("tile/zip", 0o755); err != nil {
		fatalError(logger, "failed to create zip directory", "err", err)
	}
	tr := localTileReader{root.FS()}

	var logInfo struct {
		Description string `json:"description"`
		Key         []byte `json:"key"`
		URL         string `json:"url"`
	}
	logBytes, err := root.ReadFile("log.v3.json")
	if err != nil {
		fatalError(logger, "failed to read log info", "err", err)
	}
	if err := json.Unmarshal(logBytes, &logInfo); err != nil {
		fatalError(logger, "failed to parse log info", "err", err)
	}
	key, err := x509.ParsePKIXPublicKey(logInfo.Key)
	if err != nil {
		fatalError(logger, "failed to parse log public key", "err", err)
	}
	origin := strings.TrimPrefix(logInfo.URL, "https://")
	origin = strings.TrimSuffix(origin, "/")
	v, err := sunlight.NewRFC6962Verifier(origin, key)
	if err != nil {
		fatalError(logger, "failed to construct log verifier", "err", err)
	}
	checkpointBytes, err := root.ReadFile("checkpoint")
	if err != nil {
		fatalError(logger, "failed to read checkpoint", "err", err)
	}
	n, err := note.Open(checkpointBytes, note.VerifierList(v))
	if err != nil {
		fatalError(logger, "failed to verify checkpoint", "err", err)
	}
	c, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		fatalError(logger, "failed to parse checkpoint", "err", err)
	}
	logger.Info("loaded checkpoint", "tree_size", c.N, "root_hash", c.Hash)

	hr := torchwood.TileHashReaderWithContext(ctx, c.Tree, tr)

	for n := int64(0); n < c.N; n += 256 * 256 * 256 {
		i := n / (256 * 256 * 256)
		if i >= 1000 {
			fatalError(logger, "cannot archive more than 1000 zip files")
		}
		name := fmt.Sprintf("tile/zip/%03d.zip", i)
		subtree := min(256*256*256, c.N-n)
		logger.Info("processing subtree", "name", name, "start", n, "end", n+subtree)
		f, err := root.Create(name)
		if err != nil {
			fatalError(logger, "failed to create zip file", "name", name, "err", err)
		}
		w := zip.NewWriter(f)
		comment := fmt.Sprintf("%s %03d", c.Origin, i)
		if err := w.SetComment(comment); err != nil {
			fatalError(logger, "failed to set zip comment", "name", name, "err", err)
		}
		tiles := tlog.NewTiles(torchwood.TileHeight, n, n+subtree)
		pb := progressbar.Default(int64(len(tiles)), name)
		// Sort tiles in the zip files so that higher-level tiles come first.
		slices.SortStableFunc(tiles, func(a, b tlog.Tile) int {
			switch {
			case a.L < b.L:
				return 1
			case a.L > b.L:
				return -1
			default:
				return 0
			}
		})
		for _, tile := range tiles {
			if tile.L >= 3 {
				pb.Add(1)
				continue
			}
			path := sunlight.TilePath(tile)
			// Pull the hashes through TileHashReader instead of reading them
			// directly, so that their inclusion in the tree is verified.
			data, err := tlog.ReadTileData(tile, hr)
			if err != nil {
				fatalError(logger, "failed to read tile data", "tile", path, "err", err)
			}
			zf, err := w.CreateHeader(&zip.FileHeader{
				Name:   path,
				Method: zip.Store, // hashes don't compress!
			})
			if err != nil {
				fatalError(logger, "failed to create zip entry", "tile", path, "err", err)
			}
			if _, err := zf.Write(data); err != nil {
				fatalError(logger, "failed to write zip entry", "tile", path, "err", err)
			}
			pb.Add(1)
			if err := ctx.Err(); err != nil {
				fatalError(logger, "interrupted", "err", err)
			}
		}
		pb.Reset()
		pb.ChangeMax64((subtree + 255) / 256)
		// Store data tiles after the Merkle tree tiles.
		for _, tile := range tiles {
			if tile.L != 0 {
				continue
			}
			tile.L = -1
			path := sunlight.TilePath(tile)
			data, err := root.ReadFile(path)
			if err != nil {
				fatalError(logger, "failed to read tile data", "tile", path, "err", err)
			}
			if err := verifyTileData(tile, data, hr); err != nil {
				fatalError(logger, "failed to verify tile data", "tile", path, "err", err)
			}
			zf, err := w.CreateHeader(&zip.FileHeader{
				Name:   path,
				Method: zip.Deflate,
			})
			if err != nil {
				fatalError(logger, "failed to create zip entry", "tile", path, "err", err)
			}
			if _, err := zf.Write(data); err != nil {
				fatalError(logger, "failed to write zip entry", "tile", path, "err", err)
			}
			pb.Add(1)
			if err := ctx.Err(); err != nil {
				fatalError(logger, "interrupted", "err", err)
			}
		}
		if err := w.Close(); err != nil {
			fatalError(logger, "failed to finalize zip file", "name", name, "err", err)
		}
		if err := f.Close(); err != nil {
			fatalError(logger, "failed to close zip file", "name", name, "err", err)
		}
		pb.Exit()
		logger.Info("wrote zip file", "name", name)
	}

	// Delete unnecessary tiles at level 3+, and verify the rest of them.
	for L := 3; L <= 5; L++ {
		levelDir := fmt.Sprintf("tile/%d", L)
		levelMaxSize := c.N >> (sunlight.TileHeight * L)
		if levelMaxSize == 0 {
			break
		}
		if err := fs.WalkDir(root.FS(), levelDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			t, err := sunlight.ParseTilePath(strings.TrimSuffix(path, ".p"))
			if err != nil {
				return fmt.Errorf("failed to parse tile path %s: %w", path, err)
			}
			if t.L != L {
				return fmt.Errorf("unexpected tile level %d, want %d", t.L, L)
			}
			size := t.N*sunlight.TileWidth + int64(t.W)
			if t.W != sunlight.TileWidth && size < levelMaxSize {
				// Partial tile, can be deleted.
				logger.Info("removing unnecessary partial tile", "tile", path,
					"size", size, "max", levelMaxSize)
				if err := os.Remove(path); err != nil {
					return fmt.Errorf("failed to remove tile %s: %w", path, err)
				}
				return nil
			}
			data, err := root.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read tile data %s: %w", path, err)
			}
			exp, err := tlog.ReadTileData(t, hr)
			if err != nil {
				return fmt.Errorf("failed to read tile data %s: %w", path, err)
			}
			if !bytes.Equal(data, exp) {
				return fmt.Errorf("tile data mismatch for %s", path)
			}
			logger.Info("verified tile", "tile", path)
			return nil
		}); err != nil {
			fatalError(logger, "failed to walk tile directory", "level", L, "err", err)
		}
	}

	logger.Info("done")
}

func verifyTileData(tile tlog.Tile, data []byte, hr tlog.HashReader) error {
	if tile.L != -1 {
		return fmt.Errorf("not a data tile")
	}
	indexes := make([]int64, 0, tile.W)
	for i := range tile.W {
		indexes = append(indexes, tlog.StoredHashIndex(0, tile.N*256+int64(i)))
	}
	hashes, err := hr.ReadHashes(indexes)
	if err != nil {
		return fmt.Errorf("failed to read record hashes: %w", err)
	}
	for i, h := range hashes {
		var e *sunlight.LogEntry
		e, data, err = sunlight.ReadTileLeaf(data)
		if err != nil {
			return fmt.Errorf("failed to read tile leaf: %w", err)
		}
		if !e.RFC6962ArchivalLeaf && e.LeafIndex != tile.N*256+int64(i) {
			return fmt.Errorf("unexpected leaf index %d, want %d", e.LeafIndex, tile.N*256+int64(i))
		}
		if rh := tlog.RecordHash(e.MerkleTreeLeaf()); rh != h {
			return fmt.Errorf("record hash mismatch at index %d", tile.N*256+int64(i))
		}
	}
	if len(data) != 0 {
		return fmt.Errorf("trailing data")
	}
	return nil
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

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
