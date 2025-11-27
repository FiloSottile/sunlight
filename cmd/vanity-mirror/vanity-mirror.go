// Command vanity-mirror downloads an RFC 6962 log as a Static CT log.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"filippo.io/sunlight"
	"filippo.io/sunlight/internal/stdlog"
	"filippo.io/torchwood"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
	"golang.org/x/sync/errgroup"
)

const batchSize = sunlight.TileWidth * 128

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s MIRROR_URL\n", os.Args[0])
		os.Exit(2)
	}

	logger := slog.New(stdlog.Handler)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	duration := prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "request_duration_seconds",
			Help:       "HTTP request latencies and count, by response code.",
			Objectives: map[float64]float64{0.5: 0.05, 0.75: 0.025, 0.9: 0.01, 0.99: 0.001},
			MaxAge:     100 * time.Second * 6,
			AgeBuckets: 6,
		},
		[]string{"code"},
	)
	dials := prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dial_total",
			Help: "Total number of dial attempts.",
		},
	)
	prometheus.MustRegister(duration, dials)
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.ListenAndServe("127.0.0.1:14242", nil)
	}()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: promhttp.InstrumentRoundTripperDuration(duration, &http.Transport{
			MaxIdleConnsPerHost: 100,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dials.Inc()
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		}),
	}

	type rfc6962STH struct {
		TreeSize          int64  `json:"tree_size"`
		Timestamp         int64  `json:"timestamp"`
		SHA256RootHash    []byte `json:"sha256_root_hash"`
		TreeHeadSignature []byte `json:"tree_head_signature"`
	}
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/ct/v1/get-sth", os.Args[1]), nil)
	if err != nil {
		fatalError(logger, "failed to create request", "err", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		fatalError(logger, "failed to fetch STH", "err", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fatalError(logger, "unexpected status code fetching STH", "code", resp.StatusCode)
	}
	var sth rfc6962STH
	if err := json.NewDecoder(resp.Body).Decode(&sth); err != nil {
		fatalError(logger, "failed to decode STH", "err", err)
	}
	logger.Info("fetched STH", "tree_size", sth.TreeSize)

	root, err := os.OpenRoot(".")
	if err != nil {
		fatalError(logger, "failed to open local directory", "err", err)
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

	fetchBatch := func(ctx context.Context, start, end int64) ([]*sunlight.LogEntry, error) {
		entries := make([]*sunlight.LogEntry, end-start)
		grp, ctx := errgroup.WithContext(ctx)
		for i := start; i < end; i += 32 {
			grp.Go(func() error {
				end := min(i+31, end-1)
				url := fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", os.Args[1], i, end)
				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					return err
				}
				req.Header.Set("User-Agent", "vanity-mirror/1.0 (+https://filippo.io/sunlight)")
				req.Header.Set("Accept", "application/json")
				var result struct {
					Entries []struct {
						LeafInput []byte `json:"leaf_input"`
						ExtraData []byte `json:"extra_data"`
					} `json:"entries"`
				}
				for {
					resp, err := client.Do(req)
					if err != nil {
						return fmt.Errorf("failed to fetch %q: %w", url, err)
					}
					if resp.StatusCode != http.StatusTooManyRequests {
						if resp.StatusCode != http.StatusOK {
							resp.Body.Close()
							return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
						}
						if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
							resp.Body.Close()
							return fmt.Errorf("failed to decode entries: %w", err)
						}
						io.CopyN(io.Discard, resp.Body, 1<<20)
						resp.Body.Close()
						break
					}
					resp.Body.Close()
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(500 * time.Millisecond):
					}
				}
				for j, e := range result.Entries {
					index := i + int64(j)
					entry, issuers, err := parseLogEntry(e.LeafInput, e.ExtraData)
					if err != nil {
						return fmt.Errorf("failed to parse entry %d: %w", index, err)
					}
					if err := observeIssuers(issuers, root); err != nil {
						return fmt.Errorf("failed to observe issuers for entry %d: %w", index, err)
					}
					entries[index-start] = entry
				}
				return nil
			})
		}
		if err := grp.Wait(); err != nil {
			return nil, err
		}
		return entries, nil
	}

	pb := progressbar.Default(sth.TreeSize)

	checkpointBytes, err := root.ReadFile("checkpoint")
	if err != nil && !os.IsNotExist(err) {
		fatalError(logger, "failed to read checkpoint file", "err", err)
	}
	var tree tlog.Tree
	if len(checkpointBytes) > 0 {
		c, err := torchwood.ParseCheckpoint(string(checkpointBytes))
		if err != nil {
			fatalError(logger, "failed to parse checkpoint", "err", err)
		}
		tree = c.Tree

		if tree.N > sth.TreeSize || tree.N != sth.TreeSize && tree.N%batchSize != 0 {
			fatalError(logger, "invalid progress value", "value", tree.N)
		}
	}
	pb.Set64(tree.N)

	for n := tree.N; n < sth.TreeSize; n += batchSize {
		end := min(n+batchSize, sth.TreeSize)
		entries, err := fetchBatch(ctx, n, end)
		backoffs := []time.Duration{
			1 * time.Second,
			5 * time.Second,
			10 * time.Second,
			30 * time.Second,
			1 * time.Minute,
			2 * time.Minute,
			3 * time.Minute,
			5 * time.Minute,
			7 * time.Minute,
			10 * time.Minute,
		}
		for i := 0; err != nil && i < len(backoffs); i++ {
			logger.Warn("failed to fetch batch, retrying",
				"err", err, "attempt", i+1, "backoff", backoffs[i])
			select {
			case <-ctx.Done():
				fatalError(logger, "interrupted during retry", "err", ctx.Err())
			case <-time.After(backoffs[i]):
			}
			entries, err = fetchBatch(ctx, n, end)
		}
		if err != nil {
			fatalError(logger, "failed to fetch batch after retries", "err", err)
		}
		hashes := make([]tlog.Hash, len(entries))
		for i := range entries {
			hashes[i] = tlog.RecordHash(entries[i].MerkleTreeLeaf())
		}

		newTree, tiles, data, err := NewTiles(ctx, tr, tree, hashes)
		if err != nil {
			fatalError(logger, "failed to build tiles", "err", err)
		}
		for i := range tiles {
			path := sunlight.TilePath(tiles[i])
			if err := root.MkdirAll(filepath.Dir(path), 0755); err != nil {
				fatalError(logger, "failed to create tile directory", "err", err, "path", path)
			}
			if err := root.WriteFile(path, data[i], 0644); err != nil {
				fatalError(logger, "failed to write tile", "err", err, "path", path)
			}
		}
		if len(entries) != int(newTree.N-tree.N) {
			fatalError(logger, "internal error: entry count mismatch",
				"have", len(entries), "want", newTree.N-tree.N)
		}

		for nn := n; nn < newTree.N; nn += sunlight.TileWidth {
			if nn%sunlight.TileWidth != 0 {
				fatalError(logger, "internal error: unaligned tile start", "n", nn)
			}
			w := min(sunlight.TileWidth, int(newTree.N-nn))
			tile := tlog.Tile{
				H: sunlight.TileHeight,
				L: -1,
				N: nn / sunlight.TileWidth,
				W: w,
			}
			var tileData []byte
			for _, e := range entries[:w] {
				tileData = sunlight.AppendTileLeaf(tileData, e)
			}
			entries = entries[w:]
			path := sunlight.TilePath(tile)
			if err := root.MkdirAll(filepath.Dir(path), 0755); err != nil {
				fatalError(logger, "failed to create tile directory", "err", err, "path", path)
			}
			if err := root.WriteFile(path, tileData, 0644); err != nil {
				fatalError(logger, "failed to write tile", "err", err, "path", path)
			}
		}
		if len(entries) != 0 {
			fatalError(logger, "internal error: leftover entries", "count", len(entries))
		}

		tree = newTree
		checkpoint := torchwood.Checkpoint{
			Origin: origin,
			Tree:   tree,
		}
		if err := root.WriteFile("checkpoint", []byte(checkpoint.String()), 0644); err != nil {
			fatalError(logger, "failed to write checkpoint file", "err", err)
		}
		pb.Set64(tree.N)

		select {
		case <-ctx.Done():
			logger.Info("interrupted, exiting")
			return
		default:
		}
	}

	if tree.N != sth.TreeSize {
		fatalError(logger, "incomplete mirror", "have", tree.N, "want", sth.TreeSize)
	}
	if !bytes.Equal(tree.Hash[:], sth.SHA256RootHash) {
		fatalError(logger, "STH hash mismatch", "have", fmt.Sprintf("%x", tree.Hash),
			"want", fmt.Sprintf("%x", sth.SHA256RootHash))
	}

	signer, err := sunlight.NewRFC6962InjectedSigner(origin, key, sth.TreeHeadSignature, sth.Timestamp)
	if err != nil {
		fatalError(logger, "failed to construct signer", "err", err)
	}
	signedNote, err := note.Sign(&note.Note{
		Text: torchwood.Checkpoint{Origin: origin, Tree: tree}.String(),
	}, signer)
	if err != nil {
		fatalError(logger, "failed to sign checkpoint", "err", err)
	}
	if err := root.WriteFile("checkpoint", []byte(signedNote), 0644); err != nil {
		fatalError(logger, "failed to write checkpoint file", "err", err)
	}

	logger.Info("mirror complete", "size", tree.N, "hash", fmt.Sprintf("%x", tree.Hash))
}

var (
	issuersMu   sync.Mutex
	issuersSeen = make(map[[32]byte]bool)
)

func observeIssuers(newIssuers [][]byte, root *os.Root) error {
	issuersMu.Lock()
	defer issuersMu.Unlock()
	for _, cert := range newIssuers {
		fp := sha256.Sum256(cert)
		if issuersSeen[fp] {
			continue
		}
		issuersSeen[fp] = true

		name := fmt.Sprintf("issuer/%x", fp)
		if _, err := root.Stat(name); err == nil {
			continue
		}
		if err := root.MkdirAll("issuer", 0755); err != nil {
			return err
		}
		if err := root.WriteFile(name, cert, 0644); err != nil {
			return err
		}
	}
	return nil
}

func parseLogEntry(leaf, extra []byte) (entry *sunlight.LogEntry, issuers [][]byte, err error) {
	l := cryptobyte.String(leaf)
	var version, leafType uint8
	var timestamp uint64
	var entryType uint16
	if !l.ReadUint8(&version) || version != 0 ||
		!l.ReadUint8(&leafType) || leafType != 0 ||
		!l.ReadUint64(&timestamp) || timestamp > math.MaxInt64 ||
		!l.ReadUint16(&entryType) {
		return nil, nil, fmt.Errorf("invalid leaf")
	}
	var certificate []byte
	var issuerKeyHash [32]byte
	switch entryType {
	case 1: // precert_entry
		if !l.CopyBytes(issuerKeyHash[:]) {
			return nil, nil, fmt.Errorf("invalid precert_entry")
		}
		fallthrough
	case 0: // x509_entry
		if !l.ReadUint24LengthPrefixed((*cryptobyte.String)(&certificate)) {
			return nil, nil, fmt.Errorf("invalid x509_entry")
		}
	default:
		return nil, nil, fmt.Errorf("invalid entry type: %d", entryType)
	}
	var extensions cryptobyte.String
	if !l.ReadUint16LengthPrefixed(&extensions) || !extensions.Empty() {
		return nil, nil, fmt.Errorf("invalid leaf extensions")
	}
	if !l.Empty() {
		return nil, nil, fmt.Errorf("trailing data in leaf: %x", l)
	}

	e := cryptobyte.String(extra)
	var preCertificate []byte
	var chainFingerprints [][32]byte
	switch entryType {
	case 1: // precert_entry
		if !e.ReadUint24LengthPrefixed((*cryptobyte.String)(&preCertificate)) {
			return nil, nil, fmt.Errorf("invalid precert_entry extra data")
		}
		fallthrough
	case 0: // x509_entry
		var chain cryptobyte.String
		if !e.ReadUint24LengthPrefixed(&chain) || !e.Empty() {
			return nil, nil, fmt.Errorf("invalid x509_entry extra data")
		}
		for !chain.Empty() {
			var cert []byte
			if !chain.ReadUint24LengthPrefixed((*cryptobyte.String)(&cert)) {
				return nil, nil, fmt.Errorf("invalid certificate chain")
			}
			issuers = append(issuers, cert)
			chainFingerprints = append(chainFingerprints, sha256.Sum256(cert))
		}
	default:
		return nil, nil, fmt.Errorf("invalid entry type: %d", entryType)
	}

	entry = &sunlight.LogEntry{
		Certificate:         certificate,
		IsPrecert:           entryType == 1,
		IssuerKeyHash:       issuerKeyHash,
		ChainFingerprints:   chainFingerprints,
		PreCertificate:      preCertificate,
		Timestamp:           int64(timestamp),
		RFC6962ArchivalLeaf: true,
	}
	if !bytes.Equal(entry.MerkleTreeLeaf(), leaf) {
		return nil, nil, fmt.Errorf("internal error: leaf contents mismatch")
	}
	return entry, issuers, nil
}

func fatalError(logger *slog.Logger, msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
