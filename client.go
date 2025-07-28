package sunlight

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"filippo.io/torchwood"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Client is a Certificate Transparency log client that fetches and
// authenticates tiles according to c2sp.org/static-ct-api, and exposes log
// entries as a Go iterator.
type Client struct {
	c   *torchwood.Client
	f   *torchwood.TileFetcher
	k   crypto.PublicKey
	err error
}

// ClientConfig is the configuration for a [Client].
type ClientConfig struct {
	// MonitoringPrefix is the c2sp.org/static-ct-api monitoring prefix.
	MonitoringPrefix string

	// PublicKey is the public key of the log, used to verify checkpoints in
	// [Client.Checkpoint] and SCTs in [Client.CheckInclusion].
	PublicKey crypto.PublicKey

	// HTTPClient is the HTTP client used to fetch tiles. If nil, a client is
	// created with default timeouts and settings.
	//
	// Note that Client may need to make multiple parallel requests to
	// the same host, more than the default MaxIdleConnsPerHost.
	HTTPClient *http.Client

	// UserAgent is the User-Agent string used for HTTP requests. It must be
	// set, and it must include an email address and/or an HTTPS URL.
	UserAgent string

	// Timeout is how long the Entries iterator can take to yield an entry.
	// This includes any Retry-After waits. If zero, it defaults to five minutes.
	Timeout time.Duration

	// ConcurrencyLimit is the maximum number of concurrent requests
	// made by the Client. If zero, there is no limit.
	ConcurrencyLimit int

	// Cache, if set, is a directory where the client will cache verified
	// non-partial tiles, following the same structure as the URLs.
	Cache string

	// Logger is the logger used to log errors and progress.
	// If nil, log lines are discarded.
	Logger *slog.Logger
}

// NewClient creates a new [Client].
func NewClient(config *ClientConfig) (*Client, error) {
	if config == nil || config.UserAgent == "" {
		return nil, errors.New("sunlight: missing UserAgent")
	}
	if !strings.Contains(config.UserAgent, "@") &&
		!strings.Contains(config.UserAgent, "+https://") {
		return nil, errors.New("sunlight: UserAgent must include an email address or HTTPS URL (+https://example.com)")
	}
	fetcher, err := torchwood.NewTileFetcher(config.MonitoringPrefix,
		torchwood.WithTilePath(TilePath),
		torchwood.WithHTTPClient(config.HTTPClient),
		torchwood.WithUserAgent(config.UserAgent),
		torchwood.WithConcurrencyLimit(config.ConcurrencyLimit),
		torchwood.WithTileFetcherLogger(config.Logger))
	if err != nil {
		return nil, err
	}
	var tileReader torchwood.TileReaderWithContext = fetcher
	if config.Cache != "" {
		tileReader, err = torchwood.NewPermanentCache(tileReader, config.Cache,
			torchwood.WithPermanentCacheLogger(config.Logger),
			torchwood.WithPermanentCacheTilePath(TilePath))
		if err != nil {
			return nil, err
		}
	}
	client, err := torchwood.NewClient(fetcher, torchwood.WithCutEntry(cutEntry),
		torchwood.WithTimeout(config.Timeout))
	if err != nil {
		return nil, err
	}
	return &Client{c: client, f: fetcher, k: config.PublicKey}, nil
}

// Fetcher returns the underlying [torchwood.TileFetcher], which can be used to
// fetch endpoints directly, or as a [tlog.HashReader] via
// [torchwood.TileHashReaderWithContext].
//
// It does not use [ClientConfig.Cache]. If needed, use [torchwood.NewPermanentCache].
func (c *Client) Fetcher() *torchwood.TileFetcher {
	return c.f
}

func cutEntry(tile []byte) (entry []byte, rh tlog.Hash, rest []byte, err error) {
	// This implementation is terribly inefficient, parsing the whole entry just
	// to re-serialize and throw it away. If this function shows up in profiles,
	// let me know and I'll improve it.
	e, rest, err := ReadTileLeaf(tile)
	if err != nil {
		return nil, tlog.Hash{}, nil, err
	}
	rh = tlog.RecordHash(e.MerkleTreeLeaf())
	entry = tile[:len(tile)-len(rest)]
	return entry, rh, rest, nil
}

// Err returns the error encountered by the latest [Client.Entries] call.
func (c *Client) Err() error {
	if c.err != nil {
		return c.err
	}
	if err := c.c.Err(); err != nil {
		return err
	}
	return nil
}

// Entries returns an iterator that yields entries from the given tree, starting
// at the given index. The first item in the yielded pair is the overall entry
// index in the log, starting at start.
//
// The provided tree should have been verified by the caller, for example using
// [Client.Checkpoint].
//
// Iteration may stop before the size of the tree to avoid fetching a partial
// data tile. Resuming with the same tree will yield the remaining entries,
// however clients tailing a growing log are encouraged to fetch the next
// checkpoint and use that as the tree argument.
//
// Callers must check [Client.Err] after the iteration breaks.
func (c *Client) Entries(ctx context.Context, tree tlog.Tree, start int64) iter.Seq2[int64, *LogEntry] {
	c.err = nil
	return func(yield func(int64, *LogEntry) bool) {
		for i, e := range c.c.Entries(ctx, tree, start) {
			entry, rest, err := ReadTileLeaf(e)
			if err != nil {
				c.err = err
				return
			}
			if len(rest) > 0 {
				c.err = errors.New("internal error: unexpected trailing data in entry")
				return
			}
			if !yield(i, entry) {
				return
			}
		}
	}
}

// CheckInclusion fetches the log entry for the given SCT, and verifies that it
// is included in the given tree and that the SCT is valid for the entry.
func (c *Client) CheckInclusion(ctx context.Context, tree tlog.Tree, sct []byte) (*LogEntry, tlog.RecordProof, error) {
	var s ct.SignedCertificateTimestamp
	if _, err := tls.Unmarshal(sct, &s); err != nil {
		return nil, nil, fmt.Errorf("sunlight: failed to unmarshal SCT: %w", err)
	}
	if s.SCTVersion != ct.V1 {
		return nil, nil, fmt.Errorf("sunlight: unsupported SCT version %d", s.SCTVersion)
	}
	spki, err := x509.MarshalPKIXPublicKey(c.k)
	if err != nil {
		return nil, nil, fmt.Errorf("sunlight: failed to marshal public key: %w", err)
	}
	if logID := sha256.Sum256(spki); s.LogID.KeyID != logID {
		return nil, nil, fmt.Errorf("sunlight: SCT log ID %x does not match public key %x", s.LogID.KeyID, logID)
	}
	ext, err := ParseExtensions(s.Extensions)
	if err != nil {
		return nil, nil, fmt.Errorf("sunlight: failed to parse SCT extensions: %w", err)
	}
	e, proof, err := c.c.Entry(ctx, tree, ext.LeafIndex)
	if err != nil {
		return nil, nil, fmt.Errorf("sunlight: failed to fetch log entry %d: %w", ext.LeafIndex, err)
	}
	entry, rest, err := ReadTileLeaf(e)
	if err != nil {
		return nil, nil, fmt.Errorf("sunlight: failed to parse log entry %d: %w", ext.LeafIndex, err)
	}
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("sunlight: unexpected trailing data in entry	%d", ext.LeafIndex)
	}
	if entry.LeafIndex != ext.LeafIndex {
		return nil, nil, fmt.Errorf("sunlight: SCT leaf index %d does not match entry leaf index %d", ext.LeafIndex, entry.LeafIndex)
	}
	if entry.Timestamp != int64(s.Timestamp) {
		return nil, nil, fmt.Errorf("sunlight: SCT timestamp %d does not match entry timestamp %d", s.Timestamp, entry.Timestamp)
	}
	if err := tls.VerifySignature(c.k, entry.MerkleTreeLeaf(), tls.DigitallySigned(s.Signature)); err != nil {
		return nil, nil, fmt.Errorf("sunlight: SCT signature verification failed: %w", err)
	}
	return entry, proof, nil
}

// Checkpoint fetches the latest checkpoint and verifies it.
func (c *Client) Checkpoint(ctx context.Context) (torchwood.Checkpoint, *note.Note, error) {
	signedNote, err := c.f.ReadEndpoint(ctx, "checkpoint")
	if err != nil {
		return torchwood.Checkpoint{}, nil, fmt.Errorf("sunlight: failed to fetch checkpoint: %w", err)
	}

	// In Certificate Transparency, a log is identified only by its public key,
	// so we can pull the name from the checkpoint. This will be a problem if CT
	// integrates in the witness ecosystem, which instead tracks logs by their
	// origin line. We'll need witness-aware clients to enforce the origin line.
	name, _, _ := strings.Cut(string(signedNote), "\n")

	verifier, err := NewRFC6962Verifier(name, c.k)
	if err != nil {
		return torchwood.Checkpoint{}, nil, fmt.Errorf("sunlight: failed to create verifier for checkpoint: %w", err)
	}
	n, err := note.Open(signedNote, note.VerifierList(verifier))
	if err != nil {
		return torchwood.Checkpoint{}, nil, fmt.Errorf("sunlight: failed to verify checkpoint note: %w", err)
	}

	checkpoint, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return torchwood.Checkpoint{}, nil, fmt.Errorf("sunlight: failed to parse checkpoint: %w", err)
	}
	if checkpoint.Origin != name {
		return torchwood.Checkpoint{}, nil, fmt.Errorf("sunlight: checkpoint origin %q does not match log name %q", checkpoint.Origin, name)
	}

	return checkpoint, n, nil
}

// Issuer returns the issuer matching the fingerprint from
// [LogEntry.ChainFingerprints].
func (c *Client) Issuer(ctx context.Context, fp [32]byte) (*x509.Certificate, error) {
	endpoint := fmt.Sprintf("issuer/%x", fp)
	cert, err := c.f.ReadEndpoint(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("sunlight: failed to fetch issuer certificate for %x: %w", fp, err)
	}
	if gotFP := sha256.Sum256(cert); gotFP != fp {
		return nil, fmt.Errorf("sunlight: log returned wrong issuer %x instead of %x", gotFP, fp)
	}
	return x509.ParseCertificate(cert)
}
