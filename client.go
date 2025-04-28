package sunlight

import (
	"errors"
	"iter"
	"log/slog"
	"net/http"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"
)

// Client is a Certificate Transparency log client that fetches and
// authenticates tiles according to c2sp.org/static-ct-api, and exposes log
// entries as a Go iterator.
type Client struct {
	c   *torchwood.Client
	err error
}

// ClientConfig is the configuration for a [Client]. It can be nil, or the zero
// value, in which case a default configuration is used.
type ClientConfig struct {
	// HTTPClient is the HTTP client used to fetch tiles.
	//
	// Note that Client may need to make multiple parallel requests to
	// the same host, more than the default MaxIdleConnsPerHost.
	HTTPClient *http.Client

	// ConcurrencyLimit is the maximum number of concurrent requests
	// made by the Client. If zero, there is no limit.
	ConcurrencyLimit int

	// Logger is the logger used to log errors and progress.
	// If nil, log lines are discarded.
	Logger *slog.Logger
}

// NewClient creates a new [Client] for the given monitoring prefix.
func NewClient(prefix string, config *ClientConfig) (*Client, error) {
	if config == nil {
		config = &ClientConfig{}
	}
	fetcher, err := torchwood.NewTileFetcher(prefix, torchwood.WithTilePath(TilePath),
		torchwood.WithHTTPClient(config.HTTPClient),
		torchwood.WithConcurrencyLimit(config.ConcurrencyLimit),
		torchwood.WithTileFetcherLogger(config.Logger))
	if err != nil {
		return nil, err
	}
	client, err := torchwood.NewClient(fetcher, torchwood.WithCutEntry(cutEntry))
	if err != nil {
		return nil, err
	}
	return &Client{c: client}, nil
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
// The provided tree should have been verified by the caller by verifying the
// signatures on a checkpoint with [note.Open] and [NewRFC6962Verifier], and
// then using [torchwood.ParseCheckpoint] to extract the tree.
//
// Iteration may stop before the size of the tree to avoid fetching a partial
// data tile. Resuming with the same tree will yield the remaining entries,
// however clients tailing a growing log are encouraged to fetch the next
// checkpoint and use that as the tree argument.
//
// Callers must check [Client.Err] after the iteration breaks.
func (c *Client) Entries(tree tlog.Tree, start int64) iter.Seq2[int64, *LogEntry] {
	c.err = nil
	return func(yield func(int64, *LogEntry) bool) {
		for i, e := range c.c.Entries(tree, start) {
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
