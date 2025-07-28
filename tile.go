package sunlight

import (
	"fmt"
	"math"
	"strings"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/tlog"
)

const TileHeight = 8
const TileWidth = 1 << TileHeight

// TilePath returns a tile coordinate path describing t, according to
// c2sp.org/static-st-api. It differs from [tlog.Tile.Path] in that it doesn't
// include an explicit tile height. It also supports names tiles at level -2.
//
// If t.Height is not TileHeight, TilePath panics.
func TilePath(t tlog.Tile) string {
	if t.H != TileHeight {
		panic(fmt.Sprintf("unexpected tile height %d", t.H))
	}
	if t.L == -2 {
		t.L = -1
		return "tile/names/" + strings.TrimPrefix(t.Path(), "tile/8/data/")
	}
	return "tile/" + strings.TrimPrefix(t.Path(), "tile/8/")
}

// ParseTilePath parses a tile coordinate path according to c2sp.org/static-st-api.
// It differs from [tlog.ParseTilePath] in that it doesn't include an explicit
// tile height. It also supports names tiles at level -2.
func ParseTilePath(path string) (tlog.Tile, error) {
	if rest, ok := strings.CutPrefix(path, "tile/names/"); ok {
		t, err := tlog.ParseTilePath("tile/8/data/" + rest)
		if err != nil {
			return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
		}
		t.L = -2
		return t, nil
	}
	if rest, ok := strings.CutPrefix(path, "tile/"); ok {
		t, err := tlog.ParseTilePath("tile/8/" + rest)
		if err != nil {
			return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
		}
		return t, nil
	}
	return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
}

type LogEntry struct {
	// Certificate is either the TimestampedEntry.signed_entry, or the
	// PreCert.tbs_certificate for Precertificates.
	// It must be at most 2^24-1 bytes long.
	Certificate []byte

	// IsPrecert is true if LogEntryType is precert_entry. Otherwise, the
	// following three fields are zero and ignored.
	IsPrecert bool

	// IssuerKeyHash is the PreCert.issuer_key_hash.
	IssuerKeyHash [32]byte

	// ChainFingerprints are the SHA-256 hashes of the certificates in the
	// X509ChainEntry.certificate_chain or
	// PrecertChainEntry.precertificate_chain.
	ChainFingerprints [][32]byte

	// PreCertificate is the PrecertChainEntry.pre_certificate.
	// It must be at most 2^24-1 bytes long.
	PreCertificate []byte

	// LeafIndex is the zero-based index of the leaf in the log.
	// It must be between 0 and 2^40-1.
	LeafIndex int64

	// Timestamp is the TimestampedEntry.timestamp.
	Timestamp int64
}

// MerkleTreeLeaf returns a RFC 6962 MerkleTreeLeaf.
//
// This is the Merkle tree leaf that can be passed, for example, to
// [tlog.RecordHash] for use with [tlog.CheckRecord].
//
// It also matches the digitally-signed data of an SCT, which is technically not
// a MerkleTreeLeaf, but a completely identical structure (except for the second
// field, which is a SignatureType of value 0 and length 1 instead of a
// MerkleLeafType of value 0 and length 1).
func (e *LogEntry) MerkleTreeLeaf() []byte {
	b := &cryptobyte.Builder{}
	b.AddUint8(0 /* version = v1 */)
	b.AddUint8(0 /* leaf_type = timestamped_entry */)
	b.AddUint64(uint64(e.Timestamp))
	if !e.IsPrecert {
		b.AddUint16(0 /* entry_type = x509_entry */)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.Certificate)
		})
	} else {
		b.AddUint16(1 /* entry_type = precert_entry */)
		b.AddBytes(e.IssuerKeyHash[:])
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.Certificate)
		})
	}
	addExtensions(b, e.LeafIndex)
	return b.BytesOrPanic()
}

// struct {
//     TimestampedEntry timestamped_entry;
//     select (entry_type) {
//         case x509_entry: Empty;
//         case precert_entry: ASN.1Cert pre_certificate;
//     };
//     Fingerprint certificate_chain<0..2^16-1>;
// } TileLeaf;
//
// opaque Fingerprint[32];

// ReadTileLeaf reads a LogEntry from a data tile, and returns the remaining
// data in the tile.
func ReadTileLeaf(tile []byte) (e *LogEntry, rest []byte, err error) {
	e = &LogEntry{}
	s := cryptobyte.String(tile)
	var timestamp uint64
	var entryType uint16
	var extensions, fingerprints cryptobyte.String
	if !s.ReadUint64(&timestamp) || !s.ReadUint16(&entryType) || timestamp > math.MaxInt64 {
		return nil, s, fmt.Errorf("invalid data tile")
	}
	e.Timestamp = int64(timestamp)
	switch entryType {
	case 0: // x509_entry
		if !s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.Certificate)) ||
			!s.ReadUint16LengthPrefixed(&extensions) ||
			!s.ReadUint16LengthPrefixed(&fingerprints) {
			return nil, s, fmt.Errorf("invalid data tile x509_entry")
		}
	case 1: // precert_entry
		e.IsPrecert = true
		if !s.CopyBytes(e.IssuerKeyHash[:]) ||
			!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.Certificate)) ||
			!s.ReadUint16LengthPrefixed(&extensions) ||
			!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.PreCertificate)) ||
			!s.ReadUint16LengthPrefixed(&fingerprints) {
			return nil, s, fmt.Errorf("invalid data tile precert_entry")
		}
	default:
		return nil, s, fmt.Errorf("invalid data tile: unknown type %d", entryType)
	}
	var extensionType uint8
	var extensionData cryptobyte.String
	if !extensions.ReadUint8(&extensionType) || extensionType != 0 ||
		!extensions.ReadUint16LengthPrefixed(&extensionData) ||
		!readUint40(&extensionData, &e.LeafIndex) || !extensionData.Empty() ||
		!extensions.Empty() {
		return nil, s, fmt.Errorf("invalid data tile extensions")
	}
	for !fingerprints.Empty() {
		var f [32]byte
		if !fingerprints.CopyBytes(f[:]) {
			return nil, s, fmt.Errorf("invalid data tile fingerprints")
		}
		e.ChainFingerprints = append(e.ChainFingerprints, f)
	}
	return e, s, nil
}

// AppendTileLeaf appends a LogEntry to a data tile.
func AppendTileLeaf(t []byte, e *LogEntry) []byte {
	b := cryptobyte.NewBuilder(t)
	b.AddUint64(uint64(e.Timestamp))
	if !e.IsPrecert {
		b.AddUint16(0 /* entry_type = x509_entry */)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.Certificate)
		})
	} else {
		b.AddUint16(1 /* entry_type = precert_entry */)
		b.AddBytes(e.IssuerKeyHash[:])
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.Certificate)
		})
	}
	addExtensions(b, e.LeafIndex)
	if e.IsPrecert {
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(e.PreCertificate)
		})
	}
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, f := range e.ChainFingerprints {
			b.AddBytes(f[:])
		}
	})
	return b.BytesOrPanic()
}

func addExtensions(b *cryptobyte.Builder, leafIndex int64) {
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		ext, err := MarshalExtensions(Extensions{LeafIndex: leafIndex})
		if err != nil {
			b.SetError(err)
			return
		}
		b.AddBytes(ext)
	})
}

// A TrimmedEntry is a subset of the information in a [LogEntry], including
// names parsed from the certificate or pre-certificate.
type TrimmedEntry struct {
	// Index is the zero-based index of the leaf in the log.
	Index int64

	// Timestamp is the UNIX timestamp in milliseconds of when the entry was
	// added to the log.
	Timestamp int64

	// Subject is a DER encoded RDNSequence.
	//
	// It is omitted if it includes only a CommonName that matches one of the
	// DNS or IP entries. That is the case for all Domain Validated WebPKI
	// certificates.
	Subject []byte `json:",omitempty"`

	// DNS and IP are the Subject Alternative Names of the certificate.
	DNS []string `json:",omitempty"`
	IP  []string `json:",omitempty"`
}

func (e *LogEntry) TrimmedEntry() (*TrimmedEntry, error) {
	t := &TrimmedEntry{
		Index:     e.LeafIndex,
		Timestamp: e.Timestamp,
	}
	certBytes := e.Certificate
	if e.IsPrecert {
		certBytes = e.PreCertificate
	}
	cert, err := x509.ParseCertificate(certBytes)
	if cert == nil { // x509.ParseCertificate can return non-fatal errors
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	for _, name := range cert.Subject.Names {
		if !name.Type.Equal(pkix.OIDCommonName) {
			t.Subject = cert.RawSubject
			break
		}
	}
	t.DNS = cert.DNSNames
	t.IP = make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		t.IP[i] = ip.String()
	}
	return t, nil
}
