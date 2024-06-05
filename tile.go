package sunlight

import (
	"fmt"
	"math"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/tlog"
)

const TileHeight = 8
const TileWidth = 1 << TileHeight

// TilePath returns a tile coordinate path describing t, according to
// c2sp.org/sunlight. It differs from [tlog.Tile.Path] in that it doesn't
// include an explicit tile height.
//
// If t.Height is not TileHeight, TilePath panics.
func TilePath(t tlog.Tile) string {
	if t.H != TileHeight {
		panic(fmt.Sprintf("unexpected tile height %d", t.H))
	}
	return "tile/" + strings.TrimPrefix(t.Path(), "tile/8/")
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
//     select(entry_type) {
//         case x509_entry: Empty;
//         case precert_entry: PreCertExtraData;
//     } extra_data;
// } TileLeaf;
//
// struct {
//     ASN.1Cert pre_certificate;
//     opaque PrecertificateSigningCertificate<0..2^24-1>;
// } PreCertExtraData;

// ReadTileLeaf reads a LogEntry from a data tile, and returns the remaining
// data in the tile.
func ReadTileLeaf(tile []byte) (e *LogEntry, rest []byte, err error) {
	e = &LogEntry{}
	s := cryptobyte.String(tile)
	var timestamp uint64
	var entryType uint16
	var extensions cryptobyte.String
	if !s.ReadUint64(&timestamp) || !s.ReadUint16(&entryType) || timestamp > math.MaxInt64 {
		return nil, s, fmt.Errorf("invalid data tile")
	}
	e.Timestamp = int64(timestamp)
	switch entryType {
	case 0: // x509_entry
		if !s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.Certificate)) ||
			!s.ReadUint16LengthPrefixed(&extensions) {
			return nil, s, fmt.Errorf("invalid data tile x509_entry")
		}
	case 1: // precert_entry
		e.IsPrecert = true
		if !s.CopyBytes(e.IssuerKeyHash[:]) ||
			!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.Certificate)) ||
			!s.ReadUint16LengthPrefixed(&extensions) ||
			!s.ReadUint24LengthPrefixed((*cryptobyte.String)(&e.PreCertificate)) {
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
