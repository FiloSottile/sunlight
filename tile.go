package sunlight

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
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
	//
	// If RFC6962ArchivalLeaf is true, this field is ignored and
	// should be set to 0.
	LeafIndex int64

	// RFC6962ArchivalLeaf is true if this LogEntry is an archived
	// RFC 6962 log leaf, which is missing the leaf index extension.
	//
	// [ReadTileLeaf] always sets this to false. To read such leaves,
	// use [ReadTileLeafMaybeArchival].
	RFC6962ArchivalLeaf bool

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
	addExtensions(b, e)
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
	e, rest, err = readTileLeaf(tile)
	if err != nil {
		return nil, rest, err
	}
	if e.RFC6962ArchivalLeaf {
		return nil, rest, fmt.Errorf("leaf is missing leaf index extension")
	}
	return e, rest, nil
}

// ReadTileLeafMaybeArchival reads a LogEntry from a data tile, and returns the
// remaining data in the tile.
//
// If the leaf is missing the leaf index extension, the returned LogEntry has
// RFC6962ArchivalLeaf set to true, and LeafIndex set to zero.
func ReadTileLeafMaybeArchival(tile []byte) (e *LogEntry, rest []byte, err error) {
	return readTileLeaf(tile)
}

func readTileLeaf(tile []byte) (e *LogEntry, rest []byte, err error) {
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
	if extensions.Empty() {
		e.RFC6962ArchivalLeaf = true
	} else {
		var extensionType uint8
		var extensionData cryptobyte.String
		if !extensions.ReadUint8(&extensionType) || extensionType != 0 ||
			!extensions.ReadUint16LengthPrefixed(&extensionData) ||
			!readUint40(&extensionData, &e.LeafIndex) || !extensionData.Empty() ||
			!extensions.Empty() {
			return nil, s, fmt.Errorf("invalid data tile extensions")
		}
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
	addExtensions(b, e)
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

func addExtensions(b *cryptobyte.Builder, e *LogEntry) {
	if e.RFC6962ArchivalLeaf {
		b.AddUint16(0)
		return
	}
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		ext, err := MarshalExtensions(Extensions{LeafIndex: e.LeafIndex})
		if err != nil {
			b.SetError(err)
			return
		}
		b.AddBytes(ext)
	})
}

// A TrimmedEntry is a subset of the information in a [LogEntry], including
// names parsed from the certificate or pre-certificate. An entry whose names
// could not be parsed only has the Timestamp.
type TrimmedEntry struct {
	// Timestamp is the UNIX timestamp in milliseconds of when the entry was
	// added to the log.
	Timestamp int64

	// Subject contains the parsed Subject information from the certificate.
	Subject struct {
		Country, Organization, OrganizationalUnit []string `json:",omitempty"`
		Locality, Province                        []string `json:",omitempty"`
		StreetAddress, PostalCode                 []string `json:",omitempty"`
		CommonName                                string   `json:",omitempty"`
	} `json:",omitzero"`

	// DNS and IP are the Subject Alternative Names of the certificate.
	DNS []string `json:",omitempty"`
	IP  []string `json:",omitempty"`
}

func (e *LogEntry) TrimmedEntry() (*TrimmedEntry, error) {
	t := &TrimmedEntry{
		Timestamp: e.Timestamp,
	}
	input := cryptobyte.String(e.Certificate)
	if e.IsPrecert {
		input = cryptobyte.String(e.PreCertificate)
	}

	// Certificate  ::=  SEQUENCE  {
	//     tbsCertificate       TBSCertificate,
	//     signatureAlgorithm   AlgorithmIdentifier,
	//     signatureValue       BIT STRING  }
	//
	// TBSCertificate  ::=  SEQUENCE  {
	//     version         [0]  EXPLICIT Version DEFAULT v1,
	//     serialNumber         CertificateSerialNumber,
	//     signature            AlgorithmIdentifier,
	//     issuer               Name,
	//     validity             Validity,
	//     subject              Name,
	//     subjectPublicKeyInfo SubjectPublicKeyInfo,
	//     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
	//     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
	//     extensions      [3]  EXPLICIT Extensions OPTIONAL  }
	var cert, tbs, subject, wrapper, extensions cryptobyte.String
	if !input.ReadASN1(&cert, asn1.SEQUENCE) ||
		!cert.ReadASN1(&tbs, asn1.SEQUENCE) ||
		!tbs.SkipOptionalASN1(asn1.Tag(0).Constructed().ContextSpecific()) ||
		!tbs.SkipASN1(asn1.INTEGER) ||
		!tbs.SkipASN1(asn1.SEQUENCE) ||
		!tbs.SkipASN1(asn1.SEQUENCE) ||
		!tbs.SkipASN1(asn1.SEQUENCE) ||
		!tbs.ReadASN1(&subject, asn1.SEQUENCE) ||
		!tbs.SkipASN1(asn1.SEQUENCE) ||
		!tbs.SkipOptionalASN1(asn1.Tag(1).ContextSpecific()) ||
		!tbs.SkipOptionalASN1(asn1.Tag(2).ContextSpecific()) ||
		!tbs.ReadOptionalASN1(&wrapper, nil, asn1.Tag(3).Constructed().ContextSpecific()) ||
		!wrapper.Empty() && !wrapper.ReadASN1(&extensions, asn1.SEQUENCE) {
		return nil, errors.New("failed to parse certificate")
	}

	// Name ::= SEQUENCE OF RelativeDistinguishedName
	//
	// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
	//
	// AttributeTypeAndValue ::= SEQUENCE {
	//     type     OBJECT IDENTIFIER,
	//     value    ANY -- DEFINED BY AttributeType }
	for !subject.Empty() {
		var rdn cryptobyte.String
		if !subject.ReadASN1(&rdn, asn1.SET) {
			return nil, errors.New("failed to parse certificate subject")
		}
		for !rdn.Empty() {
			var attribute, oid, value cryptobyte.String
			var tag asn1.Tag
			if !rdn.ReadASN1(&attribute, asn1.SEQUENCE) ||
				!attribute.ReadASN1(&oid, asn1.OBJECT_IDENTIFIER) ||
				!attribute.ReadAnyASN1(&value, &tag) || !attribute.Empty() {
				return nil, errors.New("failed to parse certificate subject")
			}
			s := string(value)
			switch string(oid) {
			case "\x55\x04\x03": // id-at-commonName, 2.5.4.3
				t.Subject.CommonName = s
			case "\x55\x04\x06": // id-at-countryName, 2.5.4.6
				t.Subject.Country = append(t.Subject.Country, s)
			case "\x55\x04\x07": // id-at-localityName, 2.5.4.7
				t.Subject.Locality = append(t.Subject.Locality, s)
			case "\x55\x04\x08": // id-at-stateOrProvinceName, 2.5.4.8
				t.Subject.Province = append(t.Subject.Province, s)
			case "\x55\x04\x09": // id-at-streetAddress, 2.5.4.9
				t.Subject.StreetAddress = append(t.Subject.StreetAddress, s)
			case "\x55\x04\x0a": // id-at-organizationName, 2.5.4.10
				t.Subject.Organization = append(t.Subject.Organization, s)
			case "\x55\x04\x0b": // id-at-organizationalUnitName, 2.5.4.11
				t.Subject.OrganizationalUnit = append(t.Subject.OrganizationalUnit, s)
			case "\x55\x04\x11": // id-at-postalCode, 2.5.4.17
				t.Subject.PostalCode = append(t.Subject.PostalCode, s)
			default:
				continue
			}
			// The Baseline Requirements only allow UTF8String and
			// PrintableString for the attributes above.
			if tag != asn1.UTF8String && tag != asn1.PrintableString {
				return nil, errors.New("unsupported string type in certificate subject")
			}
			// Invalid UTF-8 would be replaced when encoding the entry as JSON.
			if !utf8.Valid(value) {
				return nil, errors.New("invalid string in certificate subject")
			}
		}
	}

	// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
	//
	// Extension  ::=  SEQUENCE  {
	//     extnID      OBJECT IDENTIFIER,
	//     critical    BOOLEAN DEFAULT FALSE,
	//     extnValue   OCTET STRING  }
	for !extensions.Empty() {
		var ext, id, value cryptobyte.String
		if !extensions.ReadASN1(&ext, asn1.SEQUENCE) ||
			!ext.ReadASN1(&id, asn1.OBJECT_IDENTIFIER) ||
			!ext.SkipOptionalASN1(asn1.BOOLEAN) ||
			!ext.ReadASN1(&value, asn1.OCTET_STRING) {
			return nil, errors.New("failed to parse certificate")
		}
		if string(id) != "\x55\x1d\x11" { // id-ce-subjectAltName, 2.5.29.17
			continue
		}

		// SubjectAltName ::= GeneralNames
		//
		// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
		//
		// GeneralName ::= CHOICE {
		//     ...
		//     dNSName                         [2]     IA5String,
		//     ...
		//     iPAddress                       [7]     OCTET STRING,
		//     ...  }
		var names cryptobyte.String
		if !value.ReadASN1(&names, asn1.SEQUENCE) || !value.Empty() {
			return nil, errors.New("failed to parse certificate subjectAltName")
		}
		for !names.Empty() {
			var name cryptobyte.String
			var tag asn1.Tag
			if !names.ReadAnyASN1(&name, &tag) {
				return nil, errors.New("failed to parse certificate subjectAltName")
			}
			switch tag {
			case asn1.Tag(2).ContextSpecific():
				if !utf8.Valid(name) {
					return nil, errors.New("invalid DNS name in certificate subjectAltName")
				}
				t.DNS = append(t.DNS, string(name))
			case asn1.Tag(7).ContextSpecific():
				if len(name) != net.IPv4len && len(name) != net.IPv6len {
					return nil, errors.New("invalid IP address in certificate subjectAltName")
				}
				t.IP = append(t.IP, net.IP(name).String())
			}
		}
	}
	return t, nil
}
