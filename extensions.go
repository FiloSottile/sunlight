package sunlight

import (
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

// Extensions is the CTExtensions field of SignedCertificateTimestamp and
// TimestampedEntry, according to c2sp.org/static-ct-api.
type Extensions struct {
	LeafIndex int64
}

func MarshalExtensions(e Extensions) ([]byte, error) {
	// enum {
	//     leaf_index(0), (255)
	// } ExtensionType;
	//
	// struct {
	//     ExtensionType extension_type;
	//     opaque extension_data<0..2^16-1>;
	// } Extension;
	//
	// Extension CTExtensions<0..2^16-1>;
	//
	// uint8 uint40[5];
	// uint40 LeafIndex;

	b := &cryptobyte.Builder{}
	b.AddUint8(0 /* extension_type = leaf_index */)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		if e.LeafIndex < 0 || e.LeafIndex >= 1<<40 {
			b.SetError(errors.New("leaf_index out of range"))
			return
		}
		addUint40(b, uint64(e.LeafIndex))
	})
	return b.Bytes()
}

// ParseExtensions parse a CTExtensions field, ignoring unknown extensions.
// It is an error if the leaf_index extension is missing.
func ParseExtensions(extensions []byte) (Extensions, error) {
	b := cryptobyte.String(extensions)
	for !b.Empty() {
		var extensionType uint8
		var extension cryptobyte.String
		if !b.ReadUint8(&extensionType) || !b.ReadUint16LengthPrefixed(&extension) {
			return Extensions{}, errors.New("invalid extension")
		}
		if extensionType == 0 /* leaf_index */ {
			var e Extensions
			if !readUint40(&extension, &e.LeafIndex) || !extension.Empty() {
				return Extensions{}, errors.New("invalid leaf_index extension")
			}
			return e, nil
		}
	}
	return Extensions{}, errors.New("missing leaf_index extension")
}

// addUint40 appends a big-endian, 40-bit value to the byte string.
func addUint40(b *cryptobyte.Builder, v uint64) {
	b.AddBytes([]byte{byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// readUint40 decodes a big-endian, 40-bit value into out and advances over it.
// It reports whether the read was successful.
func readUint40(s *cryptobyte.String, out *int64) bool {
	var v []byte
	if !s.ReadBytes(&v, 5) {
		return false
	}
	*out = int64(v[0])<<32 | int64(v[1])<<24 | int64(v[2])<<16 | int64(v[3])<<8 | int64(v[4])
	return true
}
