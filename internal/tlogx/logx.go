package tlogx

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const maxCheckpointSize = 1e6

type Checkpoint struct {
	Origin string
	N      int64
	Hash   tlog.Hash
}

func ParseCheckpoint(text string) (Checkpoint, error) {
	// This is an extended version of tlog.ParseTree.
	//
	// A checkpoint looks like:
	//
	//	example.com/origin
	//	2
	//	nND/nri/U0xuHUrYSy0HtMeal2vzD9V4k/BO79C+QeI=
	//
	// For forwards compatibility, extra text lines after the encoding are ignored.

	if strings.Count(text, "\n") < 3 || len(text) > maxCheckpointSize {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}

	lines := strings.SplitN(text, "\n", 4)

	n, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || n < 0 || lines[1] != strconv.FormatInt(n, 10) {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}

	h, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(h) != tlog.HashSize {
		return Checkpoint{}, errors.New("malformed checkpoint")
	}

	var hash tlog.Hash
	copy(hash[:], h)
	return Checkpoint{lines[0], n, hash}, nil
}

const algCosignatureV1 = 4

// NewCosignatureV1Signer constructs a new CosignatureV1Signer that produces
// timestamped cosignature/v1 signatures from an Ed25519 private key.
func NewCosignatureV1Signer(name string, key crypto.Signer) (*CosignatureV1Signer, error) {
	if !isValidName(name) {
		return nil, errors.New("invalid name")
	}
	k, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("key type is not Ed25519")
	}

	s := &CosignatureV1Signer{}
	s.name = name
	s.hash = keyHash(name, append([]byte{algCosignatureV1}, k...))
	s.sign = func(msg []byte) ([]byte, error) {
		t := uint64(time.Now().Unix())
		m, err := formatCosignatureV1(t, msg)
		if err != nil {
			return nil, err
		}
		s, err := key.Sign(nil, m, crypto.Hash(0))
		if err != nil {
			return nil, err
		}

		// The signature itself is encoded as timestamp || signature.
		sig := make([]byte, 0, 8+ed25519.SignatureSize)
		sig = binary.LittleEndian.AppendUint64(sig, t)
		sig = append(sig, s...)
		return sig, nil
	}
	s.verify = func(msg, sig []byte) bool {
		if len(sig) != 8+ed25519.SignatureSize {
			return false
		}
		t := binary.LittleEndian.Uint64(sig)
		sig = sig[8:]
		m, err := formatCosignatureV1(t, msg)
		if err != nil {
			return false
		}
		return ed25519.Verify(k, m, sig)
	}

	return s, nil
}

func formatCosignatureV1(t uint64, msg []byte) ([]byte, error) {
	// The signed message is in the following format
	//
	//      cosignature/v1
	//      time TTTTTTTTTT
	//      origin line
	//      NNNNNNNNN
	//      tree hash
	//
	// where TTTTTTTTTT is the current UNIX timestamp, and the following
	// three lines are the first three lines of the note. All other
	// lines are not processed by the witness, so are not signed.

	lines := bytes.Split(msg, []byte("\n"))
	if len(lines) < 3 {
		return nil, errors.New("cosigned note format invalid")
	}
	return []byte(fmt.Sprintf(
		"cosignature/v1\ntime %d\n%s\n%s\n%s\n",
		t, lines[0], lines[1], lines[2])), nil
}

type CosignatureV1Signer struct {
	verifier
	sign func([]byte) ([]byte, error)
}

type verifier struct {
	name   string
	hash   uint32
	verify func(msg, sig []byte) bool
}

var _ note.Signer = &CosignatureV1Signer{}

func (v *verifier) Name() string                               { return v.name }
func (v *verifier) KeyHash() uint32                            { return v.hash }
func (v *verifier) Verify(msg, sig []byte) bool                { return v.verify(msg, sig) }
func (s *CosignatureV1Signer) Sign(msg []byte) ([]byte, error) { return s.sign(msg) }
func (s *CosignatureV1Signer) Verifier() note.Verifier         { return &s.verifier }

// isValidName reports whether name is valid.
// It must be non-empty and not have any Unicode spaces or pluses.
func isValidName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 && !strings.Contains(name, "+")
}

func keyHash(name string, key []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(key)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum)
}
