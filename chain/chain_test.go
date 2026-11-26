package chain

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"os"
	"os/exec"
	"testing"
)

func TestError(t *testing.T) {
	p := newTestPKI(t)
	for _, tt := range []struct {
		chain [][]byte
		want  string
	}{
		{nil, "chain: no certificates"},
		{[][]byte{p.intermediate.der}, "chain: certificate 0: extKeyUsage without the required purpose"},
		{[][]byte{p.leaf(t, nil), p.root.der}, "chain: certificate 0: issuer is not the subject of certificate 1"},
	} {
		_, err := p.verifier.Verify(tt.chain, false)
		if err == nil || err.Error() != tt.want {
			t.Errorf("got %v, want %s", err, tt.want)
		}
	}
}

// TestFIPS140Enforced runs the test binary again in FIPS 140-3 enforced mode,
// in which the package is expected to panic when it is initialized.
func TestFIPS140Enforced(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}
	if err == nil || !bytes.Contains(out, []byte("chain: verifying SHA-1 signatures is not possible")) {
		t.Errorf("got %v, want a panic at init:\n%s", err, out)
	}
}

func TestExtKeyUsages(t *testing.T) {
	for _, tt := range []struct {
		purpose ExtKeyUsage
		oid     asn1.ObjectIdentifier
	}{
		{ServerAuth, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}},
		{BrandIndicatorForMessageIdentification, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 31}},
		{anyExtendedKeyUsage, asn1.ObjectIdentifier{2, 5, 29, 37, 0}},
		{precertificateSigning, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}},
	} {
		der, err := asn1.Marshal(tt.oid)
		if err != nil {
			t.Fatal(err)
		}
		// Skip the tag and the length, which is a single byte for these.
		if want := string(der[2:]); string(tt.purpose) != want {
			t.Errorf("%v: got %x, want %x", tt.oid, tt.purpose, want)
		}
	}
}
