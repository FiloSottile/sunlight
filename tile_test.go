package sunlight

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestTrimmedEntryNamesTiles checks TrimmedEntry against the names tiles of a
// log, which were made from the same entries.
func TestTrimmedEntryNamesTiles(t *testing.T) {
	for _, tile := range []string{"000", "001", "002", "003", "003.p/10"} {
		data, err := os.ReadFile(filepath.Join("testdata", "navigli2025h2", "tile", "data", tile))
		if err != nil {
			t.Fatal(err)
		}
		names, err := os.ReadFile(filepath.Join("testdata", "navigli2025h2", "tile", "names", tile))
		if err != nil {
			t.Fatal(err)
		}
		lines := bytes.Split(bytes.TrimSuffix(names, []byte("\n")), []byte("\n"))
		for _, line := range lines {
			var e *LogEntry
			if e, data, err = ReadTileLeaf(data); err != nil {
				t.Fatal(err)
			}
			te, err := e.TrimmedEntry()
			if err != nil {
				t.Fatalf("entry %d: %v", e.LeafIndex, err)
			}
			got, err := json.Marshal(te)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, line) {
				t.Errorf("entry %d: got %s, want %s", e.LeafIndex, got, line)
			}
		}
		if len(data) != 0 {
			t.Errorf("tile %s has more entries than its names tile", tile)
		}
	}
}

func TestTrimmedEntry(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := func(modify func(*x509.Certificate)) []byte {
		t.Helper()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "example.com"},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour),
			DNSNames:     []string{"example.com"},
		}
		modify(template)
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	marshal := func(v any) []byte {
		t.Helper()
		der, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	// commonName returns a RelativeDistinguishedName with a commonName of the
	// given type.
	commonName := func(tag int, value string) pkix.RelativeDistinguishedNameSET {
		return pkix.RelativeDistinguishedNameSET{{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
			Value: asn1.RawValue{Tag: tag, Bytes: []byte(value)},
		}}
	}
	// name returns a Name with one attribute that has the given fields.
	name := func(fields ...any) []byte {
		return marshal([]asn1.RawValue{{Tag: asn1.TagSet, IsCompound: true, Bytes: marshal(fields)}})
	}
	// subjectAltName returns an extension with the given GeneralNames.
	subjectAltName := func(names ...asn1.RawValue) pkix.Extension {
		return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: marshal(names)}
	}
	dNSName := func(name string) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(name)}
	}

	for _, tt := range []struct {
		name   string
		modify func(*x509.Certificate)
		want   string
	}{
		{"names", func(c *x509.Certificate) {
			c.Subject = pkix.Name{
				Country:            []string{"IT"},
				Organization:       []string{"Esempio", "Example"},
				OrganizationalUnit: []string{"Unit"},
				Locality:           []string{"Roma"},
				Province:           []string{"RM"},
				StreetAddress:      []string{"Via Appia"},
				PostalCode:         []string{"00100"},
				SerialNumber:       "1234",
				CommonName:         "example.com",
			}
			c.DNSNames = []string{"example.com", "*.example.com"}
			c.EmailAddresses = []string{"root@example.com"}
			c.IPAddresses = []net.IP{net.IPv4(192, 0, 2, 1).To4(), net.ParseIP("2001:db8::1")}
		}, `{"Timestamp":42,"Subject":{"Country":["IT"],"Organization":["Esempio","Example"],` +
			`"OrganizationalUnit":["Unit"],"Locality":["Roma"],"Province":["RM"],` +
			`"StreetAddress":["Via Appia"],"PostalCode":["00100"],"CommonName":"example.com"},` +
			`"DNS":["example.com","*.example.com"],"IP":["192.0.2.1","2001:db8::1"]}`},
		{"no names", func(c *x509.Certificate) {
			c.Subject = pkix.Name{}
			c.DNSNames = nil
		}, `{"Timestamp":42}`},
		{"PrintableString", func(c *x509.Certificate) {
			c.RawSubject = marshal(pkix.RDNSequence{commonName(asn1.TagPrintableString, "Example")})
		}, `{"Timestamp":42,"Subject":{"CommonName":"Example"},"DNS":["example.com"]}`},
		{"attribute with two fields", func(c *x509.Certificate) {
			c.RawSubject = name(asn1.ObjectIdentifier{2, 5, 4, 3}, "example.org")
		}, `{"Timestamp":42,"Subject":{"CommonName":"example.org"},"DNS":["example.com"]}`},
		{"other attribute with another string type", func(c *x509.Certificate) {
			// domainComponent is an IA5String.
			c.RawSubject = name(asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, asn1.RawValue{Tag: asn1.TagIA5String, Bytes: []byte("example")})
		}, `{"Timestamp":42,"DNS":["example.com"]}`},
		{"two subjectAltNames", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{
				subjectAltName(dNSName("a.example")),
				subjectAltName(dNSName("b.example")),
			}
		}, `{"Timestamp":42,"Subject":{"CommonName":"example.com"},"DNS":["a.example","b.example"]}`},
		{"other GeneralNames", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{subjectAltName(
				asn1.RawValue{Tag: asn1.TagInteger, Bytes: []byte("integer.example")},
				asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte("https://uri.example")},
				dNSName("example.com"),
			)}
		}, `{"Timestamp":42,"Subject":{"CommonName":"example.com"},"DNS":["example.com"]}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			der := certificate(tt.modify)
			for _, e := range []*LogEntry{
				{Certificate: der, Timestamp: 42},
				{Certificate: []byte("tbs"), IsPrecert: true, PreCertificate: der, Timestamp: 42},
			} {
				te, err := e.TrimmedEntry()
				if err != nil {
					t.Fatal(err)
				}
				got, err := json.Marshal(te)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != tt.want {
					t.Errorf("got %s, want %s", got, tt.want)
				}
			}
		})
	}

	for _, tt := range []struct {
		name   string
		modify func(*x509.Certificate)
	}{
		{"subject that is not a sequence of sets", func(c *x509.Certificate) {
			c.RawSubject = marshal([]asn1.RawValue{
				{FullBytes: marshal(commonName(asn1.TagUTF8String, "example.com"))},
				{Tag: asn1.TagOctetString, Bytes: []byte("not a RelativeDistinguishedName")},
			})
		}},
		{"T61String", func(c *x509.Certificate) {
			c.RawSubject = marshal(pkix.RDNSequence{commonName(asn1.TagT61String, "Example")})
		}},
		{"commonName that is not a string", func(c *x509.Certificate) {
			c.RawSubject = marshal(pkix.RDNSequence{commonName(asn1.TagInteger, "\x01")})
		}},
		{"UTF8String that is not UTF-8", func(c *x509.Certificate) {
			c.RawSubject = marshal(pkix.RDNSequence{commonName(asn1.TagUTF8String, "example\xff")})
		}},
		{"PrintableString that is not UTF-8", func(c *x509.Certificate) {
			c.RawSubject = marshal(pkix.RDNSequence{commonName(asn1.TagPrintableString, "example\xff")})
		}},
		{"dNSName that is not UTF-8", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{subjectAltName(dNSName("example\xff.com"))}
		}},
		{"iPAddress of the wrong length", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{subjectAltName(
				dNSName("example.com"),
				asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 7, Bytes: []byte{1, 2, 3}},
			)}
		}},
		{"attribute with a third field", func(c *x509.Certificate) {
			c.RawSubject = name(asn1.ObjectIdentifier{2, 5, 4, 3}, "example.com", 1)
		}},
		{"truncated GeneralName", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{subjectAltName(
				dNSName("example.com"),
				asn1.RawValue{FullBytes: []byte{0x82, 0x05, 'x'}},
			)}
		}},
		{"subjectAltName that is not a SEQUENCE", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{{
				Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
				Value: marshal([]byte("example.com")),
			}}
		}},
		{"data after the subjectAltName", func(c *x509.Certificate) {
			ext := subjectAltName(dNSName("example.com"))
			ext.Value = append(ext.Value, 0x00)
			c.ExtraExtensions = []pkix.Extension{ext}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if te, err := (&LogEntry{Certificate: certificate(tt.modify)}).TrimmedEntry(); err == nil {
				t.Errorf("TrimmedEntry returned %+v", te)
			}
		})
	}

	der := certificate(func(*x509.Certificate) {})
	for _, cert := range [][]byte{nil, []byte("certificate"), der[:len(der)-1]} {
		if _, err := (&LogEntry{Certificate: cert}).TrimmedEntry(); err == nil {
			t.Errorf("TrimmedEntry accepted %x", cert)
		}
	}
}
