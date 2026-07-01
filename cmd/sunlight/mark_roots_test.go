package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/sunlight/internal/ctlog"
)

func TestFetchRFC6962Roots(t *testing.T) {
	der := testRootDER(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() == "" {
			t.Error("missing User-Agent")
		}
		if r.URL.Path != "/ct/v1/get-roots" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if err := json.NewEncoder(w).Encode(struct {
			Certificates []string `json:"certificates"`
		}{
			Certificates: []string{base64.StdEncoding.EncodeToString(der)},
		}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	t.Cleanup(ts.Close)

	roots, err := FetchRFC6962Roots(context.Background(), ts.URL+"/ct/v1/get-roots")
	if err != nil {
		t.Fatalf("FetchRFC6962Roots returned error: %v", err)
	}
	if !strings.Contains(string(roots), "BEGIN CERTIFICATE") {
		t.Fatalf("FetchRFC6962Roots did not return PEM: %q", roots)
	}
}

func TestFetchRFC6962RootsRejectsEmptyResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(struct {
			Certificates []string `json:"certificates"`
		}{}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	t.Cleanup(ts.Close)

	if _, err := FetchRFC6962Roots(context.Background(), ts.URL); err == nil {
		t.Fatal("FetchRFC6962Roots succeeded with no certificates")
	}
}

func TestParseOID(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "valid", in: "1.3.6.1.5.5.7.3.31", want: "1.3.6.1.5.5.7.3.31"},
		{name: "first arc 2 allows large second arc", in: "2.999.1", want: "2.999.1"},
		{name: "empty arc", in: "1..3", wantErr: true},
		{name: "too few arcs", in: "1", wantErr: true},
		{name: "negative arc", in: "1.-1.3", wantErr: true},
		{name: "invalid first arc", in: "3.1.1", wantErr: true},
		{name: "invalid second arc", in: "1.40.1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oid, err := parseOID(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatal("parseOID succeeded")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseOID returned error: %v", err)
			}
			if got := oid.String(); got != tt.want {
				t.Fatalf("got OID %s, want %s", got, tt.want)
			}
		})
	}
}

func TestValidateLogConfig(t *testing.T) {
	tests := []struct {
		name    string
		lc      LogConfig
		profile string
		wantErr bool
	}{
		{
			name:    "TLS default with CCADB",
			profile: ctlog.CertificateProfileTLS,
		},
		{
			name:    "mark with roots file",
			lc:      LogConfig{Roots: "roots.pem", CertificateProfile: ctlog.CertificateProfileMark},
			profile: ctlog.CertificateProfileMark,
		},
		{
			name:    "mark with roots URL",
			lc:      LogConfig{MarkRootsURL: "https://example.com/ct/v1/get-roots", CertificateProfile: ctlog.CertificateProfileMark},
			profile: ctlog.CertificateProfileMark,
		},
		{
			name:    "mark requires root source",
			lc:      LogConfig{CertificateProfile: ctlog.CertificateProfileMark},
			profile: ctlog.CertificateProfileMark,
			wantErr: true,
		},
		{
			name:    "mark rejects CCADB",
			lc:      LogConfig{CertificateProfile: ctlog.CertificateProfileMark, MarkRootsURL: "https://example.com/roots", CCADBRoots: "trusted"},
			profile: ctlog.CertificateProfileMark,
			wantErr: true,
		},
		{
			name:    "TLS rejects mark URL",
			lc:      LogConfig{MarkRootsURL: "https://example.com/roots"},
			profile: ctlog.CertificateProfileTLS,
			wantErr: true,
		},
		{
			name:    "roots rejects extra roots",
			lc:      LogConfig{Roots: "roots.pem", ExtraRoots: "extra.pem"},
			profile: ctlog.CertificateProfileTLS,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLogConfig(tt.lc, tt.profile)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateLogConfig error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCertificateProfile(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "empty defaults to TLS", want: ctlog.CertificateProfileTLS},
		{name: "explicit TLS", in: ctlog.CertificateProfileTLS, want: ctlog.CertificateProfileTLS},
		{name: "mark", in: ctlog.CertificateProfileMark, want: ctlog.CertificateProfileMark},
		{name: "invalid", in: "email", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := certificateProfile(LogConfig{CertificateProfile: tt.in})
			if tt.wantErr {
				if err == nil {
					t.Fatal("certificateProfile succeeded")
				}
				return
			}
			if err != nil {
				t.Fatalf("certificateProfile returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got profile %q, want %q", got, tt.want)
			}
		})
	}
}

func testRootDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Mark Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	return der
}
