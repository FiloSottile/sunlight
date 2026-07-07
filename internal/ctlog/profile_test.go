package ctlog

import (
	"testing"

	ctasn1 "github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
)

func TestValidateMarkCertificateProfile(t *testing.T) {
	log := &Log{c: &Config{
		CertificateProfile: CertificateProfileMark,
	}}

	t.Run("accepts mark EKU", func(t *testing.T) {
		cert := &x509.Certificate{
			UnknownExtKeyUsage: []ctasn1.ObjectIdentifier{markCertificateEKU},
		}
		if err := log.validateCertificateProfile(cert); err != nil {
			t.Fatalf("validateCertificateProfile returned error: %v", err)
		}
	})

	t.Run("rejects missing mark EKU", func(t *testing.T) {
		cert := &x509.Certificate{
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if err := log.validateCertificateProfile(cert); err == nil {
			t.Fatal("validateCertificateProfile succeeded for certificate without mark EKU")
		}
	})
}

func TestValidateTLSCertificateProfile(t *testing.T) {
	log := &Log{c: &Config{}}
	if err := log.validateCertificateProfile(&x509.Certificate{}); err != nil {
		t.Fatalf("default profile validation returned error: %v", err)
	}
}
