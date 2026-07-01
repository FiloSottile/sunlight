package ctlog

import (
	"testing"

	ctasn1 "github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
)

func TestValidateMarkCertificateProfile(t *testing.T) {
	requiredPolicy := ctasn1.ObjectIdentifier{2, 16, 840, 1, 114413, 1, 7, 23, 4}
	log := &Log{c: &Config{
		CertificateProfile:      CertificateProfileMark,
		MarkCertificatePolicies: []ctasn1.ObjectIdentifier{requiredPolicy},
	}}

	t.Run("accepts mark EKU and required policy", func(t *testing.T) {
		cert := &x509.Certificate{
			UnknownExtKeyUsage: []ctasn1.ObjectIdentifier{markCertificateEKU},
			PolicyIdentifiers:  []ctasn1.ObjectIdentifier{requiredPolicy},
		}
		if err := log.validateCertificateProfile(cert); err != nil {
			t.Fatalf("validateCertificateProfile returned error: %v", err)
		}
	})

	t.Run("rejects missing mark EKU", func(t *testing.T) {
		cert := &x509.Certificate{
			ExtKeyUsage:       []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			PolicyIdentifiers: []ctasn1.ObjectIdentifier{requiredPolicy},
		}
		if err := log.validateCertificateProfile(cert); err == nil {
			t.Fatal("validateCertificateProfile succeeded for certificate without mark EKU")
		}
	})

	t.Run("rejects missing required policy", func(t *testing.T) {
		cert := &x509.Certificate{
			UnknownExtKeyUsage: []ctasn1.ObjectIdentifier{markCertificateEKU},
		}
		if err := log.validateCertificateProfile(cert); err == nil {
			t.Fatal("validateCertificateProfile succeeded for certificate without required policy")
		}
	})
}

func TestValidateTLSCertificateProfile(t *testing.T) {
	log := &Log{c: &Config{}}
	if err := log.validateCertificateProfile(&x509.Certificate{}); err != nil {
		t.Fatalf("default profile validation returned error: %v", err)
	}
}
