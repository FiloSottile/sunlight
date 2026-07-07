package main

import (
	"testing"

	"filippo.io/sunlight/internal/ctlog"
)

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
			name:    "mark requires roots file",
			lc:      LogConfig{CertificateProfile: ctlog.CertificateProfileMark},
			profile: ctlog.CertificateProfileMark,
			wantErr: true,
		},
		{
			name:    "mark rejects CCADB",
			lc:      LogConfig{CertificateProfile: ctlog.CertificateProfileMark, Roots: "roots.pem", CCADBRoots: "trusted"},
			profile: ctlog.CertificateProfileMark,
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
