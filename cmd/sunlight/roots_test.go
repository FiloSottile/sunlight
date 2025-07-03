package main

import "testing"

func TestCCADBRoots(t *testing.T) {
	t.Run("Prod", func(t *testing.T) {
		url := "https://ccadb.my.salesforce-sites.com/ccadb/RootCACertificatesIncludedByRSReportCSV"
		testCCADBRoots(t, url)
	})
	t.Run("Testing", func(t *testing.T) {
		url := "https://ccadb.my.salesforce-sites.com/ccadb/RootCACertificatesInclusionReportCSV"
		testCCADBRoots(t, url)
	})
}

func testCCADBRoots(t *testing.T, url string) {
	certs, err := CCADBRoots(t.Context(), url)
	if err != nil {
		t.Fatalf("failed to load CCADB roots: %v", err)
	}
	if len(certs) < 50 {
		t.Fatalf("expected at least 50 CCADB roots, got %d", len(certs))
	}
	t.Logf("loaded %d CCADB roots", len(certs))
}
