package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"filippo.io/sunlight/internal/ctlog"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

func loadRoots(ctx context.Context, lc LogConfig, l *ctlog.Log) error {
	rootsPEM, err := os.ReadFile(lc.Roots)
	if err != nil {
		return err
	}
	if err := l.SetRootsFromPEM(ctx, rootsPEM); err != nil {
		return err
	}
	return nil
}

func loadCCADBRoots(ctx context.Context, lc LogConfig, l *ctlog.Log) (newRoots bool, err error) {
	old := l.RootsPEM()
	buf := bytes.NewBuffer(old)
	pool := x509util.NewPEMCertPool()
	pool.AppendCertsFromPEM(old)
	addRoot := func(cert *x509.Certificate, source string) {
		if pool.Included(cert) {
			return
		}
		newRoots = true
		pool.AddCert(cert)
		fmt.Fprintf(buf, "\n# %s\n# added on %s from %s\n%s\n",
			cert.Subject.String(),
			time.Now().Format(time.RFC3339),
			source,
			pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}),
		)
	}

	mergeDelayCert, err := x509util.CertificateFromPEM([]byte(mergeDelayRoot))
	if err != nil {
		return false, fmt.Errorf("failed to parse merge delay root: %w", err)
	}
	addRoot(mergeDelayCert, "Sunlight")

	url := "https://ccadb.my.salesforce-sites.com/ccadb/RootCACertificatesIncludedByRSReportCSV"
	if lc.CCADBRoots == "testing" {
		url = "https://ccadb.my.salesforce-sites.com/ccadb/RootCACertificatesInclusionReportCSV"
	}
	certs, err := CCADBRoots(ctx, url)
	if err != nil {
		return false, err
	}
	for _, cert := range certs {
		addRoot(cert, "CCADB")
	}

	if lc.ExtraRoots != "" {
		extraBytes, err := os.ReadFile(lc.ExtraRoots)
		if err != nil {
			return false, fmt.Errorf("failed to read extra roots file %q: %w", lc.ExtraRoots, err)
		}
		extra, err := x509util.CertificatesFromPEM(extraBytes)
		if err != nil {
			return false, fmt.Errorf("failed to parse extra roots file %q: %w", lc.ExtraRoots, err)
		}
		for _, cert := range extra {
			addRoot(cert, "extra roots file")
		}
	}

	if !newRoots {
		return false, nil
	}
	return true, l.SetRootsFromPEM(ctx, buf.Bytes())
}

var CCADBClient = &http.Client{
	Timeout: 10 * time.Second,
}

func CCADBRoots(ctx context.Context, url string) ([]*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "+https://filippo.io/sunlight")
	resp, err := CCADBClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CCADB CSV: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch CCADB CSV: %s", resp.Status)
	}

	csvReader := csv.NewReader(resp.Body)
	hdr, err := csvReader.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CCADB CSV header: %w", err)
	}
	pemIdx := slices.Index(hdr, "X.509 Certificate (PEM)")
	if pemIdx < 0 {
		return nil, fmt.Errorf("CCADB CSV header does not contain %q", "X.509 Certificate (PEM)")
	}
	usesIdx := slices.Index(hdr, "Intended Use Case(s) Served")
	if usesIdx < 0 {
		return nil, fmt.Errorf("CCADB CSV header does not contain %q", "Intended Use Case(s) Served")
	}
	var certificates []*x509.Certificate
	for {
		row, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read CCADB CSV row: %w", err)
		}
		if len(row) <= pemIdx || len(row) <= usesIdx {
			return nil, fmt.Errorf("CCADB CSV row is too short: %q", row)
		}
		// There is an "Example CA" row with an empty PEM column.
		if row[pemIdx] == "" {
			continue
		}
		if !strings.Contains(row[usesIdx], "Server Authentication (TLS) 1.3.6.1.5.5.7.3.1") {
			continue
		}
		cert, err := x509util.CertificateFromPEM([]byte(row[pemIdx]))
		if err != nil {
			return nil, fmt.Errorf("failed to parse CCADB certificate: %w\n%q", err, row)
		}
		certificates = append(certificates, cert)
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in CCADB CSV")
	}
	return certificates, nil
}

const mergeDelayRoot = `
-----BEGIN CERTIFICATE-----
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
eg==
-----END CERTIFICATE-----
`
