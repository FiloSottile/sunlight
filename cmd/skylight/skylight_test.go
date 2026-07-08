package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cespare/webtest"
	"gopkg.in/yaml.v3"
)

//go:generate go run testdata/gen.go

// TestRateLimitErrorHeaders checks that rate limited responses lose the
// content headers set optimistically before dispatch, while allowed responses
// keep them. The webtest scripts can't cover the 429 path, because triggering
// the rate limit over HTTP would be timing-dependent.
func TestRateLimitErrorHeaders(t *testing.T) {
	h := newRateLimitHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fake tile"))
	}))
	var allowed, limited int
	for range 2 * rateLimitBurst {
		req := httptest.NewRequest("GET", "/tile/data/000", nil)
		req = req.WithContext(context.WithValue(req.Context(), clientContextKey{}, "anonymous"))
		rec := httptest.NewRecorder()
		rec.Header().Set("Content-Encoding", "gzip")
		rec.Header().Set("Cache-Control", "public, max-age=604800, immutable")
		h.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusOK:
			allowed++
			if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
				t.Errorf("allowed response Content-Encoding = %q, want gzip", got)
			}
			if got := rec.Header().Get("Cache-Control"); got == "" {
				t.Error("allowed response is missing Cache-Control")
			}
		case http.StatusTooManyRequests:
			limited++
			if got := rec.Header().Get("Content-Encoding"); got != "" {
				t.Errorf("429 response Content-Encoding = %q, want empty", got)
			}
			if got := rec.Header().Get("Cache-Control"); got != "" {
				t.Errorf("429 response Cache-Control = %q, want empty", got)
			}
			if rec.Header().Get("Retry-After") == "" {
				t.Error("429 response is missing Retry-After")
			}
		default:
			t.Errorf("unexpected status code %d", rec.Code)
		}
	}
	if allowed == 0 || limited == 0 {
		t.Errorf("got %d allowed and %d rate limited responses, want some of each", allowed, limited)
	}
}

// TestScripts builds and runs the production skylight binary against the
// testdata configuration, and executes the webtest scripts against it.
func TestScripts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping exec of skylight in short mode")
	}

	// Pick a free localhost port for the server to listen on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	yml, err := os.ReadFile("testdata/skylight.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(yml, c); err != nil {
		t.Fatal(err)
	}
	c.Listen = []string{addr}
	yml, err = yaml.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "skylight.yaml")
	if err := os.WriteFile(configPath, yml, 0o666); err != nil {
		t.Fatal(err)
	}

	logs := &bytes.Buffer{}
	cmd := exec.Command("go", "run", ".", "-c", configPath)
	cmd.Stdout = io.Discard // JSON logs, duplicated on stderr
	cmd.Stderr = logs
	// Run go run in its own process group, so the SIGINT below reaches the
	// skylight child process too (go run doesn't forward signals sent
	// directly to it, only ones delivered to its process group).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
		cmd.Wait() // skylight always exits with a non-zero status
		if t.Failed() {
			t.Logf("skylight logs:\n%s", logs.Bytes())
		}
	})

	client := &http.Client{
		// Pass gzip-encoded responses through untouched.
		Transport: &http.Transport{DisableCompression: true},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for start := time.Now(); ; time.Sleep(50 * time.Millisecond) {
		resp, err := client.Get("http://" + addr + "/health")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Since(start) > 10*time.Second {
			t.Fatalf("server did not come up: %v", err)
		}
	}

	// webtest drives an http.Handler, so forward the requests to the server,
	// preserving the Host of the script URLs for name-based routing.
	webtest.TestHandler(t, "*_test.txt", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			req := r.Clone(r.Context())
			req.RequestURI = ""
			if req.Host == "" {
				req.Host = r.URL.Host
			}
			// Set a User-Agent with an email address unless the script case
			// sets its own, to avoid drawing down the global anonymous client
			// rate limit budget shared by all the test cases.
			if req.Header.Get("User-Agent") == "" {
				req.Header.Set("User-Agent", "skylight-webtest (test@test.invalid)")
			}
			req.URL.Scheme = "http"
			req.URL.Host = addr
			resp, err := client.Do(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
		}))
}
