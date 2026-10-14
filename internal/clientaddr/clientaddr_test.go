package clientaddr

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestNewHandler(t *testing.T) {
	tests := []struct {
		name       string
		trust      bool
		remoteAddr string
		forwarded  []string
		want       string
	}{
		{"direct", false, "203.0.113.1:1234", nil, "203.0.113.1:1234"},
		{"direct, header ignored", false, "203.0.113.1:1234", []string{"198.51.100.1"}, "203.0.113.1:1234"},
		{"proxy, no header", true, "10.1.2.3:1234", nil, "10.1.2.3:1234"},
		{"proxy", true, "10.1.2.3:1234", []string{"198.51.100.1"}, "198.51.100.1:0"},
		{"proxy, invalid connection address", true, "not an address", []string{"198.51.100.1"}, "198.51.100.1:0"},
		{"proxy, client-supplied entries", true, "10.1.2.3:1234", []string{"1.1.1.1, 198.51.100.1"}, "198.51.100.1:0"},
		{"proxy, spaces", true, "10.1.2.3:1234", []string{" 1.1.1.1 , 198.51.100.1 "}, "198.51.100.1:0"},
		{"proxy, multiple headers", true, "10.1.2.3:1234", []string{"1.1.1.1", "198.51.100.1"}, "198.51.100.1:0"},
		{"proxy, malformed", true, "10.1.2.3:1234", []string{"198.51.100.1, garbage"}, "10.1.2.3:1234"},
		{"proxy, empty", true, "10.1.2.3:1234", []string{""}, "10.1.2.3:1234"},
		{"proxy, mapped client", true, "10.1.2.3:1234", []string{"::ffff:198.51.100.1"}, "198.51.100.1:0"},
		{"proxy, ipv6 client", true, "10.1.2.3:1234", []string{"2001:db8:2::1"}, "[2001:db8:2::1]:0"},
		{"proxy, zoned client", true, "10.1.2.3:1234", []string{"fe80::1%eth0"}, "[fe80::1]:0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			h := NewHandler(tt.trust, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.RemoteAddr
			}))
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			for _, f := range tt.forwarded {
				r.Header.Add("X-Forwarded-For", f)
			}
			h.ServeHTTP(httptest.NewRecorder(), r)
			if got != tt.want {
				t.Fatalf("RemoteAddr = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSource(t *testing.T) {
	for _, tc := range []struct{ remoteAddr, want string }{
		{"192.0.2.1:1234", "192.0.2.1/32"},
		{"[::ffff:192.0.2.1]:1234", "192.0.2.1/32"},
		{"[2001:db8:1:2:3:4:5:6]:1234", "2001:db8:1:2::/64"},
		{"[2001:db8:1:2::]:1234", "2001:db8:1:2::/64"},
		{"[fe80::1%eth0]:1234", "fe80::/64"},
		{"192.0.2.1", ""},
		{"not an address", ""},
		{"", ""},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remoteAddr
		got := Source(r)
		if tc.want == "" {
			if got.IsValid() {
				t.Errorf("Source(%q) = %v, want zero Prefix", tc.remoteAddr, got)
			}
			continue
		}
		if got.String() != tc.want {
			t.Errorf("Source(%q) = %v, want %v", tc.remoteAddr, got, tc.want)
		}
	}
}

func TestTorExits(t *testing.T) {
	torExits.Store(&torExitSet{exits: map[netip.Addr]bool{
		netip.MustParseAddr("198.51.100.77"):    true,
		netip.MustParseAddr("2001:db8:ffff::1"): true,
	}})
	t.Cleanup(func() { torExits.Store(nil) })

	tests := []struct {
		name       string
		trust      bool
		remoteAddr string
		forwarded  []string
		want       string
	}{
		{"direct exit", false, "198.51.100.77:1234", nil, TorRemoteAddr},
		{"direct mapped exit", false, "[::ffff:198.51.100.77]:1234", nil, TorRemoteAddr},
		{"direct ipv6 exit", false, "[2001:db8:ffff::1]:1234", nil, TorRemoteAddr},
		{"direct non-exit", false, "198.51.100.78:1234", nil, "198.51.100.78:1234"},
		{"direct non-exit in exit's /64", false, "[2001:db8:ffff::2]:1234", nil, "[2001:db8:ffff::2]:1234"},
		{"direct, exit in ignored header", false, "198.51.100.78:1234", []string{"198.51.100.77"}, "198.51.100.78:1234"},
		{"proxy, exit client", true, "10.1.2.3:1234", []string{"198.51.100.77"}, TorRemoteAddr},
		{"proxy, non-exit client", true, "10.1.2.3:1234", []string{"198.51.100.78"}, "198.51.100.78:0"},
		{"proxy, no header", true, "198.51.100.77:1234", nil, TorRemoteAddr},
		{"invalid address", false, "not an address", nil, "not an address"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			h := NewHandler(tt.trust, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.RemoteAddr
			}))
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			for _, f := range tt.forwarded {
				r.Header.Add("X-Forwarded-For", f)
			}
			h.ServeHTTP(httptest.NewRecorder(), r)
			if got != tt.want {
				t.Fatalf("RemoteAddr = %q, want %q", got, tt.want)
			}
		})
	}

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = TorRemoteAddr
	if got := Source(r); got != TorSource {
		t.Errorf("Source(TorRemoteAddr) = %v, want %v", got, TorSource)
	}
}

func setTorExitListURL(t *testing.T, url string) {
	orig := torExitListURL
	torExitListURL = url
	t.Cleanup(func() { torExitListURL = orig })
}

func TestRefreshTorExits(t *testing.T) {
	t.Cleanup(func() { torExits.Store(nil) })
	const list = `{"version":"8.0","relays":[
		{"or_addresses":["198.51.100.1:9001","[2001:db8:ffff::1]:9001"],"exit_addresses":["198.51.100.2"],"exit_policy_summary":{"reject":["25"]},"exit_policy_v6_summary":{"reject":["25"]}},
		{"or_addresses":["198.51.100.3:443","[2001:db8:fffe::1]:443"],"exit_addresses":[],"exit_policy_summary":{"accept":["443"]},"exit_policy_v6_summary":{}},
		{"or_addresses":["[::ffff:198.51.100.4]:443"],"exit_policy_summary":{"accept":["80-443"]}},
		{"or_addresses":["198.51.100.6:9001","[2001:db8:fffd::1]:9001"],"exit_addresses":["198.51.100.7"],"exit_policy_summary":{"reject":["1-65535"]}},
		{"or_addresses":["198.51.100.8:9001","[2001:db8:fffc::1]:9001"],"exit_policy_summary":{"accept":["80","8443"]},"exit_policy_v6_summary":{"reject":["443"]}},
		{"or_addresses":["198.51.100.9:9001"]}
	]}`
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		outcome string
	}{
		{"success", 200, list, "success"},
		{"status", 500, list, "status"},
		{"invalid", 200, "<html>", "invalid"},
		{"invalid address", 200, `{"relays":[{"or_addresses":["nope"]}]}`, "invalid"},
		{"invalid policy port", 200, `{"relays":[{"or_addresses":["198.51.100.1:9001"],"exit_policy_summary":{"accept":["http"]}}]}`, "invalid"},
		{"invalid policy", 200, `{"relays":[{"or_addresses":["198.51.100.1:9001"],"exit_policy_summary":{"accept":["443"],"reject":["25"]}}]}`, "invalid"},
		{"no exits", 200, `{"relays":[{"or_addresses":["198.51.100.1:9001"],"exit_policy_summary":{"reject":["1-65535"]}}]}`, "empty"},
		{"empty", 200, `{"relays":[]}`, "empty"},
		{"truncated", 200, `{"relays":[],"pad":"` + strings.Repeat("x", torExitListMaxSize) + `"}`, "truncated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)
			setTorExitListURL(t, srv.URL)
			torExits.Store(nil)

			outcome, err := RefreshTorExits(t.Context())
			if outcome != tc.outcome {
				t.Errorf("outcome = %q, want %q (err: %v)", outcome, tc.outcome, err)
			}
			if (err != nil) != (tc.outcome != "success") {
				t.Errorf("err = %v, outcome %q", err, outcome)
			}
			for addr, want := range map[string]bool{
				"198.51.100.1:1":          tc.outcome == "success", // IPv4 OR address
				"198.51.100.2:1":          tc.outcome == "success", // exit address
				"198.51.100.3:1":          tc.outcome == "success", // accepts only 443
				"198.51.100.4:1":          tc.outcome == "success", // mapped OR address
				"[2001:db8:ffff::1]:1":    tc.outcome == "success", // IPv6 OR address
				"[2001:db8:ffff::2]:1":    false,
				"[2001:db8:fffe::1]:1":    false, // no IPv6 exit policy
				"[::ffff:198.51.100.5]:1": false,
				"198.51.100.6:1":          false, // non-exit
				"198.51.100.7:1":          false, // exit address of a non-exit
				"[2001:db8:fffd::1]:1":    false, // non-exit
				"198.51.100.8:1":          false, // doesn't accept 443
				"[2001:db8:fffc::1]:1":    false, // rejects 443 over IPv6
				"198.51.100.9:1":          false, // no exit policy
			} {
				if got := isTorExit(addr); got != want {
					t.Errorf("isTorExit(%q) = %v, want %v", addr, got, want)
				}
			}
		})
	}

	t.Run("request", func(t *testing.T) {
		setTorExitListURL(t, "http://127.0.0.1:1/")
		if outcome, err := RefreshTorExits(t.Context()); outcome != "request" || err == nil {
			t.Errorf("outcome = %q, err = %v, want request error", outcome, err)
		}
	})

	t.Run("unchanged", func(t *testing.T) {
		var ifModifiedSince []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ifModifiedSince = append(ifModifiedSince, r.Header.Get("If-Modified-Since"))
			if r.Header.Get("If-Modified-Since") == "Wed, 14 Oct 2026 12:09:25 GMT" {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Last-Modified", "Wed, 14 Oct 2026 12:09:25 GMT")
			w.Write([]byte(list))
		}))
		t.Cleanup(srv.Close)
		setTorExitListURL(t, srv.URL)
		torExits.Store(nil)

		if outcome, err := RefreshTorExits(t.Context()); outcome != "success" || err != nil {
			t.Fatalf("outcome = %q, err = %v, want success", outcome, err)
		}
		if outcome, err := RefreshTorExits(t.Context()); outcome != "unchanged" || err != nil {
			t.Fatalf("outcome = %q, err = %v, want unchanged", outcome, err)
		}
		if want := []string{"", "Wed, 14 Oct 2026 12:09:25 GMT"}; !slices.Equal(ifModifiedSince, want) {
			t.Errorf("If-Modified-Since = %q, want %q", ifModifiedSince, want)
		}
		if !isTorExit("198.51.100.1:1") {
			t.Error("set was lost on an unchanged response")
		}
	})
}

func TestPolicyAccepts(t *testing.T) {
	for _, tc := range []struct {
		summary map[string][]string
		want    bool
		err     bool
	}{
		{nil, false, false},
		{map[string][]string{}, false, false},
		{map[string][]string{"accept": {"443"}}, true, false},
		{map[string][]string{"accept": {"80", "443"}}, true, false},
		{map[string][]string{"accept": {"1-442", "444-65535"}}, false, false},
		{map[string][]string{"accept": {"443-443"}}, true, false},
		{map[string][]string{"accept": {"400-500"}}, true, false},
		{map[string][]string{"accept": {}}, false, false},
		{map[string][]string{"reject": {"25", "119"}}, true, false},
		{map[string][]string{"reject": {"1-65535"}}, false, false},
		{map[string][]string{"reject": {"443"}}, false, false},
		{map[string][]string{"reject": {}}, true, false},
		{map[string][]string{"accept": {"443"}, "reject": {"25"}}, false, true},
		{map[string][]string{"other": {"443"}}, false, true},
		{map[string][]string{"accept": {"https"}}, false, true},
		{map[string][]string{"accept": {"1-"}}, false, true},
		{map[string][]string{"accept": {"70000"}}, false, true},
	} {
		got, err := policyAccepts(tc.summary, 443)
		if (err != nil) != tc.err {
			t.Errorf("policyAccepts(%v) err = %v, want error %v", tc.summary, err, tc.err)
		}
		if got != tc.want {
			t.Errorf("policyAccepts(%v) = %v, want %v", tc.summary, got, tc.want)
		}
	}
}

func TestRefreshTorExitsLive(t *testing.T) {
	t.Cleanup(func() { torExits.Store(nil) })
	if outcome, err := RefreshTorExits(t.Context()); outcome != "success" || err != nil {
		t.Fatalf("outcome = %q, err = %v, want success", outcome, err)
	}
	s := torExits.Load()
	var v4, v6 int
	for a := range s.exits {
		if a.Is4() {
			v4++
		} else {
			v6++
		}
	}
	t.Logf("loaded %d IPv4 and %d IPv6 exits, Last-Modified %q", v4, v6, s.lastModified)
	if v4 < 500 || v6 < 50 {
		t.Errorf("suspiciously few exits: %d IPv4, %d IPv6", v4, v6)
	}
	if s.lastModified == "" {
		t.Error("no Last-Modified header")
	}
	if outcome, err := RefreshTorExits(t.Context()); outcome != "unchanged" || err != nil {
		t.Errorf("outcome = %q, err = %v, want unchanged", outcome, err)
	}
}
