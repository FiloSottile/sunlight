package clientaddr

import (
	"net/http"
	"net/http/httptest"
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
