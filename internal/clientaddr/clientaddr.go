// Package clientaddr determines the IP address of the client behind an HTTP
// request, optionally taking into account a reverse proxy.
package clientaddr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// NewHandler returns a handler that, if trustReverseProxy is true, replaces
// the RemoteAddr of each request with the last entry of the X-Forwarded-For
// header, and then replaces the RemoteAddr of requests from Tor exit relays
// (see [RefreshTorExits]) with [TorRemoteAddr].
func NewHandler(trustReverseProxy bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if trustReverseProxy {
			if addr, ok := forwardedFor(r); ok {
				r.RemoteAddr = netip.AddrPortFrom(addr, 0).String()
			}
		}
		if isTorExit(r.RemoteAddr) {
			r.RemoteAddr = TorRemoteAddr
		}
		next.ServeHTTP(w, r)
	})
}

// forwardedFor returns the last address in the X-Forwarded-For header, which
// is the one appended by the proxy closest to us.
func forwardedFor(r *http.Request) (netip.Addr, bool) {
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return netip.Addr{}, false
	}
	last := values[len(values)-1]
	if i := strings.LastIndex(last, ","); i >= 0 {
		last = last[i+1:]
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(last))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap().WithZone(""), true
}

// Source returns the key under which the client of r is tracked: the IPv4
// address, or the IPv6 /64, since a single client can use many addresses
// within it. It returns the zero Prefix if RemoteAddr can't be parsed.
func Source(r *http.Request) netip.Prefix {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Prefix{}
	}
	addr := ap.Addr().Unmap()
	if addr.Is6() {
		return netip.PrefixFrom(addr, 64).Masked()
	}
	return netip.PrefixFrom(addr, 32)
}

// TorRemoteAddr is the RemoteAddr assigned to requests from Tor exit relays.
// It's in the IPv6 discard-only prefix (RFC 6666).
const TorRemoteAddr = "[100::]:0"

// TorSource is the [Source] of requests from Tor exit relays.
var TorSource = netip.MustParsePrefix("100::/64")

// torExits is the set of Tor exit relay addresses.
var torExits atomic.Pointer[torExitSet]

type torExitSet struct {
	exits map[netip.Addr]bool
	// lastModified is the Last-Modified header of the Onionoo response the set
	// was built from, sent back as If-Modified-Since.
	lastModified string
}

func isTorExit(remoteAddr string) bool {
	s := torExits.Load()
	if s == nil {
		return false
	}
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return false
	}
	return s.exits[ap.Addr().Unmap()]
}

// torExitListURL returns all relays that were running in the past week, with
// their exit policies. See https://metrics.torproject.org/onionoo.html.
//
// It doesn't filter on running=true or the Exit flag, because relays regularly
// drop out of a single consensus while clients keep using them for hours.
var torExitListURL = "https://onionoo.torproject.org/details?type=relay&fields=or_addresses,exit_addresses,exit_policy_summary,exit_policy_v6_summary"

// torExitListMaxSize is the largest Tor exit list RefreshTorExits accepts.
// The list is currently ~2 MB.
const torExitListMaxSize = 16 << 20 // 16 MiB

var torExitListClient = &http.Client{
	Timeout: 30 * time.Second,
}

// RefreshTorExits fetches the Tor exit list and replaces the current set.
//
// It always returns an outcome label for metrics: "success" or "unchanged"
// if the current set is up to date, or the failure mode.
func RefreshTorExits(ctx context.Context) (outcome string, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", torExitListURL, nil)
	if err != nil {
		return "request", err
	}
	req.Header.Set("User-Agent", "+https://filippo.io/sunlight")
	if s := torExits.Load(); s != nil && s.lastModified != "" {
		req.Header.Set("If-Modified-Since", s.lastModified)
	}
	resp, err := torExitListClient.Do(req)
	if err != nil {
		return "request", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return "unchanged", nil
	}
	if resp.StatusCode != http.StatusOK {
		return "status", fmt.Errorf("unexpected status: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, torExitListMaxSize+1))
	if err != nil {
		return "request", err
	}
	if len(body) > torExitListMaxSize {
		return "truncated", fmt.Errorf("list is larger than %d bytes", torExitListMaxSize)
	}
	var list struct {
		Relays []struct {
			OrAddresses         []string            `json:"or_addresses"`
			ExitAddresses       []string            `json:"exit_addresses"`
			ExitPolicySummary   map[string][]string `json:"exit_policy_summary"`
			ExitPolicyV6Summary map[string][]string `json:"exit_policy_v6_summary"`
		} `json:"relays"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return "invalid", err
	}
	exits := make(map[netip.Addr]bool)
	for _, r := range list.Relays {
		exitsV4, err := policyAccepts(r.ExitPolicySummary, 443)
		if err != nil {
			return "invalid", err
		}
		exitsV6, err := policyAccepts(r.ExitPolicyV6Summary, 443)
		if err != nil {
			return "invalid", err
		}
		// exit_addresses are IPv4 only.
		for _, a := range r.ExitAddresses {
			addr, err := netip.ParseAddr(a)
			if err != nil {
				return "invalid", fmt.Errorf("invalid exit address %q: %w", a, err)
			}
			if exitsV4 {
				exits[addr.Unmap()] = true
			}
		}
		for _, a := range r.OrAddresses {
			ap, err := netip.ParseAddrPort(a)
			if err != nil {
				return "invalid", fmt.Errorf("invalid OR address %q: %w", a, err)
			}
			addr := ap.Addr().Unmap()
			if addr.Is4() && exitsV4 || addr.Is6() && exitsV6 {
				exits[addr] = true
			}
		}
	}
	if len(exits) == 0 {
		return "empty", errors.New("empty list")
	}
	torExits.Store(&torExitSet{exits: exits, lastModified: resp.Header.Get("Last-Modified")})
	return "success", nil
}

// policyAccepts reports whether an Onionoo exit policy summary accepts port.
//
// A summary has either an "accept" or a "reject" list of ports and port ranges
// (like "80" or "6660-6667"), and the opposite applies to all other ports. A
// missing summary rejects everything.
func policyAccepts(summary map[string][]string, port int) (bool, error) {
	accept, isAccept := summary["accept"]
	reject, isReject := summary["reject"]
	if isAccept == isReject {
		if len(summary) == 0 {
			return false, nil
		}
		return false, fmt.Errorf("invalid exit policy summary %v", summary)
	}
	ranges := reject
	if isAccept {
		ranges = accept
	}
	for _, r := range ranges {
		lo, hi, isRange := strings.Cut(r, "-")
		if !isRange {
			hi = lo
		}
		l, err := strconv.ParseUint(lo, 10, 16)
		if err != nil {
			return false, fmt.Errorf("invalid exit policy port %q: %w", r, err)
		}
		h, err := strconv.ParseUint(hi, 10, 16)
		if err != nil {
			return false, fmt.Errorf("invalid exit policy port %q: %w", r, err)
		}
		if int(l) <= port && port <= int(h) {
			return isAccept, nil
		}
	}
	return !isAccept, nil
}
