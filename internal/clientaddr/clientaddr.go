// Package clientaddr determines the IP address of the client behind an HTTP
// request, optionally taking into account a reverse proxy.
package clientaddr

import (
	"net/http"
	"net/netip"
	"strings"
)

// NewHandler returns a handler that, if trustReverseProxy is true, replaces
// the RemoteAddr of each request with the last entry of the X-Forwarded-For
// header.
func NewHandler(trustReverseProxy bool, next http.Handler) http.Handler {
	if !trustReverseProxy {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if addr, ok := forwardedFor(r); ok {
			r.RemoteAddr = netip.AddrPortFrom(addr, 0).String()
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
