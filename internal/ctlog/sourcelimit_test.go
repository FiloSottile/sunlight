package ctlog

import (
	"fmt"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

func TestSourceLimiter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = 60 * time.Millisecond
		const burst = 1000
		l := newSourceLimiter(interval, burst)
		src := "[2001:db8::1]:1234"

		// A source can burn a full burst of charges before being limited.
		for i := range burst {
			if _, ok := l.Allow(src); !ok {
				t.Fatalf("source limited after %d charges", i)
			}
		}
		if _, ok := l.Allow(src); ok {
			t.Fatal("source not limited after a full burst")
		}

		// Rejected requests are not charged, so they don't delay the refill.
		for i := range burst * 10 {
			if _, ok := l.Allow(src); ok {
				t.Fatalf("source allowed after %d rejections", i)
			}
		}

		// One request is allowed once an interval has passed, and not before.
		time.Sleep(interval - time.Nanosecond)
		if _, ok := l.Allow(src); ok {
			t.Fatal("source allowed before an interval passed")
		}
		time.Sleep(time.Nanosecond)
		if _, ok := l.Allow(src); !ok {
			t.Fatal("source not allowed after an interval passed")
		}
		if _, ok := l.Allow(src); ok {
			t.Fatal("second request allowed after one interval")
		}

		// A full window later, the whole budget has refilled.
		time.Sleep(interval * burst)
		for i := range burst {
			if _, ok := l.Allow(src); !ok {
				t.Fatalf("source limited after %d charges", i)
			}
		}
		if _, ok := l.Allow(src); ok {
			t.Fatal("source not limited after a full burst")
		}

		// Sustained submissions at the refill rate are allowed indefinitely.
		for range burst * 10 {
			time.Sleep(interval)
			if _, ok := l.Allow(src); !ok {
				t.Fatal("source limited at the sustained rate")
			}
		}
		// Slightly faster than the refill rate eventually gets limited.
		limited := false
		for range burst * 100 {
			time.Sleep(interval * 99 / 100)
			if _, ok := l.Allow(src); !ok {
				limited = true
				break
			}
		}
		if !limited {
			t.Fatal("source not limited above the sustained rate")
		}
	})
}

func TestSourceLimiterRefund(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = 60 * time.Millisecond
		const burst = 1000
		l := newSourceLimiter(interval, burst)
		src := "192.0.2.1:1234"

		// Refunded requests don't count against the budget.
		for range burst * 10 {
			receipt, ok := l.Allow(src)
			if !ok {
				t.Fatal("source limited while refunding every request")
			}
			l.Refund(receipt)
		}
		var receipts []sourceReceipt
		for i := range burst {
			receipt, ok := l.Allow(src)
			if !ok {
				t.Fatalf("source limited after %d charges", i)
			}
			receipts = append(receipts, receipt)
		}
		if _, ok := l.Allow(src); ok {
			t.Fatal("source not limited after a full burst")
		}

		// Requests in flight are charged, so a limited source stays limited
		// while they are pending, and a refund reopens one slot.
		l.Refund(receipts[0])
		if _, ok := l.Allow(src); !ok {
			t.Fatal("source not allowed after a refund")
		}
		if _, ok := l.Allow(src); ok {
			t.Fatal("source allowed after the refunded slot was reused")
		}

		// A refund never creates credit beyond a full budget, even if a
		// receipt is refunded more than once.
		for _, receipt := range receipts {
			l.Refund(receipt)
		}
		for _, receipt := range receipts {
			l.Refund(receipt)
		}
		for i := range burst {
			if _, ok := l.Allow(src); !ok {
				t.Fatalf("source limited after %d charges", i)
			}
		}
		if _, ok := l.Allow(src); ok {
			t.Fatal("source not limited after a full burst")
		}

		// A charge that already drained on its own can't be refunded: after
		// the budget refilled and was consumed again, refunding the stale
		// receipts doesn't allow a larger burst.
		receipts = receipts[:0]
		time.Sleep(interval * burst)
		for i := range burst {
			receipt, ok := l.Allow(src)
			if !ok {
				t.Fatalf("source limited after %d charges", i)
			}
			receipts = append(receipts, receipt)
		}
		time.Sleep(interval * burst)
		for i := range burst {
			if _, ok := l.Allow(src); !ok {
				t.Fatalf("source limited after %d charges", i)
			}
		}
		for _, receipt := range receipts {
			l.Refund(receipt)
		}
		if _, ok := l.Allow(src); ok {
			t.Fatal("source allowed after refunding drained charges")
		}

		// A refund never creates credit beyond a full budget: refunding after
		// the budget refilled leaves it full, not overfull.
		time.Sleep(interval * burst)
		receipt, ok := l.Allow(src)
		if !ok {
			t.Fatal("source limited after a full window")
		}
		time.Sleep(interval * burst)
		receipt.tat = receipt.tat.Add(interval * burst * 2)
		l.Refund(receipt)
		for i := range burst {
			if _, ok := l.Allow(src); !ok {
				t.Fatalf("source limited after %d charges", i)
			}
		}
		if _, ok := l.Allow(src); ok {
			t.Fatal("source not limited after a full burst")
		}
	})
}

func TestSourceLimiterUnparseable(t *testing.T) {
	l := newSourceLimiter(time.Second, 1)
	for range 10 {
		receipt, ok := l.Allow("not an address")
		if !ok {
			t.Fatal("unparseable address limited")
		}
		if receipt != (sourceReceipt{}) {
			t.Fatal("unparseable address charged")
		}
		l.Refund(receipt)
	}
}

func TestSourceLimiterEviction(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const interval = time.Second
		const burst = 10
		l := newSourceLimiter(interval, burst)

		// Find enough sources that hash to the same set to overflow it.
		var sources []string
		var prefixes []netip.Prefix
		target := sourceLimiterSet(netip.MustParsePrefix("192.0.2.0/32"))
		for i := 0; len(sources) < sourceLimiterWays+2; i++ {
			src := fmt.Sprintf("10.%d.%d.%d:1234", i>>16, i>>8&0xff, i&0xff)
			prefix, ok := sourcePrefix(src)
			if !ok {
				t.Fatalf("sourcePrefix(%q) failed", src)
			}
			if sourceLimiterSet(prefix) == target {
				sources = append(sources, src)
				prefixes = append(prefixes, prefix)
			}
		}

		// Fill the set with live entries, the first one being the most
		// offending.
		for i, src := range sources[:sourceLimiterWays] {
			charges := 2
			if i == 0 {
				charges = burst
			}
			for j := range charges {
				if _, ok := l.Allow(src); !ok {
					t.Fatalf("%v limited after %d charges", src, j)
				}
			}
		}

		// A new source evicts one of the least offending entries, but never
		// the most offending one.
		if _, ok := l.Allow(sources[sourceLimiterWays]); !ok {
			t.Fatal("new source limited")
		}
		if l.lookup(prefixes[sourceLimiterWays]) == nil {
			t.Fatal("new source not inserted")
		}
		if l.lookup(prefixes[0]) == nil {
			t.Fatal("most offending source evicted")
		}
		evicted := 0
		for _, prefix := range prefixes[1:sourceLimiterWays] {
			if l.lookup(prefix) == nil {
				evicted++
			}
		}
		if evicted != 1 {
			t.Fatalf("evicted %d entries, want 1", evicted)
		}

		// Expired entries are reused before live ones are evicted.
		time.Sleep(time.Hour)
		receipt, ok := l.Allow(sources[sourceLimiterWays+1])
		if !ok {
			t.Fatal("new source limited")
		}
		e := l.lookup(prefixes[sourceLimiterWays+1])
		if e == nil {
			t.Fatal("new source not inserted")
		}
		if want := time.Now().Add(interval); !e.tat.Equal(want) || !receipt.tat.Equal(want) {
			t.Errorf("reused entry tat = %v, receipt tat = %v, want %v", e.tat, receipt.tat, want)
		}
	})
}

func TestSourcePrefix(t *testing.T) {
	tests := []struct {
		remoteAddr string
		want       string
	}{
		{"192.0.2.1:1234", "192.0.2.1/32"},
		{"[::ffff:192.0.2.1]:1234", "192.0.2.1/32"},
		{"[2001:db8:1:2:3:4:5:6]:1234", "2001:db8:1:2::/64"},
		{"[2001:db8:1:2::]:1234", "2001:db8:1:2::/64"},
		{"[fe80::1%eth0]:1234", "fe80::/64"},
		{"192.0.2.1", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.remoteAddr, func(t *testing.T) {
			got, ok := sourcePrefix(tt.remoteAddr)
			if tt.want == "" {
				if ok {
					t.Fatalf("sourcePrefix(%q) = %v, want failure", tt.remoteAddr, got)
				}
				return
			}
			if !ok || got.String() != tt.want {
				t.Fatalf("sourcePrefix(%q) = %v, %v, want %v", tt.remoteAddr, got, ok, tt.want)
			}
		})
	}
}

func BenchmarkSourceLimiter(b *testing.B) {
	l := newSourceLimiter(60*time.Millisecond, 1000)
	var sources [64]string
	for i := range sources {
		sources[i] = fmt.Sprintf("[2001:db8:%x::1]:1234", i)
	}
	for i := range b.N {
		src := sources[i%len(sources)]
		if receipt, ok := l.Allow(src); ok && i%2 == 0 {
			l.Refund(receipt)
		}
	}
}
