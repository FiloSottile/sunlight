package ctlog

import (
	"fmt"
	"hash/maphash"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"filippo.io/sunlight/internal/frequent"
)

// sourceLimiter rate limits submission sources based on a budget that only some
// of their requests are charged against, as chosen by the caller.
//
// Each source has a budget of charges, which refills at a rate of one charge
// per interval. Every request is charged on admission, and the caller refunds
// the ones that turn out not to be chargeable, so that requests in flight count
// against the budget. Once the budget is exhausted, every request from the
// source is rejected, whether it would have been charged or not, until one
// charge's worth of budget has refilled or a charge is refunded.
type sourceLimiter struct {
	interval time.Duration
	burst    int

	mu   sync.Mutex
	sets [sourceLimiterSets][sourceLimiterWays]sourceLimiterEntry
}

type sourceLimiterEntry struct {
	source netip.Prefix
	// Theoretical Arrival Time (TAT) of a Generic Cell Rate Algorithm (GCRA)
	// rate limit. See https://letsencrypt.org/2025/01/30/scaling-rate-limits/.
	tat time.Time
}

const (
	sourceLimiterSets = 1024
	sourceLimiterWays = 8
)

// sourceLimiterSeed is randomized per process so that clients can't choose
// which set they land in.
var sourceLimiterSeed = maphash.MakeSeed()

var limitedSources = frequent.New(200)

// LimitedSourcesHandler is a debug endpoint that lists the 100 sources with the
// most requests rejected by the per-source rate limit, in the same format as
// the heavyhitter endpoints, with the log name and User-Agent of the latest
// rejected request from each source as the attribute.
func LimitedSourcesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	for _, item := range limitedSources.Top(100) {
		halfError := item.MaxError / 2
		fmt.Fprintf(w, "%d (± %d)\t%s [%s]\n", item.Count-halfError, halfError, item.Value, item.Latest)
	}
}

func sourceLimiterSet(source netip.Prefix) uint64 {
	return maphash.Comparable(sourceLimiterSeed, source) % sourceLimiterSets
}

// newSourceLimiter returns a limiter that lets each source sustain one charged
// request per interval, with a budget of burst charges on top of that before
// it's limited.
func newSourceLimiter(interval time.Duration, burst int) *sourceLimiter {
	return &sourceLimiter{
		interval: interval,
		burst:    burst,
	}
}

// sourceReceipt identifies a charge made by Allow, to refund it with.
type sourceReceipt struct {
	source netip.Prefix
	// tat is the end of the interval the charge occupies.
	tat time.Time
}

// Allow reports whether a request from source (see [clientaddr.Source])
// should be served, and if so charges it, returning a receipt to refund the
// charge with. Requests from an unknown (zero) source are always served.
func (l *sourceLimiter) Allow(source netip.Prefix) (receipt sourceReceipt, ok bool) {
	if !source.IsValid() {
		return sourceReceipt{}, true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.lookup(source)
	if e == nil {
		e = l.insert(source, now)
	}
	// The budget is drained if the TAT is further ahead than the window, which
	// is sized so that exactly burst requests can be charged at once before
	// the next request is rejected.
	window := l.interval * time.Duration(l.burst-1)
	if e.tat.After(now.Add(window)) {
		// The zero tat makes the receipt a no-op to refund.
		return sourceReceipt{source: source}, false
	}
	if e.tat.Before(now) {
		e.tat = now
	}
	e.tat = e.tat.Add(l.interval)
	return sourceReceipt{source: source, tat: e.tat}, true
}

// Refund returns the charge identified by receipt to its source's budget, for
// a request that turned out not to be chargeable.
func (l *sourceLimiter) Refund(receipt sourceReceipt) {
	// If the end of the charge's interval has already passed, the charge
	// drained on its own and there is nothing to refund.
	now := time.Now()
	if !receipt.tat.After(now) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.lookup(receipt.source)
	if e == nil {
		return
	}
	// A refund never creates credit beyond a full budget.
	e.tat = e.tat.Add(-l.interval)
	if e.tat.Before(now) {
		e.tat = now
	}
}

// lookup returns the entry for source, or nil if it isn't tracked. Entries
// whose TAT is in the past are as good as absent, but are returned anyway
// so callers can reuse the slot.
func (l *sourceLimiter) lookup(source netip.Prefix) *sourceLimiterEntry {
	set := &l.sets[sourceLimiterSet(source)]
	for i := range set {
		if set[i].source == source {
			return &set[i]
		}
	}
	return nil
}

// insert claims a slot for source in its set, and returns it with a zero TAT.
// It prefers an empty or expired slot, and otherwise evicts the entry with
// the earliest TAT.
func (l *sourceLimiter) insert(source netip.Prefix, now time.Time) *sourceLimiterEntry {
	set := &l.sets[sourceLimiterSet(source)]
	victim := &set[0]
	for i := range set {
		if set[i].tat.Before(now) {
			victim = &set[i]
			break
		}
		if set[i].tat.Before(victim.tat) {
			victim = &set[i]
		}
	}
	*victim = sourceLimiterEntry{source: source}
	return victim
}
