// Package hyperloglog implements the HyperLogLog algorithm for estimating the
// number of distinct items in a stream of data, and a sliding window of it.
package hyperloglog

import (
	"hash/maphash"
	"math"
	"math/bits"
	"sync"
	"time"
)

// p is the number of hash bits that select a register. 2^p registers of one
// byte each give a standard error of 1.04/√(2^p), about 1.6%.
const p = 12

// A Sketch estimates the number of distinct strings added to it. It is not safe
// for concurrent use.
type Sketch struct {
	reg [1 << p]uint8
}

var seed = maphash.MakeSeed()

// Add adds v to the sketch.
func (s *Sketch) Add(v string) {
	h := maphash.String(seed, v)
	i := h >> (64 - p)
	// A register holds the highest number of leading zeros observed in the
	// bits after the index, plus one. The sentinel bit caps it at 64 - p + 1.
	r := uint8(bits.LeadingZeros64(h<<p|1<<(p-1)) + 1)
	s.reg[i] = max(s.reg[i], r)
}

// Merge adds to s all the values added to o.
func (s *Sketch) Merge(o *Sketch) {
	for i := range s.reg {
		s.reg[i] = max(s.reg[i], o.reg[i])
	}
}

// Reset removes all values from s.
func (s *Sketch) Reset() {
	s.reg = [1 << p]uint8{}
}

// Estimate returns the estimated number of distinct values added to s.
func (s *Sketch) Estimate() float64 {
	m := float64(len(s.reg))
	var sum float64
	var zeros int
	for _, r := range s.reg {
		sum += 1 / float64(uint64(1)<<r)
		if r == 0 {
			zeros++
		}
	}
	e := 0.7213 / (1 + 1.079/m) * m * m / sum
	// Linear counting on the empty registers is more accurate for small
	// cardinalities.
	if e <= 2.5*m && zeros > 0 {
		e = m * math.Log(m/float64(zeros))
	}
	return e
}

// A Window estimates the number of distinct strings added to it recently.
// Values are counted in n buckets of duration d each, and the oldest bucket is
// dropped as time passes, so the estimate covers the last (n-1)×d to n×d. It
// is safe for concurrent use.
type Window struct {
	mu      sync.Mutex
	buckets []Sketch
	counts  []int     // total values added to each bucket
	current int       // index into buckets
	start   time.Time // start of the current bucket
	d       time.Duration
	now     func() time.Time
}

// NewWindow returns a Window of n buckets of duration d each.
func NewWindow(n int, d time.Duration) *Window {
	return &Window{buckets: make([]Sketch, n), counts: make([]int, n), d: d, now: time.Now}
}

// advance resets a bucket for each bucket boundary crossed since the last call,
// and makes the latest one current.
func (w *Window) advance() {
	now := w.now()
	if w.start.IsZero() {
		w.start = now
		return
	}
	elapsed := int(now.Sub(w.start) / w.d)
	if elapsed <= 0 {
		return
	}
	for range min(elapsed, len(w.buckets)) {
		w.current = (w.current + 1) % len(w.buckets)
		w.buckets[w.current].Reset()
		w.counts[w.current] = 0
	}
	w.start = w.start.Add(time.Duration(elapsed) * w.d)
}

// Add adds v to the window.
func (w *Window) Add(v string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.advance()
	w.buckets[w.current].Add(v)
	w.counts[w.current]++
}

// Estimate returns the estimated number of distinct values added to the window
// during the last (n-1)×d to n×d, and the total number of values added over
// the same span, so that the two can be compared exactly.
func (w *Window) Estimate() (distinct float64, total int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.advance()
	var s Sketch
	for i := range w.buckets {
		s.Merge(&w.buckets[i])
		total += w.counts[i]
	}
	return s.Estimate(), total
}
