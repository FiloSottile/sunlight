package hyperloglog

import (
	"fmt"
	"math"
	"testing"
	"time"
)

func add(s *Sketch, prefix string, n int) {
	for i := range n {
		s.Add(fmt.Sprintf("%s%d", prefix, i))
	}
}

func checkEstimate(t *testing.T, got float64, want int) {
	t.Helper()
	// Allow three standard errors of the 1.6% HyperLogLog error, and a small
	// absolute slack for the linear counting range.
	tolerance := 0.05*float64(want) + 2
	if math.Abs(got-float64(want)) > tolerance {
		t.Errorf("estimate = %.0f, want %d ± %.0f", got, want, tolerance)
	}
}

func TestSketch(t *testing.T) {
	for _, n := range []int{0, 1, 10, 100, 1000, 10000, 100000, 1000000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			var s Sketch
			add(&s, "item-", n)
			checkEstimate(t, s.Estimate(), n)
			// Adding the same values again doesn't change the estimate.
			e := s.Estimate()
			add(&s, "item-", n)
			if s.Estimate() != e {
				t.Errorf("estimate changed after adding duplicates: %.0f != %.0f", s.Estimate(), e)
			}
		})
	}
}

func TestMerge(t *testing.T) {
	var a, b Sketch
	add(&a, "a-", 10000)
	add(&b, "b-", 10000)
	add(&b, "a-", 5000) // overlaps with a
	a.Merge(&b)
	checkEstimate(t, a.Estimate(), 20000)
}

func TestWindow(t *testing.T) {
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	w := NewWindow(5, time.Minute)
	w.now = func() time.Time { return now }

	for i := range 1000 {
		w.Add(fmt.Sprintf("first-%d", i))
	}
	checkEstimate(t, w.Estimate(), 1000)

	now = now.Add(2 * time.Minute)
	for i := range 1000 {
		w.Add(fmt.Sprintf("second-%d", i))
	}
	checkEstimate(t, w.Estimate(), 2000)

	// Two minutes later, the first batch is four minutes old, still in the
	// window of five buckets.
	now = now.Add(2 * time.Minute)
	checkEstimate(t, w.Estimate(), 2000)

	// After five minutes the first batch is out, and the second is not.
	now = now.Add(time.Minute)
	checkEstimate(t, w.Estimate(), 1000)

	// Far in the future, everything is out, however many buckets were skipped.
	now = now.Add(time.Hour)
	checkEstimate(t, w.Estimate(), 0)
}
