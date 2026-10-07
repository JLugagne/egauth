// Package clock is the single owner of wall-clock reads: no other package calls time.Now,
// time.Since or time.Until. The composition object holds one Clock and hands it to every
// component; there is no package-level clock.
package clock

import (
	"sync"
	"time"
)

// Clock reads the current time. The zero value reads the wall clock; a Clock obtained from
// Test.Clock reads that test clock instead. A Clock is a small value, safe to copy and to use
// from several goroutines.
type Clock struct {
	test *Test
}

func (c Clock) Now() time.Time {
	if c.test != nil {
		return c.test.Now()
	}
	return time.Now()
}

func (c Clock) Since(t time.Time) time.Duration {
	return c.Now().Sub(t)
}

func (c Clock) Until(t time.Time) time.Duration {
	return t.Sub(c.Now())
}

// Test is a manually driven clock for tests. It never advances on its own. It is safe for
// concurrent use; every Clock it hands out observes Set and Advance immediately.
type Test struct {
	mu  sync.Mutex
	now time.Time
}

// NewTest returns a test clock stopped at start.
func NewTest(start time.Time) *Test {
	return &Test{now: start}
}

// Clock returns a Clock that reads this test clock.
func (t *Test) Clock() Clock {
	return Clock{test: t}
}

// Now returns the time the test clock is stopped at.
func (t *Test) Now() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.now
}

// Set moves the test clock to now, backwards or forwards.
func (t *Test) Set(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.now = now
}

// Advance moves the test clock forward by d (backwards when d is negative).
func (t *Test) Advance(d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.now = t.now.Add(d)
}
