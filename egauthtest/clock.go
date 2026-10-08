package egauthtest

import (
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/clock"
)

// Clock is a manually driven clock: it never advances on its own and is safe for concurrent use.
type Clock struct {
	t *clock.Test
}

// ReferenceTime is the instant NewClock(time.Time{}) starts at and the default instant of every
// time in a PrincipalSpec.
func ReferenceTime() time.Time {
	return time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
}

// NewClock returns a clock stopped at start, or at ReferenceTime when start is zero.
func NewClock(start time.Time) *Clock {
	if start.IsZero() {
		start = ReferenceTime()
	}
	return &Clock{t: clock.NewTest(start)}
}

// Now returns the instant the clock is stopped at.
func (c *Clock) Now() time.Time { return c.t.Now() }

// Set moves the clock to now, backwards or forwards.
func (c *Clock) Set(now time.Time) { c.t.Set(now) }

// Advance moves the clock forward by d; a negative d moves it back.
func (c *Clock) Advance(d time.Duration) { c.t.Advance(d) }

// Library returns the library clock that reads c, observing every Set and Advance. Pass it to
// memstore.NewWithClock so that store-side expiry follows c.
func (c *Clock) Library() egauth.TestClock { return c.t.Clock() }
