package identitysvc

import (
	"testing"
	"time"
)

func TestPickSpan(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(h int) time.Time { return base.Add(time.Duration(h) * time.Hour) }
	full := [revertSpans]revertSpan{
		{live: true, from: at(0), to: at(1)},
		{live: true, from: at(10), to: at(11)},
		{live: true, from: at(20), to: at(21)},
		{live: true, from: at(30), to: at(31)},
		{live: true, from: at(40), to: at(41)},
	}
	cases := []struct {
		name     string
		all      [revertSpans]revertSpan
		from, to time.Time
		slot     int
		widens   bool
	}{
		{"overlap merges in place", full, at(20), at(25), 2, false},
		{"touching merges in place", full, at(31), at(35), 3, false},
		{"containing merges in place", full, at(9), at(12), 1, false},
		{"disjoint on a full set widens the latest", full, at(50), at(51), 4, true},
		{"disjoint with room takes a free slot", [revertSpans]revertSpan{full[0], {}, full[2]}, at(50), at(51), 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			slot, widens := pickSpan(c.all, c.from, c.to)
			if slot != c.slot || widens != c.widens {
				t.Fatalf("pickSpan = (%d, %v), want (%d, %v)", slot, widens, c.slot, c.widens)
			}
		})
	}
}
