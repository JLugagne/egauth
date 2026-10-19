package journeytest_test

import (
	"sync"
	"testing"
	"time"
)

const exhaustiveBudget = 25 * time.Minute

var (
	exhaustiveOnce sync.Once
	exhaustiveFull bool
)

func exhaustive(t *testing.T) bool {
	t.Helper()
	if testing.Short() {
		return false
	}
	exhaustiveOnce.Do(func() {
		d, ok := t.Deadline()
		exhaustiveFull = !ok || time.Until(d) >= exhaustiveBudget
	})
	if !exhaustiveFull {
		t.Logf("short subset only: the exhaustive journeys need about 20 minutes, run go test -timeout 40m ./internal/journeytest/ for all of them")
	}
	return exhaustiveFull
}
