package journeytest_test

import (
	"testing"
	"time"
)

const exhaustiveBudget = 25 * time.Minute

func exhaustive(t *testing.T) bool {
	t.Helper()
	if testing.Short() {
		return false
	}
	if d, ok := t.Deadline(); ok && time.Until(d) < exhaustiveBudget {
		t.Logf("short subset only: the exhaustive journeys need about 20 minutes, run go test -timeout 40m ./internal/journeytest/ for all of them")
		return false
	}
	return true
}
