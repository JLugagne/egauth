package ceremony

import (
	"testing"

	"github.com/JLugagne/egauth/internal/core"
)

func TestPendingTTLMirrorsCore(t *testing.T) {
	if pendingTTL != core.PendingTTL {
		t.Fatalf("ceremony pendingTTL %s drifted from core.PendingTTL %s", pendingTTL, core.PendingTTL)
	}
}
