package memory_test

import (
	"testing"
	"time"

	"github.com/JLugagne/egauth/keystore"
	"github.com/JLugagne/egauth/keystore/keystoretest"
	"github.com/JLugagne/egauth/keystore/memory"
)

// TestMemoryStoreConformance runs the full keystore conformance + adversarial isolation suite
// against the in-memory backend.
func TestMemoryStoreConformance(t *testing.T) {
	keystoretest.StoreContractTesting(t, func(now func() time.Time) keystore.Store {
		return memory.New(memory.WithClock(now))
	})
}
