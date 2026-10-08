package memory_test

import (
	"testing"

	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/passkey"
	"github.com/JLugagne/egauth/store/passkey/memory"
	"github.com/JLugagne/egauth/store/passkey/storetest"
)

func TestStoreConformance(t *testing.T) {
	storetest.Seed(t, storetest.Fixtures{
		SeedV016: func(t *testing.T, s passkey.Store, c passkey.Credential) {
			t.Helper()
			s.(*memory.Store).AddV016(c)
		},
	})
	storetest.Run(t, func(*testing.T) passkey.Store { return memory.New() })
}

func TestStoreIsEphemeral(t *testing.T) {
	if got := memory.New().Durability(); got != store.Ephemeral {
		t.Fatalf("Durability = %v", got)
	}
}
