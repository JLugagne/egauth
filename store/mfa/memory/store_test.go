package memory_test

import (
	"testing"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/mfa/memory"
	"github.com/JLugagne/egauth/store/mfa/storetest"
)

func TestStoreConformance(t *testing.T) {
	storetest.Seed(t, storetest.Fixtures{
		SeedV016: func(t *testing.T, s mfa.Store, sub principal.Subject, sealed []byte) {
			t.Helper()
			s.(*memory.Store).AddV016(sub, sealed, time.Now())
		},
	})
	storetest.Run(t, func(*testing.T) mfa.Store { return memory.New() })
}

func TestStoreIsEphemeral(t *testing.T) {
	if got := memory.New().Durability(); got != store.Ephemeral {
		t.Fatalf("Durability = %v", got)
	}
}
