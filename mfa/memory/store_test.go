package memory_test

import (
	"testing"

	"github.com/JLugagne/egauth/mfa/memory"
	"github.com/JLugagne/egauth/mfa/storetest"
)

func TestMemoryStore_Contract(t *testing.T) {
	storetest.StoreContractTesting(t, memory.NewStore(), true)
}

func TestMemoryStore_StrictTenancy(t *testing.T) {
	storetest.StrictTenancyTesting(t, memory.NewStore(memory.WithStrictTenancy()))
}
