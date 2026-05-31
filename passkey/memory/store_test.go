package memory_test

import (
	"testing"

	"github.com/JLugagne/egauth/passkey/memory"
	"github.com/JLugagne/egauth/passkey/storetest"
)

func TestMemoryStore_Contract(t *testing.T) {
	storetest.StoreContractTesting(t, memory.NewStore(), true)
}

func TestMemoryStore_StrictTenancy(t *testing.T) {
	storetest.StrictTenancyTesting(t, memory.NewStore(memory.WithStrictTenancy()))
}
