package memory_test

import (
	"testing"

	"github.com/JLugagne/libauth/passkey/memory"
	"github.com/JLugagne/libauth/passkey/storetest"
)

func TestMemoryStore_Contract(t *testing.T) {
	storetest.StoreContractTesting(t, memory.NewStore(), true)
}
