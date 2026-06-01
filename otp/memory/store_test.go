package memory_test

import (
	"testing"

	"github.com/JLugagne/egauth/otp/memory"
	"github.com/JLugagne/egauth/otp/storetest"
)

func TestMemoryStore_Contract(t *testing.T) {
	storetest.StoreContractTesting(t, memory.NewStore(), true)
}
