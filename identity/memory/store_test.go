package memory_test

import (
	"testing"

	"github.com/JLugagne/libauth/identity/memory"
	"github.com/JLugagne/libauth/identity/storetest"
)

func TestStoreContract(t *testing.T) {
	store := memory.NewStore()
	storetest.StoreContractTesting(t, store, true)
}
