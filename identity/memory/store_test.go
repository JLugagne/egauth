package memory_test

import (
	"testing"

	"github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/identity/storetest"
)

func TestStoreContract(t *testing.T) {
	store := memory.NewStore()
	storetest.StoreContractTesting(t, store, true)
	storetest.StoreDisableEnableContract(t, store, "tenant-A")
	storetest.StoreDeleteAuthGateContract(t, store, "tenant-A")
}
