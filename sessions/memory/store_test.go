package memory

import (
	"testing"

	"github.com/JLugagne/egauth/sessions/storetest"
)

func TestStore(t *testing.T) {
	store := NewStore()
	storetest.StoreContractTesting(t, store, true)
}

func TestStrictTenancy(t *testing.T) {
	storetest.StrictTenancyTesting(t, NewStore(WithStrictTenancy()))
}
