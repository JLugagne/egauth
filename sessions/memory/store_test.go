package memory

import (
	"testing"

	"github.com/JLugagne/egauth/sessions/storetest"
)

func TestStore(t *testing.T) {
	store := NewStore()
	storetest.StoreContractTesting(t, store, true)
}
