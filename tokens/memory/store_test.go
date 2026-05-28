package memory

import (
	"testing"

	"github.com/JLugagne/libauth/tokens/storetest"
)

type CustomClaims struct {
	Foo string `json:"foo"`
}

func TestStore(t *testing.T) {
	store := NewStore[CustomClaims]()
	storetest.StoreContractTesting(t, store, true, CustomClaims{Foo: "bar"})
}
