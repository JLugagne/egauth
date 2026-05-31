package memory

import (
	"testing"

	"github.com/JLugagne/egauth/tokens/storetest"
)

type CustomClaims struct {
	Foo string `json:"foo"`
}

func TestStore(t *testing.T) {
	store := NewStore[CustomClaims]()
	storetest.StoreContractTesting(t, store, true, CustomClaims{Foo: "bar"})
}

func TestStrictTenancy(t *testing.T) {
	storetest.StrictTenancyTesting(t, NewStore[CustomClaims](WithStrictTenancy()), CustomClaims{Foo: "bar"})
}
