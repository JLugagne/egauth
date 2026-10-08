package egauth

import (
	"context"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g03/root/principal"
	"github.com/JLugagne/egauth/tools/archtest/testdata/uuid"
)

func BadStrings(tenant, name string) {}

func BadUUIDs(a, b uuid.UUID) {}

func BadBytes(a, b []byte) {}

func BadInts(a, b int) {}

func BadMixedInts(a int64, b int64) {}

func BadTenants(a, b principal.TenantID) {}

func BadResults() (string, string) { return "", "" }

func GoodSeparated(a string, n int, b string) {}

func GoodTyped(t principal.TenantID, u uuid.UUID, s string) {}

func GoodContexts(a, b context.Context) {}

func GoodMixedInts(a int, b int64) {}

func GoodResults() (string, error) { return "", nil }

func unexportedBad(a, b string) {}

type Svc struct{}

func (Svc) BadMethod(a, b string) {}

func (Svc) unexportedMethod(a, b string) {}

type hidden struct{}

func (hidden) Exported(a, b string) {}

type Resolver interface {
	Lookup(tenant, name string) error
}

type internalResolver interface {
	find(a, b []byte)
}

type Good interface {
	Lookup(tenant principal.TenantID, name string) error
}
