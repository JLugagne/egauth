package egauth

import (
	"net/http"

	"github.com/JLugagne/egauth/tools/archtest/testdata/g03/root/principal"
	"github.com/JLugagne/egauth/tools/archtest/testdata/uuid"
)

type UserResolver func(r *http.Request) (userID uuid.UUID, name, displayName, tenant string, ok bool)

type GoodResolver func(r *http.Request) (principal.TenantID, string)

type Config struct {
	Resolve  func(r *http.Request) (tenant, name string)
	Fine     func(r *http.Request) (principal.TenantID, string)
	resolve  func(a, b string)
	Nested   struct{ Inner func(a, b []byte) }
	Callback func(func(a, b string))
}

var Lookup = func(a, b string) {}

var lookupPrivate = func(a, b string) {}

func NonAdjacentResults() (tenant string, ok bool, name string) { return "", false, "" }

func TakesResolver(f func(r *http.Request) (tenant, name string)) {}

func GoodTakesResolver(f func(r *http.Request) (principal.TenantID, string)) {}

type unexportedResolver func(a, b string)
