package egauth

import "net/http"

type resolver func(r *http.Request) (tenant, name string)

type Hooks struct {
	Resolve resolver
	Ptr     *func(tenant, name string)
	Many    []func(tenant, name string)
	ByName  map[string]func(tenant, name string)
	Pipe    chan func(a, b []byte)
	Fine    *func(r *http.Request) (int, string)
}

func SetResolver(r resolver) {}

func GetResolver() resolver { return nil }

type AliasResolver = func(*http.Request) (tenant, name string)

type GoodAlias = func(*http.Request) (int, string)

type svc struct{}

func (svc) Do(a, b string) {}

func (svc) fine(a, b string) {}

func NewSvc() *svc { return nil }

type unreachableSvc struct{}

func (unreachableSvc) Do(a, b string) {}

func AnonLookup() interface{ Lookup(a, b string) } { return nil }
