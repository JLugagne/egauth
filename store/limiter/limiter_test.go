package limiter_test

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/limiter"
)

var (
	_ func(limiter.Limiter, context.Context, limiter.Key) (limiter.Decision, error) = limiter.Limiter.Allow
	_ func(limiter.Limiter) store.Durability                                        = limiter.Limiter.Durability
	_ func(limiter.Limiter, context.Context) (int64, error)                         = limiter.Limiter.ReapExpired
)

func TestZeroClassIsInvalidAndHasNoBudget(t *testing.T) {
	var zero limiter.Class
	if zero.Valid() || zero.String() != "invalid" || zero.Budget() != (limiter.Budget{}) {
		t.Fatal("the zero Class must be invalid and allow nothing")
	}
	if limiter.Class(200).Valid() {
		t.Fatal("an undeclared class must be invalid")
	}
}

func TestEveryDeclaredClassHasABudget(t *testing.T) {
	for c := limiter.LoginIdentifier; c.Valid(); c++ {
		b := c.Budget()
		if b.Burst < 1 || b.Refill <= 0 || c.String() == "invalid" {
			t.Fatalf("class %d lacks a budget or a name", c)
		}
	}
}

func TestKeyValidity(t *testing.T) {
	cases := []struct {
		name string
		k    limiter.Key
		want bool
	}{
		{"ok", limiter.Key{Class: limiter.LoginClient, Value: "203.0.113.0"}, true},
		{"zero class", limiter.Key{Value: "x"}, false},
		{"empty value", limiter.Key{Class: limiter.LoginClient}, false},
		{"too long", limiter.Key{Class: limiter.LoginClient, Value: strings.Repeat("a", 257)}, false},
		{"max length", limiter.Key{Class: limiter.LoginClient, Value: strings.Repeat("a", 256)}, true},
	}
	for _, c := range cases {
		if c.k.Valid() != c.want {
			t.Fatalf("%s: Valid = %v", c.name, !c.want)
		}
	}
}

func TestSelfTestClassMatchesTheStartupProbe(t *testing.T) {
	if limiter.SelfTest.String() != "selftest" || uint8(limiter.SelfTest) != 6 {
		t.Fatal("the startup probe class is selftest, persisted as 6")
	}
	if limiter.SelfTest.PerTenant() {
		t.Fatal("the startup probe is deployment-wide")
	}
}

func TestIdentifierBucketsArePerTenant(t *testing.T) {
	a, err := principal.ParseTenantID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := principal.ParseTenantID("tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []limiter.Class{limiter.LoginIdentifier, limiter.CodeRequestIdentifier} {
		ka := limiter.Key{Class: c, Tenant: a, Value: "alice@example.com"}
		kb := limiter.Key{Class: c, Tenant: b, Value: "alice@example.com"}
		if !c.PerTenant() || !ka.Valid() || !kb.Valid() || ka == kb {
			t.Fatalf("%v: an identifier in tenant A must not share the bucket of tenant B", c)
		}
	}
	for _, c := range []limiter.Class{limiter.LoginClient, limiter.CodeRequestClient, limiter.RegisterClient, limiter.SelfTest} {
		if c.PerTenant() {
			t.Fatalf("%v: client buckets are deployment-wide", c)
		}
		if (limiter.Key{Class: c, Tenant: a, Value: "203.0.113.0"}).Valid() {
			t.Fatalf("%v: a tenant on a deployment-wide class would split its budget per tenant", c)
		}
		if !(limiter.Key{Class: c, Value: "203.0.113.0"}).Valid() {
			t.Fatalf("%v: a deployment-wide key without a tenant must be valid", c)
		}
	}
}

func TestLimiterEmbedsBaseForTenantErasure(t *testing.T) {
	lt := reflect.TypeFor[limiter.Limiter]()
	for _, name := range []string{"Ping", "EraseTenant", "Durability", "ReapExpired", "Allow"} {
		if _, ok := lt.MethodByName(name); !ok {
			t.Fatalf("limiter.Limiter lacks %s: identifier buckets of an erased tenant would outlive EraseTenant", name)
		}
	}
	if !lt.Implements(reflect.TypeFor[store.Base]()) {
		t.Fatal("limiter.Limiter must embed store.Base")
	}
}

func TestStorageKeyNeverHoldsTheValue(t *testing.T) {
	a, err := principal.ParseTenantID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	k := limiter.Key{Class: limiter.LoginIdentifier, Tenant: a, Value: "alice@example.com"}
	sk := k.StorageKey()
	if bytes.Contains(sk, []byte("alice")) || bytes.Contains(sk, []byte("example.com")) {
		t.Fatalf("the storage key carries the identifier in clear: %q", sk)
	}
	if !bytes.HasPrefix(sk, limiter.TenantPrefix(limiter.LoginIdentifier, a)) {
		t.Fatal("EraseTenant could not find the bucket by its tenant prefix")
	}
	if len(sk) > 162 {
		t.Fatalf("storage key is %d bytes", len(sk))
	}
	long := limiter.Key{Class: limiter.LoginIdentifier, Tenant: a, Value: strings.Repeat("v", 256)}
	if len(long.StorageKey()) != len(sk) {
		t.Fatal("the storage key length must not depend on the value")
	}
}

func TestStorageKeysAreDistinct(t *testing.T) {
	ab, err := principal.ParseTenantID("ab")
	if err != nil {
		t.Fatal(err)
	}
	a, err := principal.ParseTenantID("a")
	if err != nil {
		t.Fatal(err)
	}
	keys := []limiter.Key{
		{Class: limiter.LoginIdentifier, Tenant: a, Value: "x"},
		{Class: limiter.LoginIdentifier, Tenant: ab, Value: "x"},
		{Class: limiter.CodeRequestIdentifier, Tenant: a, Value: "x"},
		{Class: limiter.LoginIdentifier, Value: "x"},
		{Class: limiter.LoginIdentifier, Tenant: a, Value: "y"},
		{Class: limiter.LoginClient, Value: "x"},
	}
	seen := map[string]limiter.Key{}
	for _, k := range keys {
		if prev, dup := seen[string(k.StorageKey())]; dup {
			t.Fatalf("%+v and %+v share a bucket", prev, k)
		}
		seen[string(k.StorageKey())] = k
	}
	if bytes.HasPrefix(keys[1].StorageKey(), limiter.TenantPrefix(limiter.LoginIdentifier, a)) {
		t.Fatal("erasing tenant a would also erase the buckets of tenant ab")
	}
}

func TestEphemeralBudgetIsDividedPerInstance(t *testing.T) {
	b := limiter.Budget{Burst: 10, Refill: 6 * time.Minute}
	if b.PerInstance(1) != b || b.PerInstance(0) != b {
		t.Fatal("a single instance enforces the whole budget")
	}
	if got := b.PerInstance(4); got != (limiter.Budget{Burst: 2, Refill: 24 * time.Minute}) {
		t.Fatalf("PerInstance(4) = %+v", got)
	}
	if got := b.PerInstance(50); got.Burst != 1 || got.Refill != 300*time.Minute {
		t.Fatalf("PerInstance(50) = %+v: a share never drops below one token", got)
	}
	var _ interface{ SetInstances(int) } = limiter.InstanceScaler(nil)
}
