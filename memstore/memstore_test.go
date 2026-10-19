package memstore_test

import (
	"context"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/identity"

	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/memstore"
	"github.com/JLugagne/egauth/store"
)

func testKEK(t testing.TB) kek.KEK {
	t.Helper()
	k, err := kek.NewLocal(testKEKKey)
	require.NoError(t, err)
	return k
}

func TestNewFillsEveryStorageField(t *testing.T) {
	s := memstore.New(testKEK(t))
	v := reflect.ValueOf(s)
	for i := 0; i < v.NumField(); i++ {
		require.False(t, v.Field(i).IsNil(), "Storage.%s is nil", v.Type().Field(i).Name)
	}
}

func TestEveryStoreIsEphemeralAndPingsClean(t *testing.T) {
	s := memstore.New(testKEK(t))
	v := reflect.ValueOf(s)
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		b, ok := v.Field(i).Interface().(store.Base)
		require.True(t, ok, "Storage.%s does not embed store.Base", name)
		require.Equal(t, store.Ephemeral, b.Durability(), "Storage.%s", name)
		require.NoError(t, b.Ping(context.Background()), "Storage.%s", name)
	}
}

func TestEachCallReturnsIndependentStores(t *testing.T) {
	a, b := memstore.New(testKEK(t)), memstore.New(testKEK(t))
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	for i := 0; i < va.NumField(); i++ {
		require.NotSame(t, va.Field(i).Interface(), vb.Field(i).Interface(), "Storage.%s is shared", va.Type().Field(i).Name)
	}
}

func TestFederationReadsLinksFromTheSameIdentityStore(t *testing.T) {
	ctx := context.Background()
	s := memstore.New(testKEK(t))
	tn, err := principal.ParseTenantID("tenant-a")
	require.NoError(t, err)
	mail, err := identity.NewIdentifier(identity.IdentifierEmail, "alice@example.com")
	require.NoError(t, err)
	applied, err := s.Identity.Apply(ctx, identity.CreateVerified{
		Tenant: tn, Email: mail,
		Federated: identity.FederatedIdentity{Provider: "google", ProviderSubject: "g-1", Authority: "static", ProviderEmail: mail, ProviderEmailVerified: true},
	})
	require.NoError(t, err)
	got, err := s.Federation.FindLinked(ctx, tn, federation.LinkKey{Provider: "google", ProviderSubject: "g-1"})
	require.NoError(t, err)
	require.Equal(t, applied.Subject, got.Subject)
}

var testKEKKey = randomKEKKey()

func randomKEKKey() []byte {
	k := make([]byte, kek.KeyLength)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	return k
}
