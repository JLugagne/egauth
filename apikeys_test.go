package egauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/keys"
)

func TestAPIKeysCreateRefusesClaimsBeyondTheCallers(t *testing.T) {
	w := newFacadeWorld(t)
	_, by, _ := w.user("alice@example.com")
	ctx := context.Background()
	for name, req := range map[string]egauth.APIKeyRequest{
		"role":  {Kind: "service", Roles: []string{"admin"}, Lifetime: defaultExpiry()},
		"scope": {Kind: "service", Scopes: []string{"items:read", "items:delete"}, Lifetime: defaultExpiry()},
		"group": {Kind: "service", Groups: []string{"ops"}, Lifetime: defaultExpiry()},
	} {
		_, err := w.a.APIKeys().Create(ctx, by, req)
		require.ErrorIs(t, err, egauth.ErrClaimsNotSubset, name)
	}
	list, err := w.a.APIKeys().List(ctx, by)
	require.NoError(t, err)
	require.Empty(t, list)
}

func TestAPIKeysCreatedKeyServesProtectAPIWithItsGrant(t *testing.T) {
	w := newFacadeWorld(t)
	sub, by, _ := w.user("alice@example.com")
	ctx := context.Background()
	s := &seen{}
	h := w.build(w.a.Routes().ProtectAPI("GET /api/items", s.handler, egauth.Kinds("service"), egauth.RequireAnyScope("items:read")))

	created, err := w.a.APIKeys().Create(ctx, by, egauth.APIKeyRequest{
		Kind: "service", Name: "ci", Scopes: []string{"items:read", "items:read"}, Lifetime: defaultExpiry(),
	})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(created.Reveal(), egauth.ConfigOf(w.a).Modules.APIKeys.Prefix+"_"))
	require.Equal(t, []string{"items:read"}, created.Info.Scopes)
	require.Equal(t, sub, created.Info.Owner)
	require.True(t, w.clk.Now().Add(egauth.DefaultAPIKeyLifetime).Equal(created.Info.ExpiresAt))

	rec := w.request(h, http.MethodGet, "/api/items", credentials{bearer: created.Reveal()})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	p := s.last(t)
	require.Equal(t, []string{"items:read"}, p.Claims().Scopes)
	require.Empty(t, p.Claims().Roles, "the key was granted no role")
	require.Equal(t, "pro", p.Claims().Custom.Plan, "Custom comes from the owner")
	require.Len(t, w.sink.of(event.APIKeyCreated), 1)

	list, err := w.a.APIKeys().List(ctx, by)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, created.Info.ID, list[0].ID)

	require.NoError(t, w.a.APIKeys().Revoke(ctx, by, created.Info.ID))
	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/api/items", credentials{bearer: created.Reveal()}).Code)
	list, err = w.a.APIKeys().List(ctx, by)
	require.NoError(t, err)
	require.Empty(t, list)
	require.Len(t, w.sink.of(event.APIKeyRevoked), 1)
}

func TestAPIKeysCarryNoCustomClaims(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeFor[egauth.APIKeyRequest](), reflect.TypeFor[egauth.APIKeyInfo]()} {
		for i := range typ.NumField() {
			require.NotEqual(t, "Custom", typ.Field(i).Name, typ.String())
		}
	}
}

func TestAPIKeysRevokeAndListActOnTheCallersKeysOnly(t *testing.T) {
	w := newFacadeWorld(t)
	_, alice, _ := w.user("alice@example.com")
	_, bob, _ := w.user("bob@example.com")
	ctx := context.Background()
	key, err := w.a.APIKeys().Create(ctx, alice, egauth.APIKeyRequest{Kind: "pat", Lifetime: keys.NeverExpire()})
	require.NoError(t, err)
	require.True(t, key.Info.ExpiresAt.IsZero())
	require.ErrorIs(t, w.a.APIKeys().Revoke(ctx, bob, key.Info.ID), store.ErrNotFound)
	list, err := w.a.APIKeys().List(ctx, bob)
	require.NoError(t, err)
	require.Empty(t, list)
	list, err = w.a.APIKeys().List(ctx, alice)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.ErrorIs(t, w.a.APIKeys().Revoke(ctx, alice, uuid.New()), store.ErrNotFound)
}

func TestAPIKeysCreateRefusesAnInvalidRequest(t *testing.T) {
	w := newFacadeWorld(t)
	_, by, _ := w.user("alice@example.com")
	ctx := context.Background()
	zero, err := keys.ExpireAfter(0)
	require.NoError(t, err)
	for name, req := range map[string]egauth.APIKeyRequest{
		"unknown kind":   {Kind: "robot", Lifetime: defaultExpiry()},
		"zero lifetime":  {Kind: "service"},
		"lifetime over":  {Kind: "service", Lifetime: zero},
		"long name":      {Kind: "service", Name: strings.Repeat("n", 129), Lifetime: defaultExpiry()},
		"control name":   {Kind: "service", Name: "ci\nforged", Lifetime: defaultExpiry()},
		"bidi name":      {Kind: "service", Name: "ci\u202egpj.exe", Lifetime: defaultExpiry()},
		"zero-width":     {Kind: "service", Name: "c\u200bi", Lifetime: defaultExpiry()},
		"invalid utf-8":  {Kind: "service", Name: "ci\xff", Lifetime: defaultExpiry()},
		"blank claim":    {Kind: "service", Scopes: []string{""}, Lifetime: defaultExpiry()},
		"blank grouping": {Kind: "service", Groups: []string{""}, Lifetime: defaultExpiry()},
	} {
		_, err := w.a.APIKeys().Create(ctx, by, req)
		require.ErrorIs(t, err, egauth.ErrInvalidRequest, name)
	}
}

func TestAPIKeysNeedAFreshSessionAndTheModule(t *testing.T) {
	w := newFacadeWorld(t)
	_, by, _ := w.user("alice@example.com")
	w.clk.Advance(egauth.ConfigOf(w.a).Policy.ReauthWindow + time.Second)
	_, err := w.a.APIKeys().Create(context.Background(), by, egauth.APIKeyRequest{Kind: "service", Lifetime: defaultExpiry()})
	require.ErrorIs(t, err, egauth.ErrReauthRequired)

	off := newFacadeWorld(t, func(c *egauth.Config[gateClaims]) { c.Modules.APIKeys = nil })
	_, me, _ := off.user("alice@example.com")
	_, err = off.a.APIKeys().List(context.Background(), me)
	require.ErrorIs(t, err, egauth.ErrFacadeUnavailable)
}

func TestAPIKeysSecretIsRedacted(t *testing.T) {
	w := newFacadeWorld(t)
	_, by, _ := w.user("alice@example.com")
	created, err := w.a.APIKeys().Create(context.Background(), by, egauth.APIKeyRequest{Kind: "service", Lifetime: defaultExpiry()})
	require.NoError(t, err)
	secret := created.Reveal()
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("x", "key", created)
	js, err := json.Marshal(created)
	require.NoError(t, err)
	wrapped := struct{ K egauth.APIKeySecret }{created}
	for _, out := range []string{
		fmt.Sprintf("%v %+v %#v %s %q", created, created, created, created, created), fmt.Sprintf("%v %+v %#v", wrapped, wrapped, wrapped),
		string(js), logged.String(),
	} {
		require.NotContains(t, out, secret)
		require.NotContains(t, out, secret[len(secret)-20:])
	}
}
