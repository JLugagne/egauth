package egauth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/signing"
)

type discoveryDoc struct {
	Issuer            string   `json:"issuer"`
	JWKSURI           string   `json:"jwks_uri"`
	Audiences         []string `json:"audiences"`
	ClaimsFingerprint string   `json:"claims_fingerprint"`
}

func readDiscovery(t *testing.T, w *gateWorld, h http.Handler) (discoveryDoc, map[string]any) {
	t.Helper()
	rec := w.request(h, http.MethodGet, egauth.PathWellKnown, credentials{})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var doc discoveryDoc
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	var raw map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	return doc, raw
}

func TestDiscoveryDocumentAndJWKS(t *testing.T) {
	w := newGateWorld(t)
	h := w.build(w.a.Routes())
	doc, raw := readDiscovery(t, w, h)
	require.Equal(t, gateOrigin, doc.Issuer)
	require.Equal(t, gateOrigin+"/auth"+egauth.PathJWKS, doc.JWKSURI)
	require.Equal(t, []string{gateAudience}, doc.Audiences)
	require.Equal(t, egauth.ClaimsFingerprint[gateClaims](), doc.ClaimsFingerprint)
	require.Len(t, raw, 4, "the document carries exactly issuer, jwks_uri, audiences and claims_fingerprint")

	rec := w.request(h, http.MethodGet, "/auth"+egauth.PathJWKS, credentials{})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	vs, err := signing.ParseJWKS(rec.Body.Bytes())
	require.NoError(t, err)
	require.Len(t, vs, 1)
	require.Equal(t, "gate-1", vs[0].KeyID())
	require.NotContains(t, rec.Body.String(), `"d"`, "no private material is published")

	require.Equal(t, http.StatusNotFound, w.request(h, http.MethodPost, egauth.PathWellKnown, credentials{}).Code)
}

func TestDiscoveryStatefulPublishesNoKeysAndNoResourceToken(t *testing.T) {
	w := newGateWorld(t, stateful)
	h := w.build(w.a.Routes())
	doc, raw := readDiscovery(t, w, h)
	require.Equal(t, gateOrigin, doc.Issuer)
	require.Empty(t, doc.JWKSURI)
	_, has := raw["jwks_uri"]
	require.False(t, has)
	require.Equal(t, []string{}, doc.Audiences)
	require.Equal(t, http.StatusNotFound, w.request(h, http.MethodGet, "/auth"+egauth.PathJWKS, credentials{}).Code)
	require.Equal(t, http.StatusNotFound, w.request(h, http.MethodPost, "/auth"+egauth.PathResourceToken, credentials{}).Code)
}

func TestDiscoveryHS256PublishesNoKeys(t *testing.T) {
	w := newGateWorld(t, func(c *egauth.Config[gateClaims]) {
		c.Sessions = egauth.JWT(egauth.StaticKeys(hsSigner(t, "hs-1")))
		c.Audiences = nil
	})
	h := w.build(w.a.Routes())
	doc, _ := readDiscovery(t, w, h)
	require.Empty(t, doc.JWKSURI)
	require.Equal(t, http.StatusNotFound, w.request(h, http.MethodGet, "/auth"+egauth.PathJWKS, credentials{}).Code)
}

func TestDiscoveryUnresolvableTenantIsRefused(t *testing.T) {
	w := newGateWorld(t, perRequestTenancy)
	h := w.build(w.a.Routes())
	rec := w.request(h, http.MethodGet, egauth.PathWellKnown, credentials{}, func(r *http.Request) { r.Header.Set(gateTenantHdr, "Not A Tenant!") })
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func jwtPayload(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3)
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

func resourceToken(w *gateWorld, h http.Handler, c credentials, resource string) (int, map[string]any) {
	form := url.Values{egauth.FieldResource: {resource}}
	rec := w.request(h, http.MethodPost, "/auth"+egauth.PathResourceToken, c, func(r *http.Request) {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Body = readCloser(form.Encode())
		r.ContentLength = int64(len(form.Encode()))
	})
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func TestDiscoveryResourceTokenIsMintedForAnAudienceOnly(t *testing.T) {
	w := newGateWorld(t)
	w.seedUser("nina@example.com", false)
	s := &seen{}
	h := w.build(w.a.Routes().Protect("GET /account", s.handler))
	c := w.login(h, "nina@example.com", false)
	require.Equal(t, http.StatusOK, c.code, c.body)

	code, body := resourceToken(w, h, c, gateAudience)
	require.Equal(t, http.StatusOK, code, body)
	tok, _ := body["token"].(string)
	require.NotEmpty(t, tok)
	require.Equal(t, "Bearer", body["token_type"])
	claims := jwtPayload(t, tok)
	require.Equal(t, gateAudience, claims["aud"])
	iat, exp := claims["iat"].(float64), claims["exp"].(float64)
	require.LessOrEqual(t, time.Duration(exp-iat)*time.Second, egauth.ConfigOf(w.a).Policy.RecheckEvery)
	require.NotNil(t, claims["att"])

	require.Equal(t, http.StatusUnauthorized, w.request(h, http.MethodGet, "/account", credentials{bearer: tok}).Code,
		"a resource token is never a session")

	code, _ = resourceToken(w, h, c, gateOrigin)
	require.Equal(t, http.StatusBadRequest, code)
	code, _ = resourceToken(w, h, c, "https://unknown.example")
	require.Equal(t, http.StatusBadRequest, code)
	code, _ = resourceToken(w, h, c, "")
	require.Equal(t, http.StatusBadRequest, code)
	code, _ = resourceToken(w, h, credentials{}, gateAudience)
	require.Equal(t, http.StatusUnauthorized, code)
}

func TestDiscoveryResourceTokenRefusesAMustChangeSession(t *testing.T) {
	w := newGateWorld(t)
	w.seedUser("omar@example.com", true)
	h := w.build(w.a.Routes())
	c := w.login(h, "omar@example.com", false)
	code, _ := resourceToken(w, h, c, gateAudience)
	require.Equal(t, http.StatusForbidden, code)
}

func TestDiscoveryRunsBehindTheEndpointPreamble(t *testing.T) {
	var endpoints []egauth.EndpointID
	refuse := false
	w := newGateWorld(t, func(c *egauth.Config[gateClaims]) {
		c.Hooks.BeforeEndpoint = func(_ context.Context, r egauth.EndpointRequest) error {
			endpoints = append(endpoints, r.Endpoint)
			if refuse {
				return errors.New("refused by the application")
			}
			return nil
		}
	})
	h := w.build(w.a.Routes())
	readDiscovery(t, w, h)
	require.Equal(t, []egauth.EndpointID{egauth.PathWellKnown}, endpoints)

	refuse = true
	rec := w.request(h, http.MethodGet, egauth.PathWellKnown, credentials{})
	require.NotEqual(t, http.StatusOK, rec.Code)
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
}
