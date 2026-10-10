package jwt_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/internal/session/backendtest"
	"github.com/JLugagne/egauth/internal/session/jwt"
)

func claimsOfSize(t *testing.T, n int) core.SealedClaims {
	t.Helper()
	const frame = `{"roles":[""]}`
	c := core.NewSealedClaims([]byte(`{"roles":["` + strings.Repeat("r", n-len(frame)) + `"]}`))
	if c.Len() != n {
		t.Fatalf("claims of %d bytes, want %d", c.Len(), n)
	}
	return c
}

func maximalAttrs(t *testing.T, now time.Time, tr core.Transport) core.SessionAttrs {
	t.Helper()
	return principaltest.Attrs(principaltest.Spec{
		Lineage: uuid.New(), Subject: core.Subject{Tenant: tenant(t), User: uuid.New()},
		Factors: []core.Factor{
			core.FactorPasskey, core.FactorUserVerification, core.FactorPassword, core.FactorTOTP,
			core.FactorPasskeyStepUp, core.FactorFederated,
		},
		PasskeyUses: []principaltest.Credential{
			{Factor: core.FactorPasskey, ID: make([]byte, 64)},
			{Factor: core.FactorPasskeyStepUp, ID: make([]byte, 64)},
		},
		PrimaryAt: now, SecondAt: now, Epoch: 1 << 40, RememberMe: true, MustChange: true,
		ReturnTo: "/" + strings.Repeat("x", 511), Transport: tr, Provider: "google",
		CreatedAt: now, ClaimsFetchedAt: now,
	})
}

func setCookieSizes(rec *httptest.ResponseRecorder) map[string]int {
	out := map[string]int{}
	for _, ck := range (&http.Response{Header: rec.Header()}).Cookies() {
		out[ck.Name] = len(ck.Name) + 1 + len(ck.Value)
	}
	return out
}

// TestCookieSizeBound asserts that a cookie session never writes a cookie of MaxCookieBytes or
// more: with maximal attributes (a 512-byte return_to) the largest claims that fit are accepted
// and every cookie stays under the bound, and anything larger, MaxAppClaimsBytes of claims
// included, is refused with ClaimsTooLarge before anything is stored or written. DESIGN §4.5
// expects MaxAppClaimsBytes to fit; with egv 2 JSON claims it cannot (FOLLOWUPS.md, M11-18).
func TestCookieSizeBound(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	now := fx.Clock.Now()
	largest := 0
	for n := 64; n <= session.MaxAppClaimsBytes; n += 16 {
		rec := httptest.NewRecorder()
		err := w.backend.Start(t.Context(), rec, maximalAttrs(t, now, core.TransportCookies), claimsOfSize(t, n))
		if err != nil {
			if !errors.Is(err, core.ErrClaimsTooLarge) {
				t.Fatalf("%d bytes of claims: %v", n, err)
			}
			if len(rec.Header().Values("Set-Cookie")) != 0 {
				t.Fatal("a refused session wrote cookies")
			}
			continue
		}
		sizes := setCookieSizes(rec)
		if len(sizes) != 2 {
			t.Fatalf("want the access and refresh cookies, got %v", sizes)
		}
		for name, size := range sizes {
			if size >= jwt.MaxCookieBytes {
				t.Fatalf("%d bytes of claims: cookie %s is %d bytes", n, name, size)
			}
		}
		largest = n
	}
	t.Logf("largest claims that fit a cookie session with maximal attributes: %d bytes", largest)
	if largest < session.MaxAppClaimsBytes/2 {
		t.Fatalf("only %d bytes of claims fit a cookie session", largest)
	}
	if fx.Events.Count(event.ClaimsTooLarge) == 0 && largest < session.MaxAppClaimsBytes {
		t.Fatal("refusals emitted no ClaimsTooLarge event")
	}
	rec := httptest.NewRecorder()
	if err := w.backend.Start(t.Context(), rec, maximalAttrs(t, now, core.TransportBearer), claimsOfSize(t, session.MaxAppClaimsBytes)); err != nil {
		t.Fatalf("a Bearer session with MaxAppClaimsBytes of claims: %v", err)
	}
	if n := len(rec.Header().Get(jwt.HeaderAccessToken)); n == 0 || n > jwt.MaxTokenLen {
		t.Fatalf("Bearer access token of %d bytes", n)
	}
}

func TestResourceToken(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	ctx := t.Context()
	s := mustUser(t, w)
	access, _ := startPair(t, w, passwordAttrs(t, w, s, core.TransportBearer))
	res, err := w.backend.Resume(ctx, httptest.NewRecorder(), bearerRequest(t, access, ""), tenant(t))
	if err != nil {
		t.Fatal(err)
	}
	raw, exp, err := w.backend.MintResource(ctx, res, resourceAud, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Equal(fx.Clock.Now().Add(time.Minute)) {
		t.Fatalf("resource token expires at %s", exp)
	}
	tok, err := w.codec.VerifyResource(ctx, raw, w.keys, resourceAud)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Audience() != resourceAud || tok.Family() != res.Handle().ID() || tok.Attrs().Subject() != s {
		t.Fatal("resource token does not describe the session")
	}
	if _, err := w.codec.VerifySession(ctx, raw, w.keys); !errors.Is(err, jwt.ErrInvalidToken) {
		t.Fatalf("a resource token passed as a session token: %v", err)
	}
	if _, err := w.backend.Resume(ctx, httptest.NewRecorder(), bearerRequest(t, raw, ""), tenant(t)); err == nil {
		t.Fatal("a resource token resumed a session")
	}
	if _, err := w.codec.VerifyResource(ctx, access, w.keys, resourceAud); !errors.Is(err, jwt.ErrInvalidToken) {
		t.Fatalf("a session token passed as a resource token: %v", err)
	}
	if _, err := w.codec.VerifyResource(ctx, access, w.keys, "https://acme.example.test"); !errors.Is(err, jwt.ErrInvalidToken) {
		t.Fatalf("the issuer accepted as a resource audience: %v", err)
	}
	for name, aud := range map[string]string{"unknown": "https://other.example.test", "issuer": "https://acme.example.test"} {
		if _, _, err := w.backend.MintResource(ctx, res, aud, time.Minute); !errors.Is(err, jwt.ErrAudience) {
			t.Fatalf("%s audience: %v", name, err)
		}
	}
	for _, life := range []time.Duration{0, fx.Lifetimes.RecheckEvery + time.Second} {
		if _, _, err := w.backend.MintResource(ctx, res, resourceAud, life); !errors.Is(err, core.ErrInvalidArgument) {
			t.Fatalf("lifetime %s: %v", life, err)
		}
	}
	if err := w.tokens.RevokeFamily(ctx, s.Tenant, res.Handle().ID()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.backend.MintResource(ctx, res, resourceAud, time.Minute); err == nil {
		t.Fatal("a resource token minted for a revoked family")
	}
}

func TestRenewalRefusesCrossedCredentials(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	ctx := t.Context()
	s := mustUser(t, w)
	cookieAccess, cookieRefresh := startPair(t, w, passwordAttrs(t, w, s, core.TransportCookies))
	bearerAccess, bearerRefresh := startPair(t, w, passwordAttrs(t, w, s, core.TransportBearer))
	fx.Clock.Advance(fx.Lifetimes.RecheckEvery + time.Second)
	cases := map[string]*http.Request{
		"cookie refresh token over Bearer":    bearerRequest(t, "", cookieRefresh),
		"Bearer refresh token in a cookie":    cookieRequest(t, w, "", bearerRefresh),
		"access and refresh of two sessions":  bearerRequest(t, bearerAccess, mustOtherRefresh(t, w, s)),
		"cookie access with a Bearer refresh": cookieRequest(t, w, cookieAccess, bearerRefresh),
	}
	for name, r := range cases {
		rec := httptest.NewRecorder()
		if _, err := w.backend.Resume(ctx, rec, r, tenant(t)); err == nil || errors.Is(err, httpx.ErrUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
		if len(rec.Header()) != 0 {
			t.Errorf("%s: refused renewal wrote %v", name, rec.Header())
		}
	}
	for name, r := range map[string]*http.Request{
		"cookie session": cookieRequest(t, w, cookieAccess, cookieRefresh),
		"Bearer session": bearerRequest(t, bearerAccess, bearerRefresh),
	} {
		if _, err := w.backend.Resume(ctx, httptest.NewRecorder(), r, tenant(t)); err != nil {
			t.Errorf("%s after refused crossings: %v", name, err)
		}
	}
}

func mustOtherRefresh(t *testing.T, w *world, s core.Subject) string {
	t.Helper()
	_, refresh := startPair(t, w, passwordAttrs(t, w, s, core.TransportBearer))
	return refresh
}

func TestRefreshTokenIsBoundToItsTenant(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	s := mustUser(t, w)
	_, refresh := startPair(t, w, passwordAttrs(t, w, s, core.TransportBearer))
	handle, tn, ok := strings.Cut(refresh, ".")
	if !ok || tn != "acme" {
		t.Fatalf("refresh token does not name its tenant: %q", refresh)
	}
	fx.Clock.Advance(fx.Lifetimes.RecheckEvery + time.Second)
	for _, forged := range []string{handle, handle + ".other", handle + "x.acme", "." + tn} {
		if _, err := w.backend.Resume(t.Context(), httptest.NewRecorder(), bearerRequest(t, "", forged), tenant(t)); err == nil {
			t.Fatalf("refresh token %q accepted", forged)
		}
	}
}

func TestEndWithAccessTokenOnly(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	s := mustUser(t, w)
	access, refresh := startPair(t, w, passwordAttrs(t, w, s, core.TransportBearer))
	fx.Clock.Advance(fx.Lifetimes.RecheckEvery)
	if err := w.backend.End(t.Context(), httptest.NewRecorder(), bearerRequest(t, access, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.backend.Resume(t.Context(), httptest.NewRecorder(), bearerRequest(t, "", refresh), tenant(t)); err == nil {
		t.Fatal("End through an expired access token left the family live")
	}
}

func TestNewValidatesItsConfiguration(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	renewer, err := session.NewRenewer(session.RenewConfig{
		Authority: authority{id: w.identity, enr: fx.Enrollment}, Claims: fx.Claims,
		Lifetimes: session.Lifetimes{IdleTimeout: time.Hour, MaxLifetime: 2 * time.Hour, RecheckEvery: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	good := jwt.Config{Codec: w.codec, Keys: w.keys, Tokens: w.tokens, Families: w.families, Epochs: w.epochs, Renewer: renewer, Cookies: w.cookies}
	bad := map[string]func(c *jwt.Config){
		"recheck mismatch": func(*jwt.Config) {},
		"no codec":         func(c *jwt.Config) { c.Codec = nil },
		"no tokens":        func(c *jwt.Config) { c.Tokens = nil },
		"zero cookies":     func(c *jwt.Config) { c.Cookies = cookie.Policy{} },
		"audience path":    func(c *jwt.Config) { c.Audiences = []string{"https://api.example.test/v1"} },
	}
	for name, edit := range bad {
		c := good
		edit(&c)
		if _, err := jwt.New(c); !errors.Is(err, jwt.ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, cfg := range map[string]jwt.CodecConfig{
		"path origin":       {PublicOrigin: "https://a.example.test/x", ClaimsFingerprint: "f", RecheckEvery: time.Minute},
		"inner tenant":      {PublicOrigin: "https://a.{tenant}.example.test", ClaimsFingerprint: "f", RecheckEvery: time.Minute},
		"two tenants":       {PublicOrigin: "https://{tenant}.{tenant}.test", ClaimsFingerprint: "f", RecheckEvery: time.Minute},
		"no fingerprint":    {PublicOrigin: publicOrigin, RecheckEvery: time.Minute},
		"no recheck":        {PublicOrigin: publicOrigin, ClaimsFingerprint: "f"},
		"ftp origin":        {PublicOrigin: "ftp://a.example.test", ClaimsFingerprint: "f", RecheckEvery: time.Minute},
		"long fingerprint":  {PublicOrigin: publicOrigin, ClaimsFingerprint: strings.Repeat("f", 129), RecheckEvery: time.Minute},
		"credentials in it": {PublicOrigin: "https://u:p@a.example.test", ClaimsFingerprint: "f", RecheckEvery: time.Minute},
	} {
		if _, err := jwt.NewCodec(cfg); !errors.Is(err, jwt.ErrInvalidConfig) {
			t.Errorf("codec %s: %v", name, err)
		}
	}
	if _, err := w.codec.Issuer(core.TenantID{}); !errors.Is(err, jwt.ErrInvalidToken) {
		t.Fatalf("single tenant under a {tenant} origin: %v", err)
	}
}

func TestRenewalThatOutgrowsTheCookieIsAnOutage(t *testing.T) {
	fx := backendtest.NewFixture(t)
	w := buildWorld(t, fx, newSigner(t))
	ctx := t.Context()
	s := mustUser(t, w)
	epoch, err := w.identity.CurrentEpoch(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	now := fx.Clock.Now()
	a := principaltest.Attrs(principaltest.Spec{
		Lineage: uuid.New(), Subject: s, Factors: []core.Factor{core.FactorPassword}, PrimaryAt: now,
		Epoch: epoch, RememberMe: true, ReturnTo: "/" + strings.Repeat("x", 511),
		Transport: core.TransportCookies, CreatedAt: now, ClaimsFetchedAt: now,
	})
	access, refresh := startPair(t, w, a)
	fx.Claims.Set(claimsOfSize(t, session.MaxAppClaimsBytes).Bytes())
	fx.Clock.Advance(fx.Lifetimes.RecheckEvery + time.Second)
	rec := httptest.NewRecorder()
	_, err = w.backend.Resume(ctx, rec, cookieRequest(t, w, access, refresh), tenant(t))
	if !errors.Is(err, core.ErrClaimsTooLarge) || !errors.Is(err, httpx.ErrUnavailable) {
		t.Fatalf("renewal with claims that do not fit the cookie: %v, want ClaimsTooLarge as an outage", err)
	}
	if len(rec.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("a refused renewal wrote cookies")
	}
	if fx.Events.Count(event.ClaimsTooLarge) == 0 {
		t.Fatal("no ClaimsTooLarge event")
	}
	fx.Claims.Set([]byte(`{"roles":["user"]}`))
	if _, err := w.backend.Resume(ctx, httptest.NewRecorder(), cookieRequest(t, w, access, refresh), tenant(t)); err != nil {
		t.Fatalf("the family did not survive the refused renewal: %v", err)
	}
}
