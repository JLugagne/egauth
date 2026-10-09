package jwt_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/keys"
	"github.com/JLugagne/egauth/internal/principaltest"
	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/internal/session/backendtest"
	"github.com/JLugagne/egauth/internal/session/jwt"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/signing"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	identitymemory "github.com/JLugagne/egauth/store/identity/memory"
	tokensmemory "github.com/JLugagne/egauth/store/tokens/memory"
)

const (
	publicOrigin = "https://{tenant}.example.test"
	resourceAud  = "https://api.example.test"
	fingerprint  = "egc-test-fingerprint"
	keyID        = "k1"
)

type authority struct {
	id  identity.Store
	enr *backendtest.Enrollment
}

func (a authority) AccountState(ctx context.Context, s core.Subject) (core.AccountState, error) {
	u, err := a.id.GetUser(ctx, s)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return core.AccountState{}, nil
	case err != nil:
		return core.AccountState{}, errors.Join(httpx.ErrUnavailable, err)
	}
	return core.NewAccountState(true, !u.DisabledAt.IsZero(), !u.DeletedAt.IsZero(), u.MustChange, !u.EmailVerifiedAt.IsZero(), u.SecurityEpoch), nil
}

func (a authority) MFADecision(_ context.Context, s core.Subject) (core.MFADecision, error) {
	return core.NewMFADecision(a.enr.Factors(s)), nil
}

func newSigner(t *testing.T) signing.Signer {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	s, err := signing.EdDSA(keyID, seed)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func fixedSigner(t *testing.T) signing.Signer {
	t.Helper()
	seed := sha256.Sum256([]byte("egauth internal/session/jwt golden key"))
	s, err := signing.EdDSA(keyID, seed[:])
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type world struct {
	fx       *backendtest.Fixture
	backend  *jwt.Backend
	codec    *jwt.Codec
	keys     *keys.Manager
	signer   signing.Signer
	tokens   *tokensmemory.Store
	identity *identitymemory.Store
	families *revoke.Families
	epochs   *revoke.Epochs
	cookies  cookie.Policy
}

func build(t *testing.T, fx *backendtest.Fixture) *jwt.Backend {
	t.Helper()
	return buildWorld(t, fx, newSigner(t)).backend
}

func buildWorld(t *testing.T, fx *backendtest.Fixture, signer signing.Signer) *world {
	t.Helper()
	clk := fx.Clock.Clock()
	w := &world{fx: fx, signer: signer, tokens: tokensmemory.NewWithClock(clk), identity: identitymemory.NewWithClock(clk)}
	var err error
	if w.keys, err = keys.NewStatic(signer); err != nil {
		t.Fatal(err)
	}
	cfg := revoke.Config{Clock: clk, Events: fx.Events}
	if w.families, err = revoke.NewFamilies(fx.Outage.Families(w.tokens), cfg); err != nil {
		t.Fatal(err)
	}
	if w.epochs, err = revoke.NewEpochs(fx.Outage.Epochs(w.identity), cfg); err != nil {
		t.Fatal(err)
	}
	renewer, err := session.NewRenewer(session.RenewConfig{
		Authority: authority{id: w.identity, enr: fx.Enrollment}, Claims: fx.Claims,
		Lifetimes: fx.Lifetimes, Clock: clk, Events: fx.Events,
	})
	if err != nil {
		t.Fatal(err)
	}
	if w.codec, err = jwt.NewCodec(jwt.CodecConfig{PublicOrigin: publicOrigin, ClaimsFingerprint: fingerprint, RecheckEvery: fx.Lifetimes.RecheckEvery, Clock: clk}); err != nil {
		t.Fatal(err)
	}
	if w.cookies, err = cookie.NewPolicy(cookie.Options{PublicOrigin: publicOrigin}); err != nil {
		t.Fatal(err)
	}
	if w.backend, err = jwt.New(jwt.Config{
		Codec: w.codec, Keys: w.keys, Tokens: w.tokens, Families: w.families, Epochs: w.epochs,
		Renewer: renewer, Cookies: w.cookies, Audiences: []string{resourceAud}, Clock: clk, Events: fx.Events,
	}); err != nil {
		t.Fatal(err)
	}
	fx.Identity = w.identity
	fx.Start = w.backend.Start
	fx.Reissue = w.backend.Reissue
	fx.Poll = func(ctx context.Context) error { return errors.Join(w.families.Poll(ctx), w.epochs.Poll(ctx)) }
	fx.Forge = w.forge
	fx.Carry = carry
	return w
}

func carry(resp, next http.Header) {
	if v := resp.Get(jwt.HeaderAccessToken); v != "" {
		next.Set("Authorization", "Bearer "+v)
	}
	if v := resp.Get(jwt.HeaderRefreshToken); v != "" {
		next.Set(jwt.HeaderRefreshToken, v)
	}
}

func (w *world) access(t *testing.T, c backendtest.Credentials) (string, core.Transport) {
	t.Helper()
	name := w.cookies.CookieName(cookie.AccessToken)
	for _, ck := range c.Cookies {
		if ck.Name == name {
			return ck.Value, core.TransportCookies
		}
	}
	if v, ok := strings.CutPrefix(c.Header.Get("Authorization"), "Bearer "); ok {
		return v, core.TransportBearer
	}
	t.Fatal("no access token in the credentials")
	return "", 0
}

func (w *world) refresh(c backendtest.Credentials, tr core.Transport) string {
	if tr == core.TransportBearer {
		return c.Header.Get(jwt.HeaderRefreshToken)
	}
	name := w.cookies.CookieName(cookie.RefreshToken)
	for _, ck := range c.Cookies {
		if ck.Name == name {
			return ck.Value
		}
	}
	return ""
}

func (w *world) present(tok string, tr core.Transport) backendtest.Credentials {
	if tr == core.TransportCookies {
		return backendtest.Credentials{Cookies: []*http.Cookie{{Name: w.cookies.CookieName(cookie.AccessToken), Value: tok}}, Header: http.Header{}}
	}
	return backendtest.Credentials{Header: http.Header{"Authorization": {"Bearer " + tok}}}
}

func decodePart(t *testing.T, part string) map[string]any {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (w *world) resign(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	tok, err := jwt.SignForTest(w.signer, mustJSON(t, header), mustJSON(t, payload))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func (w *world) forge(t *testing.T, f backendtest.Forgery, c backendtest.Credentials) backendtest.Credentials {
	t.Helper()
	tok, tr := w.access(t, c)
	parts := strings.Split(tok, ".")
	header, payload := decodePart(t, parts[0]), decodePart(t, parts[1])
	switch f {
	case backendtest.ForgeLegacy:
		legacy := map[string]any{
			"sub": payload["sub"], "tid": payload["tid"], "sid": payload["sid"], "iat": payload["iat"],
			"exp": payload["exp"], "iss": payload["iss"], "aud": payload["aud"], "roles": []string{"admin"},
			"amr": payload["amr"], "auth_time": payload["auth_time"],
		}
		return w.present(w.resign(t, map[string]any{"alg": header["alg"], "kid": header["kid"], "typ": "JWT"}, legacy), tr)
	case backendtest.ForgeRandomFamily:
		payload["sid"] = uuid.NewString()
		return w.present(w.resign(t, header, payload), tr)
	case backendtest.ForgeOtherTransport:
		refresh := w.refresh(c, tr)
		if tr == core.TransportCookies {
			out := w.present(tok, core.TransportBearer)
			out.Header.Set(jwt.HeaderRefreshToken, refresh)
			return out
		}
		out := w.present(tok, core.TransportCookies)
		out.Cookies = append(out.Cookies, &http.Cookie{Name: w.cookies.CookieName(cookie.RefreshToken), Value: refresh})
		return out
	}
	t.Fatalf("unknown forgery %d", f)
	return backendtest.Credentials{}
}

func tenant(t *testing.T) principal.TenantID {
	t.Helper()
	tn, err := principal.ParseTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	return tn
}

func mustUser(t *testing.T, w *world) principal.Subject {
	t.Helper()
	email, err := identity.NewIdentifier(identity.IdentifierEmail, "u-"+uuid.NewString()+"@example.test")
	if err != nil {
		t.Fatal(err)
	}
	out, err := w.identity.Apply(t.Context(), identity.CreateVerified{Tenant: tenant(t), Email: email})
	if err != nil {
		t.Fatal(err)
	}
	return out.Subject
}

func passwordAttrs(t *testing.T, w *world, s principal.Subject, tr core.Transport) core.SessionAttrs {
	t.Helper()
	epoch, err := w.identity.CurrentEpoch(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	now := w.fx.Clock.Now()
	return principaltest.Attrs(principaltest.Spec{
		Lineage: uuid.New(), Subject: s, Factors: []core.Factor{core.FactorPassword}, PrimaryAt: now,
		Epoch: epoch, Transport: tr, CreatedAt: now, ClaimsFetchedAt: now,
	})
}

func startPair(t *testing.T, w *world, a core.SessionAttrs) (string, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := w.backend.Start(t.Context(), rec, a, w.fx.Claims.Value()); err != nil {
		t.Fatal(err)
	}
	if a.Transport() == core.TransportBearer {
		return rec.Header().Get(jwt.HeaderAccessToken), rec.Header().Get(jwt.HeaderRefreshToken)
	}
	var access, refresh string
	for _, ck := range (&http.Response{Header: rec.Header()}).Cookies() {
		switch ck.Name {
		case w.cookies.CookieName(cookie.AccessToken):
			access = ck.Value
		case w.cookies.CookieName(cookie.RefreshToken):
			refresh = ck.Value
		}
	}
	return access, refresh
}

func bearerRequest(t *testing.T, access, refresh string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://acme.example.test/", nil)
	if access != "" {
		r.Header.Set("Authorization", "Bearer "+access)
	}
	if refresh != "" {
		r.Header.Set(jwt.HeaderRefreshToken, refresh)
	}
	return r
}

func cookieRequest(t *testing.T, w *world, access, refresh string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://acme.example.test/", nil)
	if access != "" {
		r.AddCookie(&http.Cookie{Name: w.cookies.CookieName(cookie.AccessToken), Value: access})
	}
	if refresh != "" {
		r.AddCookie(&http.Cookie{Name: w.cookies.CookieName(cookie.RefreshToken), Value: refresh})
	}
	return r
}
