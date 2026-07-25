// This file proves that the pre-MFA INTERIM credential minted by an MFA-gated login is not a
// usable session: it must not reach an ordinary protected route, must not strip or reset the
// second factor, must not be upgraded into a full renewable pair, and must not delete the
// account. It also proves the MFA-gated login response is distinguishable on the wire from a
// full login, so a consumer can drive the step-up flow.
//
// Everything is wired with the genuine components (real identity.Service, real mfa.Service, one
// real jwt.Service acting as both issuer and verifier, and the real tokens middleware) behind an
// httptest.Server with a cookie jar, so the interim access cookie is carried exactly as a browser
// would carry it.
package internal_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/mfa"
	mfamemory "github.com/JLugagne/egauth/mfa/memory"
	"github.com/JLugagne/egauth/passwords/hashertest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	tokensmemory "github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	interimEmail    = "enrolled@example.com"
	interimPassword = "CorrectHorse1!"
)

// interimPolicy is a permissive password policy: the interim-credential authority, not password
// strength, is what these tests exercise.
type interimPolicy struct{}

func (interimPolicy) Verify(_ context.Context, _ string) error { return nil }

// interimClock is a settable clock shared by the MFA service and the token issuer, so a test can
// advance past a TOTP period (the MFA service refuses a replayed code within the same step).
type interimClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *interimClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *interimClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// interimServer bundles the wired-up stack for the interim-credential tests.
type interimServer struct {
	srv    *httptest.Server
	idsvc  identity.Service
	mfasvc mfa.Service
	store  *identitymemory.Store
	secret string
	userID uuid.UUID
	clk    *interimClock
}

// newInterimServer wires a real identity service, a real MFA service with the test user already
// enrolled AND confirmed, one real jwt.Service (issuer + verifier) and the real tokens middleware
// into an httptest.Server. The mux exposes:
//
//	POST /login              — identity.LoginHandler WITH identity.WithMFAGate
//	GET  /app                — RequireAuth: an ordinary protected route
//	POST /mfa/step-up        — mfa.StepUpHandler behind ContextMiddleware
//	POST /mfa/disable        — mfa.DisableHandler behind ContextMiddleware
//	POST /mfa/recovery-codes — mfa.RegenerateRecoveryCodesHandler behind ContextMiddleware
//	POST /change             — identity.ChangePasswordWithReissueHandler behind ContextMiddleware
//	POST /delete             — identity.DeleteAccountHandler behind ContextMiddleware
func newInterimServer(t *testing.T) *interimServer {
	t.Helper()
	ctx := context.Background()
	clk := &interimClock{t: time.Now()}
	now := clk.now

	store := identitymemory.NewStore()
	hasher := &hashertest.MockHasher{
		HashFunc: func(_ context.Context, p string) (string, error) { return "hashed-" + p, nil },
		CompareFunc: func(_ context.Context, hash, pw string) error {
			if hash != "hashed-"+pw {
				return identity.ErrInvalidCredentials
			}
			return nil
		},
	}
	idsvc := identity.NewService(store, hasher, interimPolicy{})
	user, err := idsvc.Register(ctx, "", interimEmail, interimPassword)
	require.NoError(t, err)

	mfasvc := mfa.NewService(mfamemory.NewStore(), mfa.WithClock(now))
	enrollment, err := mfasvc.EnrollTOTP(ctx, "", user.ID, interimEmail)
	require.NoError(t, err)
	code, err := mfa.GenerateCode(enrollment.Secret, now(), mfa.DefaultDigits, mfa.DefaultPeriod)
	require.NoError(t, err)
	_, err = mfasvc.ConfirmTOTP(ctx, "", user.ID, code)
	require.NoError(t, err)

	jwtSvc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      tokensmemory.NewStore[struct{}](),
		SecretKey:  "interim-secret-key-aaaaaaaaaaaaaaaa", // 32+ bytes
		Issuer:     "egauth-interim",
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
		Clock:      now,
		ClaimsProvider: tokens.ClaimsProviderFunc[struct{}](func(_ context.Context, userID uuid.UUID, tenant string) (tokens.Claims[struct{}], error) {
			return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}, nil
		}),
	})

	cookies := tokens.Cookies{
		AccessName:  "access_token",
		RefreshName: "refresh_token",
		Path:        "/",
		RefreshPath: "/",
		SameSite:    http.SameSiteLaxMode,
		Insecure:    true,
	}
	require.NoError(t, cookies.Validate())

	claimsOf := func(u *identity.User) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: u.ID, TenantID: u.TenantID}
	}
	stepUpClaimsOf := func(_ context.Context, userID uuid.UUID, tenant string) tokens.Claims[struct{}] {
		return tokens.Claims[struct{}]{Subject: userID, TenantID: tenant}
	}

	idOpts := []identity.HandlerOption{identity.WithCookies(cookies), identity.WithInsecureCookies()}
	userResolver := identity.WithUserResolver(func(r *http.Request) (*identity.User, bool) {
		uid, tenant, ok := tokens.UserResolverFromContext(r)
		if !ok {
			return nil, false
		}
		u, err := store.FindUserByID(r.Context(), tenant, uid)
		if err != nil || u == nil {
			return nil, false
		}
		return u, true
	})
	mfaOpts := []mfa.HandlerOption{
		mfa.WithUserResolver(tokens.UserResolverFromContext),
		mfa.WithCookies(cookies),
	}
	authOpts := []tokens.AuthOption[struct{}]{
		tokens.WithCookieAuth[struct{}](cookies),
		tokens.WithoutHeaderAuth[struct{}](),
	}

	mux := http.NewServeMux()
	mux.Handle("/login", identity.LoginHandler[struct{}](idsvc, jwtSvc, claimsOf,
		append(append([]identity.HandlerOption{}, idOpts...), identity.WithMFAGate(mfasvc))...))
	mux.Handle("/app", tokens.RequireAuth[struct{}](jwtSvc,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("app-reached"))
		}, authOpts...))
	// The step-up endpoint is the ONE route that must admit the interim credential: it exists to
	// complete the second factor. Every other route refuses it.
	mux.Handle("/mfa/step-up", tokens.ContextMiddleware[struct{}](jwtSvc,
		mfa.StepUpHandler[struct{}](mfasvc, jwtSvc, stepUpClaimsOf, mfaOpts...),
		append(append([]tokens.AuthOption[struct{}]{}, authOpts...), tokens.WithInterimAllowed[struct{}]())...))
	mux.Handle("/mfa/disable", tokens.ContextMiddleware[struct{}](jwtSvc,
		mfa.DisableHandler(mfasvc, mfaOpts...), authOpts...))
	mux.Handle("/mfa/recovery-codes", tokens.ContextMiddleware[struct{}](jwtSvc,
		mfa.RegenerateRecoveryCodesHandler(mfasvc, mfaOpts...), authOpts...))
	mux.Handle("/change", tokens.ContextMiddleware[struct{}](jwtSvc,
		identity.ChangePasswordWithReissueHandler[struct{}](idsvc, jwtSvc, claimsOf,
			append([]identity.HandlerOption{userResolver}, idOpts...)...), authOpts...))
	mux.Handle("/delete", tokens.ContextMiddleware[struct{}](jwtSvc,
		identity.DeleteAccountHandler(idsvc,
			append([]identity.HandlerOption{userResolver}, idOpts...)...), authOpts...))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	srv.Client().Jar = jar
	srv.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &interimServer{srv: srv, idsvc: idsvc, mfasvc: mfasvc, store: store,
		secret: enrollment.Secret, userID: user.ID, clk: clk}
}

func (s *interimServer) post(t *testing.T, path string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.srv.URL+path, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", s.srv.URL)
	resp, err := s.srv.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (s *interimServer) get(t *testing.T, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.srv.URL+path, nil)
	require.NoError(t, err)
	resp, err := s.srv.Client().Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func (s *interimServer) cookie(t *testing.T, name string) *http.Cookie {
	t.Helper()
	u, err := url.Parse(s.srv.URL)
	require.NoError(t, err)
	for _, c := range s.srv.Client().Jar.Cookies(u) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// interimLogin performs the password step of an MFA-gated login and asserts the client now holds
// the interim access cookie and NO refresh cookie.
func (s *interimServer) interimLogin(t *testing.T) *http.Response {
	t.Helper()
	resp := s.post(t, "/login", url.Values{"email": {interimEmail}, "password": {interimPassword}})
	require.NotNil(t, s.cookie(t, "access_token"), "the password step must set the interim access cookie")
	require.Nil(t, s.cookie(t, "refresh_token"), "the interim state must not be renewable")
	return resp
}

// TestInterimCredential_CannotReachOrdinaryProtectedRoute proves the pre-MFA interim credential is
// not a session: an ordinary RequireAuth-protected route must refuse it with 403 step_up_required,
// so the second factor is an ENFORCED control rather than a convention the consumer must remember.
func TestInterimCredential_CannotReachOrdinaryProtectedRoute(t *testing.T) {
	s := newInterimServer(t)
	s.interimLogin(t)

	resp := s.get(t, "/app")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"an interim (pre-second-factor) credential must not authenticate an ordinary protected route")
	assert.Contains(t, readBody(t, resp), "step_up_required")
}

// TestInterimCredential_CannotStripMFA proves finding mfa/SF-1: the interim credential must not be
// able to delete the victim's second factor (and with it every recovery code).
func TestInterimCredential_CannotStripMFA(t *testing.T) {
	s := newInterimServer(t)
	s.interimLogin(t)

	resp := s.post(t, "/mfa/disable", url.Values{})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"an interim credential must not be able to disable the second factor")

	enrolled, err := s.mfasvc.IsEnrolled(context.Background(), "", s.userID)
	require.NoError(t, err)
	assert.True(t, enrolled, "the second factor must survive an interim-credential disable attempt")
}

// TestInterimCredential_CannotRegenerateRecoveryCodes proves the same enforcement for the other
// factor-mutating MFA route: regenerating invalidates every existing recovery code.
func TestInterimCredential_CannotRegenerateRecoveryCodes(t *testing.T) {
	s := newInterimServer(t)
	s.interimLogin(t)

	resp := s.post(t, "/mfa/recovery-codes", url.Values{})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"an interim credential must not be able to regenerate (and thus invalidate) recovery codes")
}

// TestInterimCredential_CannotUpgradeToFullSession proves finding mfa/SF-2: the re-issuing
// change-password handler must not turn an interim credential into a full renewable pair, which
// would bypass the second factor entirely for anyone who knows the password.
func TestInterimCredential_CannotUpgradeToFullSession(t *testing.T) {
	s := newInterimServer(t)
	s.interimLogin(t)

	resp := s.post(t, "/change", url.Values{
		"current_password": {interimPassword},
		"new_password":     {"AnotherPass1!"},
	})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"an interim credential must not be upgradable into a full session")
	assert.Nil(t, s.cookie(t, "refresh_token"),
		"no refresh cookie may be issued to a pre-second-factor request")
}

// TestInterimCredential_CannotDeleteAccount proves the refuter-found MEDIUM: account deletion is
// irreversible, so an interim credential must not reach it.
func TestInterimCredential_CannotDeleteAccount(t *testing.T) {
	s := newInterimServer(t)
	s.interimLogin(t)

	resp := s.post(t, "/delete", url.Values{})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"an interim credential must not be able to delete the account")

	u, err := s.store.FindUserByEmail(context.Background(), "", interimEmail)
	require.NoError(t, err)
	assert.NotNil(t, u, "the account must survive an interim-credential deletion attempt")
}

// TestInterimCredential_StepUpUnlocksFullSession is the counter-test to all of the above: the
// enforcement must not over-block. Completing the second factor at the ONE route that admits the
// interim credential (tokens.WithInterimAllowed) must yield a full renewable session that then
// reaches the ordinary route AND the factor-mutating one.
func TestInterimCredential_StepUpUnlocksFullSession(t *testing.T) {
	s := newInterimServer(t)
	s.interimLogin(t)

	// Advance one TOTP period: the enrollment confirmation already consumed the current step.
	s.clk.advance(mfa.DefaultPeriod)
	code, err := mfa.GenerateCode(s.secret, s.clk.now(), mfa.DefaultDigits, mfa.DefaultPeriod)
	require.NoError(t, err)

	resp := s.post(t, "/mfa/step-up", url.Values{"code": {code}})
	require.Equal(t, http.StatusNoContent, resp.StatusCode, "a correct second factor must complete the login")
	require.NotNil(t, s.cookie(t, "refresh_token"), "step-up must issue the full renewable pair")

	resp = s.get(t, "/app")
	require.Equal(t, http.StatusOK, resp.StatusCode, "the stepped-up session must reach an ordinary route")
	assert.Equal(t, "app-reached", readBody(t, resp))

	resp = s.post(t, "/mfa/recovery-codes", url.Values{})
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"a stepped-up session must be able to regenerate recovery codes")

	resp = s.post(t, "/mfa/disable", url.Values{})
	assert.Equal(t, http.StatusNoContent, resp.StatusCode,
		"a stepped-up session must be able to disable the second factor")
	enrolled, err := s.mfasvc.IsEnrolled(context.Background(), "", s.userID)
	require.NoError(t, err)
	assert.False(t, enrolled)
}

// TestInterimCredential_BadSecondFactorKeepsInterim proves a wrong code mints nothing: the session
// stays interim and therefore stays powerless.
func TestInterimCredential_BadSecondFactorKeepsInterim(t *testing.T) {
	s := newInterimServer(t)
	s.interimLogin(t)

	resp := s.post(t, "/mfa/step-up", url.Values{"code": {"000000"}})
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Nil(t, s.cookie(t, "refresh_token"), "a failed second factor must not upgrade the session")

	resp = s.get(t, "/app")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestMFAGatedLogin_ResponseIsDistinguishable proves the refuter-found MEDIUM: an MFA-gated login
// must be distinguishable on the wire from a full login, otherwise the consumer has no signal to
// drive the step-up flow and will treat the interim credential as a session.
func TestMFAGatedLogin_ResponseIsDistinguishable(t *testing.T) {
	s := newInterimServer(t)
	resp := s.interimLogin(t)

	body := readBody(t, resp)
	var payload struct {
		MFARequired bool `json:"mfa_required"`
	}
	_ = json.Unmarshal([]byte(body), &payload)
	assert.True(t, payload.MFARequired,
		"the MFA-gated login response must carry a machine-readable mfa_required marker; got body %q with status %d",
		body, resp.StatusCode)
}
