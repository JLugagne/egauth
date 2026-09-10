package loginflowtest

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/JLugagne/egauth/authflow"
	"github.com/JLugagne/egauth/identity"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/issuance"
	"github.com/JLugagne/egauth/mfa"
	mfamemory "github.com/JLugagne/egauth/mfa/memory"
	"github.com/JLugagne/egauth/oauth"
	"github.com/JLugagne/egauth/otp"
	otpmemory "github.com/JLugagne/egauth/otp/memory"
	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/JLugagne/egauth/passkey/passkeytest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/basic"
	"github.com/JLugagne/egauth/webapp"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

const (
	engineSecret     = "loginflowtest-engine-hmac-secret-key"
	rpID             = "example.com"
	rpOrigin         = "https://example.com"
	passkeyCookieKey = "loginflowtest-passkey-ceremony-cookie-key"
	oauthStateKey    = "loginflowtest-oauth-state-signing-key"
)

// loginFlows is the conformance table: one entry per exported login entry point.
func loginFlows() []loginFlow {
	return []loginFlow{
		{
			name:        "identity_password_login",
			entrypoints: []string{"identity.LoginHandler"},
			new:         newPasswordHarness,
		},
		{
			name:        "identity_magic_link_login",
			entrypoints: []string{"identity.MagicLinkLoginHandler"},
			new: func(t *testing.T, scn scenario) harness {
				return newMagicLinkHarness(t, scn, false)
			},
		},
		{
			name:        "authflow_engine",
			entrypoints: []string{"authflow.StepUpHandler"},
			new:         newEngineHarness,
			notApplicable: map[invariant]string{
				invTenantUnresolved: "the engine has no per-request tenant resolver; the tenant is carried by the authenticated user record",
				invTenantCross:      "the engine mints for the tenant on the user record and has no request partition to cross into",
			},
			wantEvents: []event.Type{event.LoginSucceeded},
			verifyMFA:  verifyEngineMFA,
		},
		{
			name:        "identity_magic_link_with_authflow",
			entrypoints: []string{"identity.MagicLinkLoginHandler", "authflow.StepUpHandler"},
			new: func(t *testing.T, scn scenario) harness {
				return newMagicLinkHarness(t, scn, true)
			},
			wantEvents: []event.Type{event.LoginSucceeded},
			verifyMFA:  verifyEngineMFA,
		},
		{
			name:        "oauth_callback",
			entrypoints: []string{"oauth.CallbackHandler"},
			new: func(t *testing.T, scn scenario) harness {
				return newOAuthHarness(t, scn, false)
			},
			notApplicable: map[invariant]string{
				invMFAGate: "the native callback has no MFA gate; wire WithAuthFlow to enforce one (covered by oauth_callback_with_authflow)",
			},
		},
		{
			name:        "oauth_callback_with_authflow",
			entrypoints: []string{"oauth.CallbackHandler", "authflow.StepUpHandler"},
			new: func(t *testing.T, scn scenario) harness {
				return newOAuthHarness(t, scn, true)
			},
			wantEvents: []event.Type{event.LoginSucceeded},
			verifyMFA:  verifyEngineMFA,
		},
		{
			name:        "mfa_step_up",
			entrypoints: []string{"mfa.StepUpHandler"},
			new:         newMFAStepUpHarness,
			verifyMFA:   verifyStepUpMFA,
			verifyAudit: verifyStepUpAudit,
		},
		{
			name:        "otp_verify",
			entrypoints: []string{"otp.VerifyHandler"},
			new:         newOTPHarness,
			notApplicable: map[invariant]string{
				invMFAGate: "otp verify has no second-factor gate constructor; the application callback routes issuance through the shared pipeline",
			},
		},
		{
			name:        "passkey_finish_login",
			entrypoints: []string{"passkey.BeginLoginHandler", "passkey.FinishLoginHandler"},
			new: func(t *testing.T, scn scenario) harness {
				return newPasskeyHarness(t, scn, false)
			},
			notApplicable: map[invariant]string{
				invMFAGate:          "passkey finish has no gate constructor; the application login-success hook routes issuance through the shared pipeline",
				invTenantUnresolved: "passkey takes the tenant from its configured resolver accessor; an empty value is the documented single-tenant partition, not a resolution failure",
			},
		},
		{
			name:        "passkey_discoverable_login",
			entrypoints: []string{"passkey.BeginDiscoverableLoginHandler", "passkey.FinishDiscoverableLoginHandler"},
			new: func(t *testing.T, scn scenario) harness {
				return newPasskeyHarness(t, scn, true)
			},
			notApplicable: map[invariant]string{
				invMFAGate:          "passkey finish has no gate constructor; the application login-success hook routes issuance through the shared pipeline",
				invTenantUnresolved: "the discoverable tenant extractor's empty value is the documented single-tenant partition, not a resolution failure",
			},
		},
		{
			name:        "webapp_preset",
			entrypoints: []string{"webapp.NewWebApp"},
			new:         newWebAppHarness,
			notApplicable: map[invariant]string{
				invTenantUnresolved: "the preset uses a fixed configured tenant, not a per-request resolver",
				invClaimsRefresh:    "the preset wires a fixed internal claims builder with no custom-claims seam",
				invMFAGate:          "the preset has no MFA-gate configuration; compose identity.LoginHandler directly for gated logins",
			},
		},
	}
}

// --- password ----------------------------------------------------------------------------

type passwordHarness struct {
	env     *baseEnv
	handler http.HandlerFunc
}

func newPasswordHarness(t *testing.T, scn scenario) harness {
	t.Helper()
	env := newBaseEnv(t, scn)
	opts := []identity.HandlerOption{identity.WithHandlerEventSink(env.sink)}
	if r := tenantResolver(scn); r != nil {
		opts = append(opts, identity.WithTenantResolver(r))
	}
	if scn.mfaEnrolled {
		opts = append(opts, identity.WithMFAGate(stubMFAGate{enrolled: true}))
	}
	env.applyState(scn)
	return &passwordHarness{
		env:     env,
		handler: identity.LoginHandler[struct{}](env.svc, env.issuer, env.claimsBuilder(scn), opts...),
	}
}

func (h *passwordHarness) login(t *testing.T, ctx context.Context) observed {
	t.Helper()
	h.env.reset()
	rec := httptest.NewRecorder()
	h.handler(rec, postForm(t, "/auth/login", url.Values{"email": {h.env.email}, "password": {h.env.password}}))
	return h.env.observe(rec, "")
}

func (h *passwordHarness) verifier() tokens.Verifier[struct{}] { return h.env.issuer.svc }

// --- magic link (native and authflow-backed) ----------------------------------------------

type magicLinkHarness struct {
	env     *baseEnv
	handler http.HandlerFunc
	token   string
	step    *engineStepUp
}

func newMagicLinkHarness(t *testing.T, scn scenario, withFlow bool) harness {
	t.Helper()
	env := newBaseEnv(t, scn)
	token, _, err := env.svc.RequestMagicLink(context.Background(), "", env.email)
	require.NoError(t, err)
	require.NotEmpty(t, token, "a live account must receive a magic link")

	opts := []identity.HandlerOption{identity.WithHandlerEventSink(env.sink)}
	if r := tenantResolver(scn); r != nil {
		opts = append(opts, identity.WithTenantResolver(r))
	}
	var step *engineStepUp
	if withFlow {
		engine := newEngine(t, env, scn)
		opts = append(opts, identity.WithAuthFlow(authflow.NewHandlerFlow(engine)))
		step = &engineStepUp{env: env, engine: engine}
	} else if scn.mfaEnrolled {
		opts = append(opts, identity.WithMFAGate(stubMFAGate{enrolled: true}))
	}
	env.applyState(scn)
	return &magicLinkHarness{
		env:     env,
		token:   token,
		step:    step,
		handler: identity.MagicLinkLoginHandler[struct{}](env.svc, env.issuer, env.claimsBuilder(scn), opts...),
	}
}

func (h *magicLinkHarness) login(t *testing.T, ctx context.Context) observed {
	t.Helper()
	h.env.reset()
	rec := httptest.NewRecorder()
	h.handler(rec, postForm(t, "/auth/magic-link", url.Values{"token": {h.token}}))
	obs := h.env.observe(rec, authflow.DefaultFlowCookieName)
	if h.step != nil {
		if c := findCookie(rec, authflow.DefaultFlowCookieName); c != nil {
			h.step.flowToken = c.Value
		}
	}
	return obs
}

func (h *magicLinkHarness) stepUp(t *testing.T, ctx context.Context) observed {
	t.Helper()
	require.NotNil(t, h.step, "the native magic-link path has no engine step-up")
	return h.step.stepUp(t, ctx)
}

func (h *magicLinkHarness) verifier() tokens.Verifier[struct{}] { return h.env.issuer.svc }

// --- authflow engine ---------------------------------------------------------------------

// stubFactorVerifier accepts any second-factor code; the engine's gate behavior, not the code
// check, is what the conformance suite asserts here.
type stubFactorVerifier struct{}

func (stubFactorVerifier) VerifyTOTP(context.Context, string, uuid.UUID, string) error {
	return nil
}

func (stubFactorVerifier) VerifyRecoveryCode(context.Context, string, uuid.UUID, string) error {
	return nil
}

type engineStepUp struct {
	env       *baseEnv
	engine    *authflow.Engine
	flowToken string
}

func (e *engineStepUp) stepUp(t *testing.T, ctx context.Context) observed {
	t.Helper()
	require.NotEmpty(t, e.flowToken, "the primary attempt must have parked a flow token")
	e.env.reset()
	req := postForm(t, "/auth/flow/step-up", url.Values{"code": {"123456"}})
	req.AddCookie(&http.Cookie{Name: authflow.DefaultFlowCookieName, Value: e.flowToken})
	rec := httptest.NewRecorder()
	authflow.StepUpHandler(e.engine, stubFactorVerifier{})(rec, req)
	return e.env.observe(rec, "")
}

type engineHarness struct{ *engineStepUp }

func newEngineHarness(t *testing.T, scn scenario) harness {
	t.Helper()
	env := newBaseEnv(t, scn)
	engine := newEngine(t, env, scn)
	env.applyState(scn)
	return &engineHarness{engineStepUp: &engineStepUp{env: env, engine: engine}}
}

func newEngine(t *testing.T, env *baseEnv, scn scenario) *authflow.Engine {
	t.Helper()
	opts := []authflow.Option{
		authflow.WithMinter(authflow.NewJWTMinter[struct{}](env.issuer, env.claimsBuilder(scn), env.cookies, false)),
		authflow.WithAccountValidator(authflow.NewIdentityAccountValidator(env.store)),
		authflow.WithEventSink(env.sink),
		authflow.WithPasswordPolicyChecker(env.svc.PasswordChangeRequired),
	}
	if scn.mfaEnrolled {
		opts = append(opts, authflow.WithMFAGate(stubMFAGate{enrolled: true}))
	}
	engine, err := authflow.NewEngine([]byte(engineSecret), opts...)
	require.NoError(t, err)
	return engine
}

func (h *engineHarness) login(t *testing.T, ctx context.Context) observed {
	t.Helper()
	h.env.reset()
	user, err := h.env.store.FindUserByID(ctx, "", h.env.user.ID)
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/flow/primary", nil)
	_, err = h.engine.ProcessPrimaryAuth(ctx, rec, req, user, "password", []string{tokens.AMRPassword}, false,
		authflow.WithPrimaryMustChange(false))
	if err != nil {
		writeRejection(rec, err)
	}
	obs := h.env.observe(rec, authflow.DefaultFlowCookieName)
	if c := obs.cookie(authflow.DefaultFlowCookieName); c != nil {
		h.flowToken = c.Value
	}
	return obs
}

func (h *engineHarness) verifier() tokens.Verifier[struct{}] { return h.env.issuer.svc }

func verifyEngineMFA(t *testing.T, f loginFlow) {
	t.Helper()
	ctx := context.Background()
	base := f.new(t, scenario{mfaEnrolled: true})
	h, ok := base.(stepUpHarness)
	require.True(t, ok, "engine-backed flow must expose step-up completion")

	primary := base.login(t, ctx)
	require.False(t, primary.fullSessionMinted(),
		"the engine must not mint a full session before the second factor")
	require.True(t, primary.Challenged, "the engine must park the ceremony in the MFA-challenged state")

	done := h.stepUp(t, ctx)
	require.True(t, done.fullSessionMinted(),
		"completing the second factor must mint the full renewable pair")
	require.False(t, done.Challenged)
}

// --- oauth callback ----------------------------------------------------------------------

type oauthHarness struct {
	env         *baseEnv
	callback    http.HandlerFunc
	state       string
	stateCookie *http.Cookie
	step        *engineStepUp
}

func newOAuthHarness(t *testing.T, scn scenario, withFlow bool) harness {
	t.Helper()
	env := newBaseEnv(t, scn)
	ctx := context.Background()
	require.NoError(t, env.store.AddIdentity(ctx, "", &identity.Identity{
		UserID:     env.user.ID,
		Provider:   "test",
		ProviderID: "prov-1",
	}))

	provider := newStubProvider(t, env.email)
	redirect := "https://app.example.com/auth/test/callback"

	beginRec := httptest.NewRecorder()
	oauth.BeginHandler(provider,
		oauth.WithStateSigningKey([]byte(oauthStateKey)), oauth.WithRedirectURL(redirect),
	)(beginRec, httptest.NewRequest(http.MethodGet, "/auth/test/login", nil))
	require.Equal(t, http.StatusFound, beginRec.Code, "begin must redirect to the provider")
	stateCookie := findCookie(beginRec, oauth.DefaultStateCookieName)
	require.NotNil(t, stateCookie, "begin must set the signed state cookie")
	loc, err := url.Parse(beginRec.Header().Get("Location"))
	require.NoError(t, err)
	state := loc.Query().Get("state")
	require.NotEmpty(t, state)

	callbackOpts := []oauth.HandlerOption{
		oauth.WithStateSigningKey([]byte(oauthStateKey)),
		oauth.WithRedirectURL(redirect),
		oauth.WithEventSink(env.sink),
	}
	if r := tenantResolver(scn); r != nil {
		callbackOpts = append(callbackOpts, oauth.WithTenantResolver(r))
	}
	var step *engineStepUp
	if withFlow {
		engine := newEngine(t, env, scn)
		callbackOpts = append(callbackOpts, oauth.WithAuthFlow(authflow.NewHandlerFlow(engine)))
		step = &engineStepUp{env: env, engine: engine}
	}
	env.applyState(scn)
	return &oauthHarness{
		env:         env,
		state:       state,
		stateCookie: stateCookie,
		step:        step,
		callback:    oauth.CallbackHandler[struct{}](provider, env.svc, env.issuer, env.claimsBuilder(scn), callbackOpts...),
	}
}

func newStubProvider(t *testing.T, email string) *oauth.Provider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"at-123","token_type":"bearer"}`)
	}))
	t.Cleanup(srv.Close)
	fetch := func(context.Context, *http.Client, string) (*oauth.UserInfo, error) {
		return &oauth.UserInfo{ProviderID: "prov-1", Email: email, EmailVerified: true}, nil
	}
	return oauth.New("test", "cid", "csecret", srv.URL+"/auth", srv.URL+"/token", []string{"email"}, fetch,
		oauth.WithHTTPClient(srv.Client()), oauth.WithInsecureURLs())
}

func (h *oauthHarness) login(t *testing.T, ctx context.Context) observed {
	t.Helper()
	h.env.reset()
	req := httptest.NewRequest(http.MethodGet,
		"/auth/test/callback?"+url.Values{"state": {h.state}, "code": {"auth-code"}}.Encode(), nil)
	req.AddCookie(h.stateCookie)
	rec := httptest.NewRecorder()
	h.callback(rec, req)
	obs := h.env.observe(rec, authflow.DefaultFlowCookieName)
	if h.step != nil {
		if c := findCookie(rec, authflow.DefaultFlowCookieName); c != nil {
			h.step.flowToken = c.Value
		}
	}
	return obs
}

func (h *oauthHarness) stepUp(t *testing.T, ctx context.Context) observed {
	t.Helper()
	require.NotNil(t, h.step, "the native oauth path has no engine step-up")
	return h.step.stepUp(t, ctx)
}

func (h *oauthHarness) verifier() tokens.Verifier[struct{}] { return h.env.issuer.svc }

// --- mfa step-up --------------------------------------------------------------------------

type mfaStepUpHarness struct {
	env         *baseEnv
	handler     http.HandlerFunc
	secret      string
	invalidCode bool
}

func newMFAStepUpHarness(t *testing.T, scn scenario) harness {
	t.Helper()
	env := newBaseEnv(t, scn)
	svc := mfa.NewService(mfamemory.NewStore(), mfa.WithEventSink(env.sink))
	enrollment, err := svc.EnrollTOTP(context.Background(), "", env.user.ID, "conformance")
	require.NoError(t, err)
	code, err := mfa.GenerateCode(enrollment.Secret, time.Now(), mfa.DefaultDigits, mfa.DefaultPeriod)
	require.NoError(t, err)
	_, err = svc.ConfirmTOTP(context.Background(), "", env.user.ID, code)
	require.NoError(t, err)

	claims := func(_ context.Context, uid uuid.UUID, tenant string) tokens.Claims[struct{}] {
		c := tokens.Claims[struct{}]{Subject: uid, TenantID: tenant}
		if scn.claimsRole != "" {
			c.Roles = []string{scn.claimsRole}
		}
		if scn.claimsClear {
			c.MustChangePassword = false
		}
		return c
	}
	opts := []mfa.HandlerOption{
		mfa.WithUserResolver(func(*http.Request) (uuid.UUID, string, bool) {
			return env.user.ID, tenantOfRequest(scn), true
		}),
		mfa.WithSessionStateResolver(env.resolver),
	}
	if r := tenantResolver(scn); r != nil {
		opts = append(opts, mfa.WithTenantResolver(r))
	}
	env.applyState(scn)
	return &mfaStepUpHarness{
		env:         env,
		secret:      enrollment.Secret,
		invalidCode: scn.invalidCode,
		handler:     mfa.StepUpHandler[struct{}](svc, env.issuer, claims, opts...),
	}
}

func (h *mfaStepUpHarness) login(t *testing.T, ctx context.Context) observed {
	t.Helper()
	h.env.reset()
	code := "000000"
	if !h.invalidCode {
		var err error
		// Generate for the next time step: the enrollment consumed a code in the current
		// step, and the replay guard would otherwise reject the identical code here.
		code, err = mfa.GenerateCode(h.secret, time.Now().Add(mfa.DefaultPeriod), mfa.DefaultDigits, mfa.DefaultPeriod)
		require.NoError(t, err)
	}
	rec := httptest.NewRecorder()
	h.handler(rec, postForm(t, "/mfa/step-up", url.Values{"code": {code}}))
	return h.env.observe(rec, "")
}

func (h *mfaStepUpHarness) verifier() tokens.Verifier[struct{}] { return h.env.issuer.svc }

func verifyStepUpMFA(t *testing.T, f loginFlow) {
	t.Helper()
	ctx := context.Background()
	bad := f.new(t, scenario{invalidCode: true}).login(t, ctx)
	assertNoSession(t, bad)

	good := f.new(t, scenario{}).login(t, ctx)
	require.True(t, good.fullSessionMinted(), "a correct second factor must complete the full session")
}

func verifyStepUpAudit(t *testing.T, f loginFlow) {
	t.Helper()
	// The step-up constructor builds its issuance pipeline without an event sink and the MFA
	// service emits only failure events, so a successful step-up currently carries no library
	// event. Keep that gap explicit and assert the audit signal that does exist: the rejection
	// path must be observable.
	obs := f.new(t, scenario{invalidCode: true}).login(t, context.Background())
	assertNoSession(t, obs)
	for _, ev := range obs.Events {
		if ev.Type == event.MFAVerificationFailed {
			return
		}
	}
	t.Errorf("a rejected second factor must emit an audit event, saw %v", obs.Events)
}

// --- otp verify ---------------------------------------------------------------------------

type otpHarness struct {
	env         *baseEnv
	handler     http.HandlerFunc
	code        string
	invalidCode bool
}

func newOTPHarness(t *testing.T, scn scenario) harness {
	t.Helper()
	env := newBaseEnv(t, scn)
	svc := otp.NewService(otpmemory.NewStore(), otp.WithEventSink(env.sink))
	challenge, err := svc.Issue(context.Background(), "", env.user.ID, "login")
	require.NoError(t, err)
	require.NotEmpty(t, challenge.Code)

	pipe, err := issuance.New[struct{}](env.issuer, issuance.WithResolver(env.resolver), issuance.WithEventSink(env.sink))
	require.NoError(t, err)
	requestTenant := tenantOfRequest(scn)
	builder := env.claimsBuilder(scn)
	opts := []otp.HandlerOption{
		otp.WithSubjectResolver(func(*http.Request) (uuid.UUID, bool) { return env.user.ID, true }),
		otp.WithOnVerified(func(w http.ResponseWriter, r *http.Request, subjectID uuid.UUID) {
			res, err := pipe.Issue(r.Context(), issuance.Request[struct{}]{
				TenantID: requestTenant,
				UserID:   subjectID,
				Claims:   builder(env.user),
				Method:   "otp",
				AMR:      []string{tokens.AMROTP},
			})
			if err != nil {
				writeRejection(w, err)
				return
			}
			env.cookies.SetAccess(w, res.Pair.AccessToken)
			if !res.Interim {
				env.cookies.SetRefresh(w, res.Pair.RefreshToken, res.Pair.RefreshTokenExpiresAt, false)
			}
		}),
	}
	if r := tenantResolver(scn); r != nil {
		opts = append(opts, otp.WithTenantResolver(r))
	}
	env.applyState(scn)
	return &otpHarness{
		env:         env,
		code:        challenge.Code,
		invalidCode: scn.invalidCode,
		handler:     otp.VerifyHandler(svc, opts...),
	}
}

func (h *otpHarness) login(t *testing.T, ctx context.Context) observed {
	t.Helper()
	h.env.reset()
	code := h.code
	if h.invalidCode {
		code = "000000"
	}
	rec := httptest.NewRecorder()
	h.handler(rec, postForm(t, "/otp/verify", url.Values{"code": {code}}))
	return h.env.observe(rec, "")
}

func (h *otpHarness) verifier() tokens.Verifier[struct{}] { return h.env.issuer.svc }

// --- passkey login ------------------------------------------------------------------------

type passkeyHarness struct {
	env          *baseEnv
	svc          *passkey.Service
	opts         []passkey.HandlerOption
	auth         *passkeytest.SoftAuthenticator
	discoverable bool
}

func newPasskeyHarness(t *testing.T, scn scenario, discoverable bool) harness {
	t.Helper()
	env := newBaseEnv(t, scn)
	svc, err := passkey.NewService(passkeymemory.NewStore(), passkey.Config{
		RPID:           rpID,
		RPDisplayName:  "Conformance",
		RPOrigins:      []string{rpOrigin},
		CookieKey:      []byte(passkeyCookieKey),
		ChallengeStore: passkeymemory.NewChallengeStore(),
		AccountGate:    passkey.NewIdentityAccountGate(env.store),
		Events:         env.sink,
	})
	require.NoError(t, err)

	auth := passkeytest.NewSoftAuthenticator(t, rpID, rpOrigin)
	_, session, err := svc.BeginRegistration(context.Background(), "", env.user.ID, env.email, "Conformance User")
	require.NoError(t, err)
	_, err = svc.FinishRegistration(context.Background(), "", env.user.ID, env.email, "Conformance User", *session,
		auth.RegistrationRequest(t, session.Challenge))
	require.NoError(t, err)

	pipe, err := issuance.New[struct{}](env.issuer, issuance.WithResolver(env.resolver), issuance.WithEventSink(env.sink))
	require.NoError(t, err)
	builder := env.claimsBuilder(scn)
	success := func(w http.ResponseWriter, r *http.Request, uid uuid.UUID, tenant string) {
		res, err := pipe.Issue(r.Context(), issuance.Request[struct{}]{
			TenantID: tenant,
			UserID:   uid,
			Claims:   builder(env.user),
			Method:   "passkey",
			AMR:      []string{tokens.AMRWebAuthn},
		})
		if err != nil {
			writeRejection(w, err)
			return
		}
		env.cookies.SetAccess(w, res.Pair.AccessToken)
		if !res.Interim {
			env.cookies.SetRefresh(w, res.Pair.RefreshToken, res.Pair.RefreshTokenExpiresAt, false)
		}
	}
	tenant := tenantOfRequest(scn)
	opts := []passkey.HandlerOption{
		passkey.WithUserResolver(func(*http.Request) (uuid.UUID, string, string, string, bool) {
			return env.user.ID, env.email, "Conformance User", tenant, true
		}),
		passkey.WithLoginSuccessWithTenant(success),
	}
	if discoverable {
		opts = append(opts, passkey.WithDiscoverableTenant(func(*http.Request) string { return tenant }))
	}
	env.applyState(scn)
	return &passkeyHarness{env: env, svc: svc, opts: opts, auth: auth, discoverable: discoverable}
}

func (h *passkeyHarness) login(t *testing.T, ctx context.Context) observed {
	t.Helper()
	h.env.reset()
	if h.discoverable {
		beginRec := httptest.NewRecorder()
		passkey.BeginDiscoverableLoginHandler(h.svc, h.opts...)(
			beginRec, httptest.NewRequest(http.MethodPost, "/passkey/login/begin", nil))
		require.Equal(t, http.StatusOK, beginRec.Code, "discoverable begin must succeed")
		cookie := findCookie(beginRec, passkey.DefaultSessionCookieName)
		require.NotNil(t, cookie, "begin must set the ceremony cookie")
		finishReq := h.auth.LoginRequest(t, challengeFromJSON(t, beginRec.Body.Bytes()), passkeytest.UserHandleOf(h.env.user.ID))
		finishReq.AddCookie(cookie)
		rec := httptest.NewRecorder()
		passkey.FinishDiscoverableLoginHandler(h.svc, h.opts...)(rec, finishReq)
		return h.env.observe(rec, "")
	}

	beginRec := httptest.NewRecorder()
	passkey.BeginLoginHandler(h.svc, h.opts...)(
		beginRec, httptest.NewRequest(http.MethodPost, "/passkey/login/begin", nil))
	if beginRec.Code != http.StatusOK {
		// The lifecycle gate (or a missing credential for the requested tenant) can refuse
		// the ceremony before any assertion: surface that response for the assertions.
		return h.env.observe(beginRec, "")
	}
	cookie := findCookie(beginRec, passkey.DefaultSessionCookieName)
	require.NotNil(t, cookie, "begin must set the ceremony cookie")
	finishReq := h.auth.LoginRequest(t, challengeFromJSON(t, beginRec.Body.Bytes()), passkeytest.UserHandleOf(h.env.user.ID))
	finishReq.AddCookie(cookie)
	rec := httptest.NewRecorder()
	passkey.FinishLoginHandler(h.svc, h.opts...)(rec, finishReq)
	return h.env.observe(rec, "")
}

func (h *passkeyHarness) verifier() tokens.Verifier[struct{}] { return h.env.issuer.svc }

func challengeFromJSON(t *testing.T, raw []byte) string {
	t.Helper()
	var body struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal(raw, &body))
	require.NotEmpty(t, body.PublicKey.Challenge, "begin response must carry a challenge")
	return body.PublicKey.Challenge
}

// --- webapp preset ------------------------------------------------------------------------

type webappHarness struct {
	env    *baseEnv
	mux    http.Handler
	verify *basic.Issuer
	tenant string
}

func newWebAppHarness(t *testing.T, scn scenario) harness {
	t.Helper()
	env := newBaseEnv(t, scn)
	const signingKey = "loginflowtest-webapp-signing-key-0123456789"
	tokenStore := basic.NewMemoryStore()
	cfg := webapp.Config{
		Identity:              env.svc,
		TokenStore:            tokenStore,
		SigningKey:            signingKey,
		Issuer:                "loginflowtest",
		InsecureNoOriginCheck: true,
		InsecureNoRateLimit:   true,
		EventSink:             env.sink,
	}
	if scn.tenant == tenantCross {
		cfg.Tenant = crossTenant
	}
	mux, err := webapp.NewWebApp(cfg)
	require.NoError(t, err)
	verify := basic.NewIssuer(basic.Config{
		Store:      tokenStore,
		Issuer:     "loginflowtest",
		SecretKey:  signingKey,
		AccessTTL:  webapp.DefaultAccessTTL,
		RefreshTTL: webapp.DefaultRefreshTTL,
	})
	env.applyState(scn)
	return &webappHarness{env: env, mux: mux, verify: verify, tenant: tenantOfRequest(scn)}
}

func (h *webappHarness) login(t *testing.T, ctx context.Context) observed {
	t.Helper()
	h.env.reset()
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, postForm(t, "/auth/login", url.Values{"email": {h.env.email}, "password": {h.env.password}}))
	obs := h.env.observe(rec, "")
	// The preset owns its issuer, so reconstruct the minted pair from the delivered cookie by
	// verifying it with an identically-configured issuer. This is what lets the shared
	// must-change and audit assertions run against the preset.
	if c := obs.accessCookie(); c != nil {
		if claims, err := h.verify.VerifyAccessTokenForTenant(ctx, h.tenant, c.Value); err == nil {
			obs.Pairs = append(obs.Pairs, &tokens.TokenPair[struct{}]{AccessToken: c.Value, Claims: *claims})
		}
	}
	return obs
}

func (h *webappHarness) verifier() tokens.Verifier[struct{}] { return h.verify }

// --- coverage guard -----------------------------------------------------------------------

// loginPackages are the packages that own exported login entry points.
var loginPackages = []string{
	"authflow",
	"identity",
	"oauth",
	"mfa",
	"otp",
	"passkey",
	"webapp",
}

// requiredFlowConstructors are the exported login entry points the conformance table must
// exercise. A rename or removal of any of them fails TestAllLoginFlowsRegistered until the
// table (and this list) is updated.
var requiredFlowConstructors = []string{
	"identity.LoginHandler",
	"identity.MagicLinkLoginHandler",
	"authflow.StepUpHandler",
	"oauth.CallbackHandler",
	"mfa.StepUpHandler",
	"otp.VerifyHandler",
	"passkey.FinishLoginHandler",
	"passkey.FinishDiscoverableLoginHandler",
	"webapp.NewWebApp",
}

// nonFlowConstructors records constructors that match the login name heuristic but are not
// session-issuing login entry points, with the reason each is out of scope.
var nonFlowConstructors = map[string]string{
	"oauth.DynamicCallbackHandler":              "dynamic-provider wrapper around oauth.CallbackHandler; the issuance path is identical",
	"otp.IssueHandler":                          "mints and delivers a one-time challenge, not a session",
	"identity.RegisterHandler":                  "self-registration auto-login; the account is created in the same request, and the issuance pipeline is covered by identity_password_login",
	"identity.ChangePasswordWithReissueHandler": "authenticated re-issuance after a password change; uses the same identity issuance pipeline as identity_password_login",
}

// looksLikeLoginFlow is the heuristic that catches newly added login entry points: any
// constructor whose name advertises a login/step-up/callback/mint/issuance role must be
// classified in the table (or in nonFlowConstructors) before it can ship.
func looksLikeLoginFlow(name string) bool {
	markers := []string{"Login", "StepUp", "Callback", "Mint", "Issue", "Register", "Reissue", "WebApp"}
	for _, m := range markers {
		if strings.Contains(name, m) {
			return true
		}
	}
	return false
}

// TestAllLoginFlowsRegistered is the coverage guard: every required login constructor must be
// present in the source and exercised by a table entry, and every heuristic login-shaped
// constructor must be covered or explicitly exempted.
func TestAllLoginFlowsRegistered(t *testing.T) {
	root := repoRoot(t)
	found := scanHandlerConstructors(t, root)
	foundSet := make(map[string]bool, len(found))
	for _, c := range found {
		foundSet[c] = true
	}
	covered := make(map[string]string)
	for _, f := range loginFlows() {
		for _, entrypoint := range f.entrypoints {
			covered[entrypoint] = f.name
		}
	}

	for _, required := range requiredFlowConstructors {
		if !foundSet[required] {
			t.Errorf("required login constructor %s is no longer present in the source; update the conformance table and this list", required)
		}
		if covered[required] == "" {
			t.Errorf("login constructor %s is not exercised by any conformance table entry", required)
		}
	}
	for _, c := range found {
		if covered[c] != "" {
			continue
		}
		if reason, exempt := nonFlowConstructors[c]; exempt {
			if strings.TrimSpace(reason) == "" {
				t.Errorf("constructor %s is exempted without a reason", c)
			}
			continue
		}
		if looksLikeLoginFlow(c) {
			t.Errorf("login constructor %s is neither in the conformance table nor explicitly exempted: add a table entry or record why it is out of scope", c)
		}
	}
	for entrypoint := range covered {
		if !foundSet[entrypoint] {
			t.Errorf("conformance table references %s, which is not an exported handler constructor in the scanned packages", entrypoint)
		}
	}
}

// TestCoverageGuardRejectsNewLoginHandler demonstrates the guard: a synthetic login-shaped
// constructor that no table entry covers is reported by the same predicate the guard uses.
func TestCoverageGuardRejectsNewLoginHandler(t *testing.T) {
	c := "identity.PasswordlessLoginHandler"
	if !looksLikeLoginFlow(c) {
		t.Fatalf("%s must be treated as a login entry point", c)
	}
	if reason, exempt := nonFlowConstructors[c]; exempt {
		t.Fatalf("%s must not be exempt, got %q", c, reason)
	}
}

// scanHandlerConstructors returns the sorted "pkg.Func" names of every exported package-level
// function across the login packages whose results include http.Handler or http.HandlerFunc.
func scanHandlerConstructors(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	for _, pkg := range loginPackages {
		dir := filepath.Join(root, filepath.FromSlash(pkg))
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("reading login package %s: %v", pkg, err)
		}
		fset := token.NewFileSet()
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
			if err != nil {
				t.Fatalf("parsing %s/%s: %v", pkg, name, err)
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || !fn.Name.IsExported() {
					continue
				}
				if returnsHTTPHandler(fn.Type.Results) {
					found = append(found, filepath.Base(pkg)+"."+fn.Name.Name)
				}
			}
		}
	}
	sort.Strings(found)
	return found
}

// returnsHTTPHandler reports whether a result list contains http.Handler or http.HandlerFunc.
func returnsHTTPHandler(results *ast.FieldList) bool {
	if results == nil {
		return false
	}
	for _, field := range results.List {
		sel, ok := field.Type.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "http" {
			continue
		}
		if sel.Sel.Name == "Handler" || sel.Sel.Name == "HandlerFunc" {
			return true
		}
	}
	return false
}

// repoRoot returns the module root (the parent of internal/) from this test file's location.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found at %s: %v", root, err)
	}
	return root
}

// findCookie returns the named cookie from a recorder's response, or nil.
func findCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}
