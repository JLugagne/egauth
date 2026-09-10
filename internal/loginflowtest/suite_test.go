package loginflowtest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	"github.com/JLugagne/egauth/issuance"
	"github.com/JLugagne/egauth/passwords/argon2"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	tokenmemory "github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// invariant is one post-authentication control the suite asserts identically across flows.
type invariant string

const (
	// invDisabled: a disabled account cannot obtain a session, whichever layer catches it.
	invDisabled invariant = "disabled_account"
	// invDeleted: a deleted/anonymized account cannot obtain a session.
	invDeleted invariant = "deleted_account"
	// invTenantUnresolved: a configured request-tenant resolver returning "" fails closed.
	invTenantUnresolved invariant = "tenant_resolver_empty"
	// invTenantCross: a flow driven for another tenant cannot mint a session for a user of a
	// different partition.
	invTenantCross invariant = "cross_tenant"
	// invMustChange: MustChangePassword is propagated into the issued claims, a caller cannot
	// clear it, and tokens.WithPasswordChangeGate blocks the flagged session.
	invMustChange invariant = "must_change_password"
	// invMFAGate: a configured MFA/step-up gate withholds the full renewable pair until the
	// second factor is verified.
	invMFAGate invariant = "mfa_gate"
	// invClaimsRefresh: the claims builder is re-evaluated at issuance, so updated claims
	// (e.g. a new role) are reflected in the minted pair.
	invClaimsRefresh invariant = "claims_reevaluation"
	// invAuditEvent: the login emits an audit event (type configurable per flow).
	invAuditEvent invariant = "issuance_event"
	// invUniformFailure: no rejection path mints a session, whatever its status code.
	invUniformFailure invariant = "uniform_failure"
)

// allInvariants is the order the suite reports invariant subtests in.
var allInvariants = []invariant{
	invDisabled,
	invDeleted,
	invTenantUnresolved,
	invTenantCross,
	invMustChange,
	invMFAGate,
	invClaimsRefresh,
	invAuditEvent,
	invUniformFailure,
}

// userState selects the authoritative account lifecycle to set up before the login attempt.
type userState int

const (
	userActive userState = iota
	userDisabled
	userDeleted
)

// tenantMode selects how the flow is asked to resolve the request tenant.
type tenantMode int

const (
	// tenantNormal uses the single-tenant default partition ("").
	tenantNormal tenantMode = iota
	// tenantUnresolved configures a request-tenant resolver that answers "".
	tenantUnresolved
	// tenantCross drives the flow for a different, existing partition.
	tenantCross
)

// crossTenant is the mismatching partition used by the cross-tenant invariant.
const crossTenant = "other-tenant"

// scenario is the input each flow harness is built from. A fresh harness (and therefore a fresh
// in-memory world) is built per assertion so state cannot leak between invariant runs.
type scenario struct {
	user        userState
	tenant      tenantMode
	mustChange  bool
	claimsClear bool
	claimsRole  string
	mfaEnrolled bool
	invalidCode bool
}

// tenantOfRequest returns the tenant a harness should associate with the request. The
// single-tenant default is ""; the cross-tenant scenario uses crossTenant.
func tenantOfRequest(scn scenario) string {
	if scn.tenant == tenantCross {
		return crossTenant
	}
	return ""
}

// tenantResolver returns a configured request-tenant resolver for the scenarios that need one.
// A nil return means no resolver is configured at all (the legitimate single-tenant default).
func tenantResolver(scn scenario) func(*http.Request) string {
	switch scn.tenant {
	case tenantUnresolved:
		return func(*http.Request) string { return "" }
	case tenantCross:
		return func(*http.Request) string { return crossTenant }
	default:
		return nil
	}
}

// observed is the client-visible and auditable outcome of one login attempt.
type observed struct {
	Status  int
	Cookies []*http.Cookie
	Pairs   []*tokens.TokenPair[struct{}]
	Events  []event.Event
	// Challenged reports that the flow parked the ceremony (e.g. wrote an auth-flow token or
	// otherwise demanded a second factor) instead of delivering credentials.
	Challenged bool
}

func (o observed) cookie(name string) *http.Cookie {
	for _, c := range o.Cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func (o observed) accessCookie() *http.Cookie  { return o.cookie(tokens.DefaultAccessCookieName) }
func (o observed) refreshCookie() *http.Cookie { return o.cookie(tokens.DefaultRefreshCookieName) }

// fullSessionMinted reports whether a complete, renewable pair reached the client.
func (o observed) fullSessionMinted() bool {
	return o.accessCookie() != nil && o.refreshCookie() != nil
}

// sessionMinted reports whether the flow minted or delivered any session material at all.
func (o observed) sessionMinted() bool {
	return len(o.Pairs) > 0 || o.accessCookie() != nil || o.refreshCookie() != nil
}

// challengedOrInterim reports whether an enrolled user was parked short of a full session: an
// access-only interim token or an MFA-challenged ceremony.
func (o observed) challengedOrInterim() bool {
	return o.Challenged || (o.accessCookie() != nil && o.refreshCookie() == nil)
}

// harness drives one login entry point once and exposes the verifier needed to exercise the
// password-change middleware on the minted token.
type harness interface {
	login(t *testing.T, ctx context.Context) observed
	verifier() tokens.Verifier[struct{}]
}

// stepUpHarness is implemented by flows that can complete a second factor after the primary
// attempt was parked in the MFA-challenged state.
type stepUpHarness interface {
	stepUp(t *testing.T, ctx context.Context) observed
}

// loginFlow is one table entry. notApplicable records invariants the flow genuinely cannot
// exercise, each with the reason it does not apply.
type loginFlow struct {
	name          string
	entrypoints   []string
	new           func(t *testing.T, scn scenario) harness
	notApplicable map[invariant]string
	// wantEvents overrides the default audit-event expectation (event.SessionIssued).
	wantEvents []event.Type
	// verifyMFA overrides the generic MFA-gate assertion for flows whose gate completes
	// internally (the authflow engine) or whose second factor is the flow itself (step-up).
	verifyMFA func(t *testing.T, f loginFlow)
	// verifyAudit overrides the generic issuance-event assertion for flows whose success path
	// emits differently; it must still assert an observable audit event.
	verifyAudit func(t *testing.T, f loginFlow)
}

// TestLoginFlowInvariants runs every applicable invariant against every flow in the table.
func TestLoginFlowInvariants(t *testing.T) {
	for _, f := range loginFlows() {
		f := f
		t.Run(f.name, func(t *testing.T) {
			for _, inv := range allInvariants {
				inv := inv
				t.Run(string(inv), func(t *testing.T) {
					if reason, skipped := f.notApplicable[inv]; skipped {
						t.Skipf("not applicable: %s", reason)
					}
					runInvariant(t, f, inv)
				})
			}
		})
	}
}

// runInvariant dispatches one invariant against one flow.
func runInvariant(t *testing.T, f loginFlow, inv invariant) {
	t.Helper()
	ctx := context.Background()
	switch inv {
	case invDisabled:
		assertNoSession(t, f.new(t, scenario{user: userDisabled}).login(t, ctx))

	case invDeleted:
		assertNoSession(t, f.new(t, scenario{user: userDeleted}).login(t, ctx))

	case invTenantUnresolved:
		assertNoSession(t, f.new(t, scenario{tenant: tenantUnresolved}).login(t, ctx))

	case invTenantCross:
		assertNoSession(t, f.new(t, scenario{tenant: tenantCross}).login(t, ctx))

	case invMustChange:
		h := f.new(t, scenario{mustChange: true, claimsClear: true})
		obs := h.login(t, ctx)
		require.NotEmpty(t, obs.Pairs, "a must-change user must still be issued a session")
		for _, pair := range obs.Pairs {
			require.True(t, pair.Claims.MustChangePassword,
				"the forced-change flag must survive a caller-passed false; the pipeline derives it from authoritative state")
		}
		assertPasswordChangeGateBlocks(t, obs, h.verifier())

	case invMFAGate:
		if f.verifyMFA != nil {
			f.verifyMFA(t, f)
			return
		}
		obs := f.new(t, scenario{mfaEnrolled: true}).login(t, ctx)
		require.False(t, obs.fullSessionMinted(),
			"an MFA-enrolled user must not receive a full renewable session from the primary factor alone")
		require.True(t, obs.challengedOrInterim(),
			"the flow must park the ceremony in an interim or MFA-challenged state")

	case invClaimsRefresh:
		h := f.new(t, scenario{claimsRole: "conformance-admin"})
		obs := h.login(t, ctx)
		require.NotEmpty(t, obs.Pairs, "the flow must issue a session to evaluate claims")
		require.Contains(t, obs.Pairs[0].Claims.Roles, "conformance-admin",
			"claims rebuilt at issuance must be reflected in the minted pair")

	case invAuditEvent:
		if f.verifyAudit != nil {
			f.verifyAudit(t, f)
			return
		}
		want := f.wantEvents
		if len(want) == 0 {
			want = []event.Type{event.SessionIssued}
		}
		obs := f.new(t, scenario{}).login(t, ctx)
		var seen []string
		for _, ev := range obs.Events {
			for _, w := range want {
				if ev.Type == w {
					return
				}
			}
			seen = append(seen, string(ev.Type))
		}
		t.Errorf("no issuance audit event observed: want one of %v, saw %v", want, seen)

	case invUniformFailure:
		scenarios := []scenario{{user: userDisabled}, {user: userDeleted}}
		if _, skipped := f.notApplicable[invTenantUnresolved]; !skipped {
			scenarios = append(scenarios, scenario{tenant: tenantUnresolved})
		}
		if _, skipped := f.notApplicable[invTenantCross]; !skipped {
			scenarios = append(scenarios, scenario{tenant: tenantCross})
		}
		for _, scn := range scenarios {
			obs := f.new(t, scn).login(t, ctx)
			assertNoSession(t, obs)
			assert.GreaterOrEqual(t, obs.Status, http.StatusBadRequest,
				"a rejected login must not answer with a success status")
		}
	}
}

// assertNoSession fails when any session material was minted or delivered.
func assertNoSession(t *testing.T, obs observed) {
	t.Helper()
	assert.Nil(t, obs.accessCookie(), "a rejected login must not set an access cookie")
	assert.Nil(t, obs.refreshCookie(), "a rejected login must not set a refresh cookie")
	assert.Empty(t, obs.Pairs, "a rejected login must not mint a token pair")
}

// assertPasswordChangeGateBlocks verifies that the minted, flagged access token is refused by
// tokens.WithPasswordChangeGate, i.e. the advisory flag is actually enforced by middleware.
func assertPasswordChangeGateBlocks(t *testing.T, obs observed, verifier tokens.Verifier[struct{}]) {
	t.Helper()
	require.NotEmpty(t, obs.Pairs, "the gate check needs a minted access token")
	token := obs.Pairs[0].AccessToken
	require.NotEmpty(t, token)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: tokens.DefaultAccessCookieName, Value: token})
	rec := httptest.NewRecorder()
	tokens.RequireAuth[struct{}](
		verifier,
		func(w http.ResponseWriter, _ *http.Request, _ egauth.Actor, _ struct{}) {
			w.WriteHeader(http.StatusNoContent)
		},
		tokens.WithCookieAuth[struct{}](tokens.DefaultCookies()),
		tokens.WithPasswordChangeGate[struct{}]("/auth/change-password"),
	)(rec, req)

	require.NotEqual(t, http.StatusNoContent, rec.Code,
		"a flagged token must not pass WithPasswordChangeGate")
	assert.Equal(t, http.StatusSeeOther, rec.Code,
		"the gate must divert the flagged session to the configured reset URL")
}

// recordingSink captures every emitted event.
type recordingSink struct {
	mu     sync.Mutex
	events []event.Event
}

func (s *recordingSink) EmitEvent(_ context.Context, ev event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *recordingSink) snapshot() []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]event.Event(nil), s.events...)
}

func (s *recordingSink) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = nil
}

// recordingIssuer mints real JWTs (so tokens can be verified by the middleware) while recording
// every pair, which is how the shared assertions observe issuance.
type recordingIssuer struct {
	svc   *jwt.Service[struct{}]
	mu    sync.Mutex
	pairs []*tokens.TokenPair[struct{}]
}

func newRecordingIssuer(t *testing.T) *recordingIssuer {
	t.Helper()
	return &recordingIssuer{svc: jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      tokenmemory.NewStore[struct{}](),
		SecretKey:  "loginflowtest-signing-key-not-for-production",
		Issuer:     "loginflowtest",
		AccessTTL:  5 * time.Minute,
		RefreshTTL: time.Hour,
	})}
}

func (r *recordingIssuer) IssueTokenPair(ctx context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
	pair, err := r.svc.IssueTokenPair(ctx, claims)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.pairs = append(r.pairs, pair)
	r.mu.Unlock()
	return pair, nil
}

func (r *recordingIssuer) IssueAPIKey(ctx context.Context, prefix string, keyType tokens.KeyType, createdBy uuid.UUID, claims tokens.Claims[struct{}]) (*tokens.APIKey[struct{}], error) {
	return r.svc.IssueAPIKey(ctx, prefix, keyType, createdBy, claims)
}

func (r *recordingIssuer) take() []*tokens.TokenPair[struct{}] {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.pairs
	r.pairs = nil
	return out
}

// stubMFAGate is an enrollment checker that satisfies the gate seam of every package.
type stubMFAGate struct{ enrolled bool }

func (g stubMFAGate) IsEnrolled(context.Context, string, uuid.UUID) (bool, error) {
	return g.enrolled, nil
}

// baseEnv is the shared in-memory world for one login attempt: a real identity service over the
// memory store, a recording issuer, a recording event sink and the registered user.
type baseEnv struct {
	t        *testing.T
	store    *identitymemory.Store
	svc      identity.Service
	resolver issuance.Resolver
	user     *identity.User
	email    string
	password string
	sink     *recordingSink
	issuer   *recordingIssuer
	cookies  tokens.Cookies
}

func newBaseEnv(t *testing.T, scn scenario) *baseEnv {
	t.Helper()
	sink := &recordingSink{}
	store := identitymemory.NewStore()
	svc := identity.NewService(store, argon2.NewHasher(), policy.NewDefaultPolicy(),
		identity.WithEventSink(sink))
	resolver, ok := svc.(identity.SessionStateReader)
	require.True(t, ok, "the built-in identity service must expose authoritative session state")

	const password = "Sup3rSecret!pass"
	email := fmt.Sprintf("user-%s@example.com", strings.ReplaceAll(uuid.Must(uuid.NewV7()).String(), "-", "")[:10])

	var (
		user *identity.User
		err  error
	)
	if scn.mustChange {
		user, err = svc.AdminCreateUser(context.Background(), "", email, password)
	} else {
		user, err = svc.Register(context.Background(), "", email, password)
	}
	require.NoError(t, err)

	return &baseEnv{
		t:        t,
		store:    store,
		svc:      svc,
		resolver: resolver,
		user:     user,
		email:    email,
		password: password,
		sink:     sink,
		issuer:   newRecordingIssuer(t),
		cookies:  tokens.DefaultCookies(),
	}
}

// applyState mutates the account lifecycle after any credentials/tokens have been prepared. A
// deleted account is soft-deleted through the service, so the store retains the record (with
// DeletedAt set) exactly as a real deployment would.
func (e *baseEnv) applyState(scn scenario) {
	e.t.Helper()
	ctx := context.Background()
	switch scn.user {
	case userDisabled:
		require.NoError(e.t, e.svc.DisableUser(ctx, "", e.user.ID))
	case userDeleted:
		require.NoError(e.t, e.svc.DeleteAccount(ctx, "", e.user.ID))
	}
}

// claimsBuilder returns the application claims builder used at issuance. It deliberately sets
// MustChangePassword=false when the scenario says so, proving the pipeline (not the caller)
// owns the authoritative flag. A role can be injected to observe claims re-evaluation.
func (e *baseEnv) claimsBuilder(scn scenario) identity.ClaimsBuilder[struct{}] {
	return func(u *identity.User) tokens.Claims[struct{}] {
		claims := tokens.Claims[struct{}]{Subject: u.ID, TenantID: u.TenantID}
		if scn.claimsRole != "" {
			claims.Roles = []string{scn.claimsRole}
		}
		if scn.claimsClear {
			claims.MustChangePassword = false
		}
		return claims
	}
}

// reset clears the per-attempt observations before the flow is driven.
func (e *baseEnv) reset() {
	e.sink.reset()
	e.issuer.take()
}

// observe snapshots everything recorded during the attempt and computes the MFA-challenge bit
// from the auth-flow cookie, which the engine writes when it parks a ceremony.
func (e *baseEnv) observe(rec *httptest.ResponseRecorder, flowCookieName string) observed {
	obs := observed{
		Status:  rec.Code,
		Cookies: rec.Result().Cookies(),
		Pairs:   e.issuer.take(),
		Events:  e.sink.snapshot(),
	}
	if flowCookieName != "" && obs.cookie(flowCookieName) != nil {
		obs.Challenged = true
	}
	return obs
}

// postForm builds a same-origin POST form request, matching how the handlers' CSRF-by-default
// origin check expects browser traffic.
func postForm(t *testing.T, path string, values url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://"+req.Host)
	return req
}

// writeRejection maps a flow error to a client-visible failure status for harnesses that drive
// a library API directly instead of an HTTP handler.
func writeRejection(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrAccountDisabled):
		http.Error(w, "account_disabled", http.StatusForbidden)
	case errors.Is(err, identity.ErrUserNotFound), errors.Is(err, identity.ErrInvalidCredentials):
		http.Error(w, "invalid_credentials", http.StatusUnauthorized)
	default:
		http.Error(w, "flow_failed", http.StatusInternalServerError)
	}
}
