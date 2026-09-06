package oauth

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/JLugagne/egauth/authflow"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// flowRecordingMinter captures flows handed to the engine's SessionMinter (SEC-GLO-02 tests).
type flowRecordingMinter struct {
	flows []*authflow.FlowContext
}

func (m *flowRecordingMinter) Mint(ctx context.Context, w http.ResponseWriter, r *http.Request, flow *authflow.FlowContext) error {
	m.flows = append(m.flows, flow)
	return nil
}

// enrolledGateStub is a minimal authflow.MFAGate double for the callback wiring tests.
type enrolledGateStub struct{ enrolled bool }

func (g enrolledGateStub) IsEnrolled(ctx context.Context, tenantID string, userID uuid.UUID) (bool, error) {
	return g.enrolled, nil
}

// newFlowTestEngine assembles an authflow engine the way an application would: signed flow
// tokens, an MFA enrollment gate, and a recording minter.
func newFlowTestEngine(t *testing.T, enrolled bool, minter *flowRecordingMinter) *authflow.Engine {
	t.Helper()
	engine, err := authflow.NewEngine([]byte("01234567890123456789012345678901"),
		authflow.WithMFAGate(enrolledGateStub{enrolled: enrolled}),
		authflow.WithMinter(minter),
	)
	require.NoError(t, err)
	return engine
}

// TestCallbackHandler_AuthFlow_EnrolledChallengesWithoutCredentials proves the SEC-GLO-02 fix
// (issue #71): an OAuth callback wired with WithAuthFlow must NOT mint a full token pair for an
// MFA-enrolled user. The engine parks the ceremony in the challenged state, setting only the
// flow-token cookie; the second factor completes via authflow.StepUpHandler.
func TestCallbackHandler_AuthFlow_EnrolledChallengesWithoutCredentials(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true,"name":"U"}`
	p, _ := stubProviderServer(t, &body)
	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}
	minter := &flowRecordingMinter{}
	engine := newFlowTestEngine(t, true, minter)

	rec := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect),
		WithAuthFlow(authflow.NewHandlerFlow(engine)))

	require.Equal(t, http.StatusNoContent, rec.Code)
	var flowCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, tokens.DefaultAccessCookieName, c.Name,
			"SEC-GLO-02: a challenged OAuth flow must not receive an access cookie")
		assert.NotEqual(t, tokens.DefaultRefreshCookieName, c.Name,
			"SEC-GLO-02: a challenged OAuth flow must not receive a refresh cookie")
		if c.Name == authflow.DefaultFlowCookieName {
			flowCookie = c
		}
	}
	assert.Empty(t, minter.flows, "no credentials may be minted before the second factor")
	require.NotNil(t, flowCookie, "the flow-token cookie must be set so the client can step up")
	assert.NotEmpty(t, flowCookie.Value)
	assert.True(t, flowCookie.HttpOnly)
}

// TestCallbackHandler_AuthFlow_NotEnrolledMintsViaEngine proves delegation: with no enrolled
// factor the engine completes and its minter — not the handler's issuer — issues credentials,
// preserving the oauth AMR and the provider-stamped method.
func TestCallbackHandler_AuthFlow_NotEnrolledMintsViaEngine(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true,"name":"U"}`
	p, _ := stubProviderServer(t, &body)
	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	uid := uuid.Must(uuid.NewV7())
	linker := &stubLinker{user: &identity.User{ID: uid, Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}
	minter := &flowRecordingMinter{}
	engine := newFlowTestEngine(t, false, minter)

	rec := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect),
		WithAuthFlow(authflow.NewHandlerFlow(engine)))

	require.Equal(t, http.StatusNoContent, rec.Code)
	require.Len(t, minter.flows, 1, "the engine minter must issue the final credentials")
	flow := minter.flows[0]
	assert.Equal(t, uid, flow.UserID)
	assert.Equal(t, "oauth:"+p.Name(), flow.PrimaryFactor)
	assert.Equal(t, []string{"oauth"}, flow.AMR)

	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, tokens.DefaultAccessCookieName, c.Name,
			"the legacy issuance path must be bypassed when a flow engine is configured")
		assert.NotEqual(t, tokens.DefaultRefreshCookieName, c.Name,
			"the legacy issuance path must be bypassed when a flow engine is configured")
	}
}
