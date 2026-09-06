package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/JLugagne/egauth/authflow"
	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingMinter captures the flows an authflow.Engine hands to its SessionMinter so the
// magic-link wiring tests can assert what the engine decided to issue (or not issue).
type recordingMinter struct {
	flows []*authflow.FlowContext
	err   error
}

func (m *recordingMinter) Mint(ctx context.Context, w http.ResponseWriter, r *http.Request, flow *authflow.FlowContext) error {
	m.flows = append(m.flows, flow)
	return m.err
}

// testFlowEngine builds an authflow engine wired with the given MFA enrollment answer and a
// recording minter, matching how an application would assemble it.
func testFlowEngine(t *testing.T, enrolled bool, minter *recordingMinter) *authflow.Engine {
	t.Helper()
	engine, err := authflow.NewEngine([]byte("01234567890123456789012345678901"),
		authflow.WithMFAGate(stubMFAGate{enrolled: enrolled}),
		authflow.WithMinter(minter),
	)
	require.NoError(t, err)
	return engine
}

// TestMagicLinkLoginHandler_AuthFlow_EnrolledChallengesWithoutCredentials proves the SEC-ID-03
// fix through the unified flow engine (issue #71): when MagicLinkLoginHandler is wired with
// WithAuthFlow and the user has MFA enrolled, the handler must NOT mint any credentials. The
// engine parks the ceremony in StateMFAChallenged, sets only the short-lived flow-token cookie,
// and the client must complete the second factor via authflow.StepUpHandler.
func TestMagicLinkLoginHandler_AuthFlow_EnrolledChallengesWithoutCredentials(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	svc := &servicetest.MockService{
		LoginWithMagicLinkFunc: func(ctx context.Context, tenantID string, token string, _ ...event.RequestContext) (*identity.User, error) {
			return &identity.User{ID: uid, TenantID: "tenant-1", Email: "ml@example.com"}, nil
		},
	}
	minter := &recordingMinter{}
	engine := testFlowEngine(t, true, minter)

	h := identity.MagicLinkLoginHandler[struct{}](svc, okIssuer(), testClaimsBuilder(),
		identity.WithAuthFlow(authflow.NewHandlerFlow(engine)))

	rec := httptest.NewRecorder()
	h(rec, postForm(url.Values{"token": {"sel.ver"}}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Nil(t, cookieByName(rec, tokens.DefaultAccessCookieName),
		"a challenged flow must not receive an access cookie")
	assert.Nil(t, cookieByName(rec, tokens.DefaultRefreshCookieName),
		"SEC-ID-03: a challenged flow must not receive a refresh cookie")
	assert.Empty(t, minter.flows, "no credentials may be minted before the second factor")

	flowCookie := cookieByName(rec, authflow.DefaultFlowCookieName)
	require.NotNil(t, flowCookie, "the flow-token cookie must be set so the client can step up")
	assert.NotEmpty(t, flowCookie.Value)
	assert.True(t, flowCookie.HttpOnly)
}

// TestMagicLinkLoginHandler_AuthFlow_NotEnrolledMintsViaEngine proves the delegation half: with
// no second factor enrolled, the engine completes the flow and its SessionMinter — not the
// handler's own issuer — produces the credentials, carrying the magic-link AMR.
func TestMagicLinkLoginHandler_AuthFlow_NotEnrolledMintsViaEngine(t *testing.T) {
	uid := uuid.Must(uuid.NewV7())
	svc := &servicetest.MockService{
		LoginWithMagicLinkFunc: func(ctx context.Context, tenantID string, token string, _ ...event.RequestContext) (*identity.User, error) {
			return &identity.User{ID: uid, TenantID: "tenant-1", Email: "ml@example.com"}, nil
		},
	}
	minter := &recordingMinter{}
	engine := testFlowEngine(t, false, minter)

	var captured tokens.Claims[struct{}]
	h := identity.MagicLinkLoginHandler[struct{}](svc, capturingIssuer(&captured), testClaimsBuilder(),
		identity.WithAuthFlow(authflow.NewHandlerFlow(engine)))

	rec := httptest.NewRecorder()
	h(rec, postForm(url.Values{"token": {"sel.ver"}}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	require.Len(t, minter.flows, 1, "the engine minter must issue the final credentials")
	flow := minter.flows[0]
	assert.Equal(t, uid, flow.UserID)
	assert.Equal(t, "tenant-1", flow.TenantID)
	assert.Equal(t, "magic_link", flow.PrimaryFactor)
	assert.Equal(t, []string{tokens.AMROTP}, flow.AMR, "magic-link primary factor maps to the otp AMR")
	assert.Equal(t, uuid.Nil, captured.Subject, "the handler-side issuer must be bypassed entirely")
}
