package identity_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingIssuer records which issuance path a handler took. It implements both tokens.Issuer and
// the optional tokens.AccessTokenIssuer extension, so a handler that only needs an access token can
// avoid minting (and persisting) a refresh-token family.
type countingIssuer struct {
	pairCalls   int
	accessCalls int
	claims      tokens.Claims[struct{}]
}

func (c *countingIssuer) IssueTokenPair(_ context.Context, claims tokens.Claims[struct{}]) (*tokens.TokenPair[struct{}], error) {
	c.pairCalls++
	c.claims = claims
	return &tokens.TokenPair[struct{}]{
		AccessToken:           "access-jwt",
		RefreshToken:          "refresh-opaque",
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
		Claims:                claims,
	}, nil
}

func (c *countingIssuer) IssueAPIKey(context.Context, string, tokens.KeyType, uuid.UUID, tokens.Claims[struct{}]) (*tokens.APIKey[struct{}], error) {
	return nil, nil
}

func (c *countingIssuer) IssueAccessToken(_ context.Context, claims tokens.Claims[struct{}]) (string, time.Time, error) {
	c.accessCalls++
	c.claims = claims
	return "interim-jwt", time.Now().Add(5 * time.Minute), nil
}

// TestLoginHandler_MFAGate_InterimPersistsNoRefreshFamily proves the refuter-found LOW: the
// MFA-gated interim login used to mint a full pair and DISCARD its refresh token, leaving a
// full-RefreshTTL refresh-token row behind for a session that was never granted. The interim
// credential must be issued through the access-token-only path instead.
func TestLoginHandler_MFAGate_InterimPersistsNoRefreshFamily(t *testing.T) {
	svc := &servicetest.MockService{
		AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
			return &identity.User{ID: uuid.Must(uuid.NewV7())}, nil
		},
	}
	issuer := &countingIssuer{}
	h := identity.LoginHandler[struct{}](svc, issuer, testClaimsBuilder(),
		identity.WithMFAGate(stubMFAGate{enrolled: true}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, loginForm(t, "/login", "user@example.com", "secret", ""))

	// A refresh cookie left over from an earlier full session must be CLEARED: the interim state
	// claims not to be renewable, so it must not leave a renewable credential in the browser.
	refresh := cookieByName(rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, refresh, "the interim login must actively clear any existing refresh cookie")
	assert.Less(t, refresh.MaxAge, 0, "the refresh cookie must be expired, not set")
	assert.Empty(t, refresh.Value)

	assert.Equal(t, 0, issuer.pairCalls,
		"the interim login must NOT mint a token pair (that persists a refresh family whose token is discarded)")
	assert.Equal(t, 1, issuer.accessCalls,
		"the interim login must use the access-token-only issuance path")
	require.NotNil(t, cookieByName(rec, tokens.DefaultAccessCookieName))
}
