package oauth

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubEnrollment is a minimal identity.MFAEnrollmentChecker for the OAuth gate tests.
type stubEnrollment struct {
	enrolled bool
	err      error
}

func (s stubEnrollment) IsEnrolled(context.Context, string, uuid.UUID) (bool, error) {
	return s.enrolled, s.err
}

// callbackCookies returns the auth cookies the callback wrote, by name.
func callbackCookies(rec *http.Response) map[string]*http.Cookie {
	out := map[string]*http.Cookie{}
	for _, c := range rec.Cookies() {
		out[c.Name] = c
	}
	return out
}

// TestCallbackHandler_MFAGate_EnrolledGetsInterimNoRefresh proves finding mfa/SF-3 for the OAuth
// half: an IdP-account compromise must not hand an MFA-enrolled user a full renewable session. The
// callback must apply the same MFA gate as the password login.
func TestCallbackHandler_MFAGate_EnrolledGetsInterimNoRefresh(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)
	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}

	rec := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect), WithMFAGate(stubEnrollment{enrolled: true}))

	got := callbackCookies(rec.Result())
	require.NotNil(t, got[tokens.DefaultAccessCookieName], "the interim access cookie is expected")
	// No USABLE refresh cookie: the callback writes an expiring one so a refresh cookie left over
	// from an earlier full session cannot survive the pre-step-up state.
	if refresh := got[tokens.DefaultRefreshCookieName]; refresh != nil {
		assert.Empty(t, refresh.Value,
			"an MFA-enrolled OAuth login must NOT receive a renewable refresh cookie before the second factor")
		assert.Less(t, refresh.MaxAge, 0)
	}
	assert.Contains(t, rec.Body.String(), "mfa_required",
		"the gated callback must signal that a second factor is required")
}

// TestCallbackHandler_MFAGate_NotEnrolledGetsFullPair confirms the gate is transparent for users
// with no enrolled factor.
func TestCallbackHandler_MFAGate_NotEnrolledGetsFullPair(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)
	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{
		AccessToken:           "access",
		RefreshToken:          "refresh",
		RefreshTokenExpiresAt: time.Now().Add(time.Hour),
	}}

	rec := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect), WithMFAGate(stubEnrollment{enrolled: false}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	got := callbackCookies(rec.Result())
	assert.NotNil(t, got[tokens.DefaultAccessCookieName])
	assert.NotNil(t, got[tokens.DefaultRefreshCookieName],
		"a non-enrolled user keeps the full refreshable pair")
}

// TestCallbackHandler_MFAGate_CheckErrorFailsClosed proves the gate fails closed: an enrollment
// check that errors must never fall through to a full session.
func TestCallbackHandler_MFAGate_CheckErrorFailsClosed(t *testing.T) {
	body := `{"sub":"prov-1","email":"u@example.com","email_verified":true}`
	p, _ := stubProviderServer(t, &body)
	stateCookie, state := runBegin(t, p, WithRedirectURL(testRedirect))

	linker := &stubLinker{user: &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "u@example.com"}}
	issuer := &stubIssuer{pair: &tokens.TokenPair[struct{}]{AccessToken: "access", RefreshToken: "refresh"}}

	rec := runCallback(t, p, linker, issuer, stateCookie,
		url.Values{"state": {state}, "code": {"auth-code"}}.Encode(),
		WithRedirectURL(testRedirect), WithMFAGate(stubEnrollment{err: assert.AnError}))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	got := callbackCookies(rec.Result())
	assert.Nil(t, got[tokens.DefaultAccessCookieName])
	assert.Nil(t, got[tokens.DefaultRefreshCookieName])
}
