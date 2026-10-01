// Regression tests for F-PASSKEY-001: a ceremony refused by a store capacity bound must be
// reported as the documented 503, never as an empty 200. The handler-level mapping is the
// only place the contract can be observed; the store-level tests can only assert the
// sentinel wraps ErrStoreCapacityReached.
package passkey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestStoreCapacityFailsClosedWith503 covers the challenge-store path: any unauthenticated
// caller can fill a tenant's live-entry budget, and the next legitimate Begin must see 503.
func TestStoreCapacityFailsClosedWith503(t *testing.T) {
	ctx := context.Background()
	cs := passkeymemory.NewChallengeStore(passkeymemory.WithMaxChallenges(1))
	svc, err := passkey.NewService(passkeymemory.NewStore(), passkey.Config{
		RPID: testRPID, RPDisplayName: testRPName, RPOrigins: []string{testOrigin},
		CookieKey: testCookieKey, ChallengeStore: cs,
	})
	require.NoError(t, err)

	uid := uuid.Must(uuid.NewV7())
	_ = registerTenant(t, svc, "t1", uid)

	// Fill the single per-tenant slot the way an unauthenticated flood would.
	require.NoError(t, cs.Put(ctx, "t1", "already-there", time.Now().Add(5*time.Minute)))

	rec := httptest.NewRecorder()
	passkey.BeginLoginHandler(svc, resolver(uid))(rec, httptest.NewRequest(http.MethodPost, "/login/begin", nil))

	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"a ceremony refused by the store capacity bound must fail closed with 503, not 200")
	require.NotEmpty(t, rec.Body.String(), "the 503 must carry an error body")
}

// TestRegistrationCapacityFailsClosedWith503 covers the credential-store path: the per-user
// credential cap refuses the registration at Finish, and the handler must report 503.
func TestRegistrationCapacityFailsClosedWith503(t *testing.T) {
	store := passkeymemory.NewStore(passkeymemory.WithMaxCredentialsPerUser(1))
	cs := passkeymemory.NewChallengeStore()
	svc, err := passkey.NewService(store, passkey.Config{
		RPID: testRPID, RPDisplayName: testRPName, RPOrigins: []string{testOrigin},
		CookieKey: testCookieKey, ChallengeStore: cs,
	})
	require.NoError(t, err)

	uid := uuid.Must(uuid.NewV7())
	_ = registerTenant(t, svc, "t1", uid)

	opts := []passkey.HandlerOption{resolver(uid), passkey.WithCookieKey(testCookieKey), passkey.WithInsecureNoAssuranceCheck()}
	beginRec := httptest.NewRecorder()
	passkey.BeginRegistrationHandler(svc, opts...)(beginRec, httptest.NewRequest(http.MethodPost, "/reg/begin", nil))
	require.Equal(t, http.StatusOK, beginRec.Code)
	cookie := findCookie(beginRec.Result().Cookies(), passkey.DefaultSessionCookieName)
	require.NotNil(t, cookie)

	var creation struct {
		Response struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal(beginRec.Body.Bytes(), &creation))

	auth := newSoftAuthenticator(t, testRPID, testOrigin)
	body := drainBody(t, auth.registrationRequest(t, creation.Response.Challenge))

	req := httptest.NewRequest(http.MethodPost, "/reg/finish", bytes.NewReader(body))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	passkey.FinishRegistrationHandler(svc, opts...)(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code,
		"a registration refused by the per-user credential cap must fail closed with 503, not 200")
	require.NotEmpty(t, rec.Body.String(), "the 503 must carry an error body")
}
