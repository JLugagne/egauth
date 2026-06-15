package passkey_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingStore makes every operation fail, to exercise store-error handling.
type failingStore struct{}

func (failingStore) SaveCredential(_ context.Context, _ string, _ *passkey.Credential) error {
	return errors.New("db down")
}
func (failingStore) GetCredentials(_ context.Context, _ string, _ uuid.UUID) ([]*passkey.Credential, error) {
	return nil, errors.New("db down")
}
func (failingStore) UpdateCredential(_ context.Context, _ string, _ *passkey.Credential) error {
	return errors.New("db down")
}
func (failingStore) DeleteCredential(_ context.Context, _ string, _ uuid.UUID, _ []byte) error {
	return errors.New("db down")
}

var testCookieKey = []byte("0123456789abcdef0123456789abcdef")

func resolver(uid uuid.UUID) passkey.HandlerOption {
	return passkey.WithUserResolver(func(*http.Request) (uuid.UUID, string, string, string, bool) {
		return uid, "alice", "Alice", "t1", true
	})
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestBeginRegistrationHandler(t *testing.T) {
	svc, _ := testService(t)
	uid := uuid.Must(uuid.NewV7())
	h := passkey.BeginRegistrationHandler(svc, resolver(uid), passkey.WithCookieKey(testCookieKey))

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/passkey/register/begin", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	// Body carries the creation options (with a challenge).
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Contains(t, body, "publicKey")

	// Ceremony cookie is set, HttpOnly.
	cookie := findCookie(rec.Result().Cookies(), passkey.DefaultSessionCookieName)
	require.NotNil(t, cookie)
	assert.True(t, cookie.HttpOnly)
	assert.NotEmpty(t, cookie.Value)
}

func TestBeginRegistrationHandler_EmptyCookieKeyOverrideFailsClosed(t *testing.T) {
	svc, _ := testService(t)
	// The Service carries a validated cookie key, but a per-handler override that clears it must
	// still fail closed (defense in depth) rather than emit an unauthenticated cookie.
	h := passkey.BeginRegistrationHandler(svc, resolver(uuid.Must(uuid.NewV7())), passkey.WithCookieKey(nil))
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Nil(t, findCookie(rec.Result().Cookies(), passkey.DefaultSessionCookieName))
}

func TestCeremonyCookie_TamperedIsRejected(t *testing.T) {
	svc, _ := testService(t)
	uid := uuid.Must(uuid.NewV7())

	// Begin to obtain a validly-signed ceremony cookie.
	beginRec := httptest.NewRecorder()
	passkey.BeginRegistrationHandler(svc, resolver(uid), passkey.WithCookieKey(testCookieKey))(
		beginRec, httptest.NewRequest(http.MethodPost, "/", nil))
	cookie := findCookie(beginRec.Result().Cookies(), passkey.DefaultSessionCookieName)
	require.NotNil(t, cookie)

	// Tamper the cookie value: the HMAC must no longer verify.
	tampered := &http.Cookie{Name: cookie.Name, Value: cookie.Value + "x"}

	finishReq := httptest.NewRequest(http.MethodPost, "/", nil)
	finishReq.AddCookie(tampered)
	finishRec := httptest.NewRecorder()
	passkey.FinishRegistrationHandler(svc, resolver(uid), passkey.WithCookieKey(testCookieKey))(finishRec, finishReq)

	assert.Equal(t, http.StatusBadRequest, finishRec.Code, "a tampered ceremony cookie must be rejected")

	// A different key must also reject the legitimate cookie (HMAC mismatch).
	otherReq := httptest.NewRequest(http.MethodPost, "/", nil)
	otherReq.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	otherRec := httptest.NewRecorder()
	passkey.FinishRegistrationHandler(svc, resolver(uid), passkey.WithCookieKey([]byte("a-totally-different-secret-key-32")))(otherRec, otherReq)
	assert.Equal(t, http.StatusBadRequest, otherRec.Code)
}

func TestPasskeyHandlers_AuthAndMethodGuards(t *testing.T) {
	svc, _ := testService(t)

	t.Run("no resolver -> 401", func(t *testing.T) {
		rec := httptest.NewRecorder()
		passkey.BeginRegistrationHandler(svc)(rec, httptest.NewRequest(http.MethodPost, "/", nil))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("GET -> 405", func(t *testing.T) {
		rec := httptest.NewRecorder()
		passkey.BeginLoginHandler(svc, resolver(uuid.Must(uuid.NewV7())))(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})
}

func TestFinishRegistrationHandler_MissingSessionCookie(t *testing.T) {
	svc, _ := testService(t)
	h := passkey.FinishRegistrationHandler(svc, resolver(uuid.Must(uuid.NewV7())), passkey.WithCookieKey(testCookieKey))

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/passkey/register/finish", nil))

	// No ceremony cookie → rejected before any attestation parsing.
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPasskeyHandlers_StoreErrorIs500(t *testing.T) {
	svc, err := passkey.NewService(failingStore{}, passkey.Config{
		RPID: "example.com", RPDisplayName: "Example", RPOrigins: []string{"https://example.com"},
		CookieKey: testCookieKey, ChallengeStore: passkeymemory.NewChallengeStore(),
	})
	require.NoError(t, err)

	// BeginLogin loads credentials first; a store failure must surface as 5xx, not a 400
	// "bad attestation".
	h := passkey.BeginLoginHandler(svc, resolver(uuid.Must(uuid.NewV7())), passkey.WithCookieKey(testCookieKey))
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestBeginLoginHandler_NoCredentials(t *testing.T) {
	svc, _ := testService(t)
	h := passkey.BeginLoginHandler(svc, resolver(uuid.Must(uuid.NewV7())))

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/passkey/login/begin", nil))

	assert.Equal(t, http.StatusBadRequest, rec.Code) // no_credentials
}
