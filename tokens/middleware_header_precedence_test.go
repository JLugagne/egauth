package tokens_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/jwt"
	"github.com/JLugagne/egauth/tokens/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRequireAuth_AuthorizationHeaderBeatsCookie pins the credential precedence: an EXPLICITLY
// presented Authorization: Bearer token wins over the ambient access cookie the browser attaches
// to every request. Without this an API client that deliberately acts as another principal is
// silently served the cookie's identity.
func TestRequireAuth_AuthorizationHeaderBeatsCookie(t *testing.T) {
	svc := jwt.New[struct{}](jwt.Config[struct{}]{
		Store:      memory.NewStore[struct{}](),
		SecretKey:  "header-precedence-secret-aaaaaaaa!!", // 32 bytes
		Issuer:     "egauth-test",
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
	})
	cookies := tokens.DefaultCookies()

	cookieUser := uuid.Must(uuid.NewV7())
	headerUser := uuid.Must(uuid.NewV7())
	cookiePair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: cookieUser})
	require.NoError(t, err)
	headerPair, err := svc.IssueTokenPair(context.Background(), tokens.Claims[struct{}]{Subject: headerUser})
	require.NoError(t, err)

	var seen uuid.UUID
	h := tokens.RequireAuth[struct{}](svc,
		func(w http.ResponseWriter, _ *http.Request, actor egauth.Actor, _ struct{}) {
			seen = actor.UserID
			w.WriteHeader(http.StatusOK)
		},
		tokens.WithCookieAuth[struct{}](cookies),
	)

	newRequest := func(authorization string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.AddCookie(&http.Cookie{Name: cookies.AccessName, Value: cookiePair.AccessToken})
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		return req
	}

	t.Run("bearer header wins over the cookie", func(t *testing.T) {
		seen = uuid.Nil
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newRequest("Bearer "+headerPair.AccessToken))
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, headerUser, seen, "the explicitly presented header token must be the one verified")
	})

	t.Run("no header falls back to the cookie", func(t *testing.T) {
		seen = uuid.Nil
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newRequest(""))
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, cookieUser, seen)
	})

	t.Run("a non-bearer scheme does not shadow the cookie", func(t *testing.T) {
		seen = uuid.Nil
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newRequest("Basic dXNlcjpwYXNz"))
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, cookieUser, seen, "an unrelated Authorization scheme must leave the cookie in charge")
	})

	t.Run("extra whitespace after the scheme is tolerated", func(t *testing.T) {
		seen = uuid.Nil
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newRequest("bearer   "+headerPair.AccessToken))
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, headerUser, seen)
	})

	t.Run("an invalid bearer token is rejected, never downgraded to the cookie", func(t *testing.T) {
		seen = uuid.Nil
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, newRequest("Bearer not-a-jwt"))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, uuid.Nil, seen, "a presented-but-invalid token must not fall back to the ambient cookie")
	})
}
