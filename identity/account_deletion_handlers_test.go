package identity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/tokens"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteAccountHandler_RequiresResolvedUser(t *testing.T) {
	t.Run("rejects GET", func(t *testing.T) {
		h := identity.DeleteAccountHandler(&servicetest.MockService{})
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	})

	t.Run("no resolver -> 401", func(t *testing.T) {
		h := identity.DeleteAccountHandler(&servicetest.MockService{})
		rec := httptest.NewRecorder()
		h(rec, postForm(url.Values{}))
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestDeleteAccountHandler_SuccessClearsCookies(t *testing.T) {
	user := &identity.User{ID: uuid.Must(uuid.NewV7()), Email: "gone@example.com"}
	var deleted uuid.UUID
	svc := &servicetest.MockService{
		DeleteAccountFunc: func(_ context.Context, _ string, userID uuid.UUID) error {
			deleted = userID
			return nil
		},
	}
	h := identity.DeleteAccountHandler(svc,
		identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }),
		fullSessionAssurance())
	rec := httptest.NewRecorder()
	h(rec, postForm(url.Values{}))

	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, user.ID, deleted)

	// The auth cookies are cleared (max-age in the past) since the account is gone.
	access := cookieByName(rec, tokens.DefaultAccessCookieName)
	require.NotNil(t, access)
	assert.True(t, access.MaxAge < 0, "access cookie must be expired")
	refresh := cookieByName(rec, tokens.DefaultRefreshCookieName)
	require.NotNil(t, refresh)
	assert.True(t, refresh.MaxAge < 0, "refresh cookie must be expired")
}

func TestDeleteAccountHandler_ErrorMapping(t *testing.T) {
	user := &identity.User{ID: uuid.Must(uuid.NewV7())}
	cases := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"not found -> 404", identity.ErrUserNotFound, http.StatusNotFound},
		{"backend error -> 500", context.DeadlineExceeded, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &servicetest.MockService{
				DeleteAccountFunc: func(_ context.Context, _ string, _ uuid.UUID) error {
					return tc.err
				},
			}
			h := identity.DeleteAccountHandler(svc,
				identity.WithUserResolver(func(*http.Request) (*identity.User, bool) { return user, true }),
				fullSessionAssurance())
			rec := httptest.NewRecorder()
			h(rec, postForm(url.Values{}))
			assert.Equal(t, tc.wantCode, rec.Code)
		})
	}
}
