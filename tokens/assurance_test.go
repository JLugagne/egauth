package tokens_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/tokens"
	"github.com/JLugagne/egauth/tokens/issuertest"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DenyInterim is the ready-made func(*http.Request) error gate credential-enrollment
// handlers (passkey, mfa, identity) can install without depending on the generic Claims[C]
// type. It must deny an interim (pre-second-factor) verified context and allow anything
// else, including a request with no token context at all.

func interimVerifier() *issuertest.MockVerifier[customClaims] {
	return &issuertest.MockVerifier[customClaims]{
		VerifyAccessTokenForTenantFunc: func(_ context.Context, _, token string) (*tokens.Claims[customClaims], error) {
			switch token {
			case "interim-token":
				return &tokens.Claims[customClaims]{Subject: uuid.Must(uuid.NewV7()), Interim: true}, nil
			case "full-token":
				return &tokens.Claims[customClaims]{Subject: uuid.Must(uuid.NewV7()), Interim: false}, nil
			default:
				return nil, tokens.ErrInvalidToken
			}
		},
	}
}

func TestDenyInterim_EmptyContextAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/enroll", nil)
	require.NoError(t, tokens.DenyInterim(req), "a request with no token context must be allowed")
}

func TestDenyInterim_ContextMiddleware(t *testing.T) {
	verifier := interimVerifier()
	call := func(token string) (int, error) {
		var got error
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = tokens.DenyInterim(r)
			w.WriteHeader(http.StatusOK)
		})
		req := httptest.NewRequest(http.MethodGet, "/enroll", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		tokens.ContextMiddleware[customClaims](verifier, next).ServeHTTP(rec, req)
		return rec.Code, got
	}

	t.Run("interim context is denied", func(t *testing.T) {
		code, got := call("interim-token")
		require.Equal(t, http.StatusOK, code)
		require.ErrorIs(t, got, tokens.ErrInterimDenied,
			"an interim access token must be refused by the enrollment gate")
	})
	t.Run("full context is allowed", func(t *testing.T) {
		code, got := call("full-token")
		require.Equal(t, http.StatusOK, code)
		require.NoError(t, got)
	})
}

func TestDenyInterim_RequireAuth(t *testing.T) {
	verifier := interimVerifier()
	call := func(token string) (int, error) {
		var got error
		h := tokens.RequireAuth[customClaims](verifier, func(w http.ResponseWriter, r *http.Request, _ egauth.Actor, _ customClaims) {
			got = tokens.DenyInterim(r)
			w.WriteHeader(http.StatusOK)
		})
		req := httptest.NewRequest(http.MethodGet, "/enroll", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec.Code, got
	}

	t.Run("interim request is denied", func(t *testing.T) {
		code, got := call("interim-token")
		require.Equal(t, http.StatusOK, code)
		assert.True(t, errors.Is(got, tokens.ErrInterimDenied))
	})
	t.Run("full request is allowed", func(t *testing.T) {
		_, got := call("full-token")
		assert.NoError(t, got)
	})
}

func TestErrInterimDenied_IsStable(t *testing.T) {
	require.Error(t, tokens.ErrInterimDenied)
	assert.Contains(t, tokens.ErrInterimDenied.Error(), "interim")
}
