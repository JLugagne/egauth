package webapp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/identity"
	"github.com/JLugagne/egauth/identity/servicetest"
	"github.com/JLugagne/egauth/webapp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWebApp_LoginUniformErrorsByDefault(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"locked", identity.ErrAccountLocked},
		{"disabled", identity.ErrAccountDisabled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &servicetest.MockService{
				AuthenticateFunc: func(ctx context.Context, tenantID string, provider, providerID, password string) (*identity.User, error) {
					return nil, tc.err
				},
			}
			cfg := baseConfig()
			cfg.Identity = svc
			cfg.TrustedOrigins = []string{"https://example.com"}
			h, err := webapp.NewWebApp(cfg)
			require.NoError(t, err)

			form := url.Values{}
			form.Set("email", "victim@example.com")
			form.Set("password", "secret")
			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", "https://example.com")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusUnauthorized, rec.Code,
				"webapp preset must not answer 429 on locked/disabled accounts (account enumeration oracle)")
			assert.Contains(t, rec.Body.String(), "invalid_credentials")
			assert.NotContains(t, rec.Body.String(), "account_locked")
		})
	}
}
