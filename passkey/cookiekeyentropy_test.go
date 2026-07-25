package passkey_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	"github.com/JLugagne/egauth/passkey/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewService_RejectsAllZeroCookieKey pins crypto/CRY-8: a 32-byte key of zeros satisfies the
// length bound but carries no entropy at all, so every ceremony cookie it seals is forgeable by
// anyone who knows the (obvious) key.
func TestNewService_RejectsAllZeroCookieKey(t *testing.T) {
	cfg := secureCfg()
	cfg.CookieKey = make([]byte, passkey.MinCookieKeyLength)
	_, err := passkey.NewService(memory.NewStore(), cfg)
	assert.ErrorIs(t, err, passkey.ErrCookieKeyWeak,
		"an all-zero cookie key must be rejected at construction, not merely length-checked")
}

func TestNewService_RejectsAllSameByteCookieKey(t *testing.T) {
	cfg := secureCfg()
	cfg.CookieKey = bytes.Repeat([]byte{0x41}, passkey.MinCookieKeyLength)
	_, err := passkey.NewService(memory.NewStore(), cfg)
	assert.ErrorIs(t, err, passkey.ErrCookieKeyWeak,
		"a single-repeated-byte cookie key must be rejected at construction")
}

func TestNewService_AcceptsRandomCookieKey(t *testing.T) {
	cfg := secureCfg()
	_, err := passkey.NewService(memory.NewStore(), cfg)
	require.NoError(t, err, "a real random key must still be accepted")
}

// TestWithCookieKey_RejectsAllZeroOverride pins that the per-handler override and the per-tenant
// resolver apply the same entropy floor, so the weak key cannot sneak back in past construction.
func TestWithCookieKey_RejectsAllZeroOverride(t *testing.T) {
	svc, _ := testService(t)
	h := passkey.BeginRegistrationHandler(svc,
		resolver(uuid.Must(uuid.NewV7())),
		passkey.WithInsecureNoOriginCheck(),
		passkey.WithCookieKey(make([]byte, passkey.MinCookieKeyLength)),
	)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/begin", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code,
		"an all-zero per-handler cookie key must fail the request closed")
}

func TestWithTenantCookieKeys_RejectsAllZeroKey(t *testing.T) {
	svc, _ := testService(t)
	h := passkey.BeginRegistrationHandler(svc,
		resolver(uuid.Must(uuid.NewV7())),
		passkey.WithInsecureNoOriginCheck(),
		passkey.WithTenantCookieKeys(func(context.Context, string) ([]byte, error) {
			return make([]byte, passkey.MinCookieKeyLength), nil
		}),
	)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/begin", nil))
	assert.Equal(t, http.StatusInternalServerError, rec.Code,
		"a per-tenant resolver returning an all-zero key must fail the request closed")
}
