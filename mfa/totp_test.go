package mfa

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHOTP_RFC4226Vectors checks the dynamic-truncation implementation against the canonical
// RFC 4226 Appendix D test vectors (secret = ASCII "12345678901234567890").
func TestHOTP_RFC4226Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		assert.Equal(t, w, hotp(key, uint64(i), 6), "counter %d", i)
	}
}

func TestValidateTOTP_RoundTripAndSkew(t *testing.T) {
	secret, err := GenerateSecret()
	require.NoError(t, err)
	key, err := decodeSecret(secret)
	require.NoError(t, err)

	at := time.Unix(1234567890, 0)
	step := timeStep(at, DefaultPeriod)

	code := hotp(key, uint64(step), DefaultDigits)
	matched, ok := validateTOTP(secret, code, at, DefaultDigits, DefaultPeriod, DefaultSkew)
	assert.True(t, ok)
	assert.Equal(t, step, matched)

	// A code well outside the skew window must be rejected.
	farCode := hotp(key, uint64(step+5), DefaultDigits)
	_, ok = validateTOTP(secret, farCode, at, DefaultDigits, DefaultPeriod, DefaultSkew)
	assert.False(t, ok)

	// A code from the previous step is accepted within ±1 skew.
	prevCode := hotp(key, uint64(step-1), DefaultDigits)
	matched, ok = validateTOTP(secret, prevCode, at, DefaultDigits, DefaultPeriod, DefaultSkew)
	assert.True(t, ok)
	assert.Equal(t, step-1, matched)

	// Empty / malformed code is rejected.
	_, ok = validateTOTP(secret, "", at, DefaultDigits, DefaultPeriod, DefaultSkew)
	assert.False(t, ok)
}

func TestProvisioningURI(t *testing.T) {
	uri := ProvisioningURI("ABCDEF", "Acme Inc", "user@example.com", DefaultDigits, DefaultPeriod)
	assert.True(t, strings.HasPrefix(uri, "otpauth://totp/"))

	u, err := url.Parse(uri)
	require.NoError(t, err)
	q := u.Query()
	assert.Equal(t, "ABCDEF", q.Get("secret"))
	assert.Equal(t, "Acme Inc", q.Get("issuer"))
	assert.Equal(t, "SHA1", q.Get("algorithm"))
	assert.Equal(t, "6", q.Get("digits"))
	assert.Equal(t, "30", q.Get("period"))
}

func TestGenerateSecret_DecodesToFullEntropy(t *testing.T) {
	secret, err := GenerateSecret()
	require.NoError(t, err)
	key, err := decodeSecret(secret)
	require.NoError(t, err)
	assert.Len(t, key, secretBytes)
}
