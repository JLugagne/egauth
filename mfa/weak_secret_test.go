package mfa_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/JLugagne/egauth/mfa"
	"github.com/JLugagne/egauth/mfa/memory"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hotpForKey reimplements RFC 4226 dynamic truncation locally so the test can compute the code an
// attacker would submit for a DEGENERATE key (empty or truncated) without going through the
// library's own guards.
func hotpForKey(key []byte, counter uint64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	mod := 1
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%uint32(mod))
}

func base32Secret(key []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
}

// TestVerifyTOTP_RejectsDegenerateStoredSecret proves the vulnerability: a TOTP row whose shared
// secret is empty or truncated yields a zero-length (or trivially short) HMAC key, and the code it
// produces is computable by anyone. Such a factor must never verify.
func TestVerifyTOTP_RejectsDegenerateStoredSecret(t *testing.T) {
	cases := []struct {
		name string
		key  []byte
	}{
		{"empty secret", []byte{}},
		{"one byte of entropy", []byte{0x01}},
		{"five bytes of entropy", []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
		{"one byte below the floor", make([]byte, mfa.MinSecretBytes-1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Unix(1_700_000_000, 0)
			store := memory.NewStore()
			svc := mfa.NewService(store, mfa.WithClock(func() time.Time { return now }), mfa.WithIssuer("Acme"))
			uid := uuid.Must(uuid.NewV7())

			confirmed := now.Add(-time.Hour)
			require.NoError(t, store.SaveTOTP(ctx, "", &mfa.TOTPEnrollment{
				UserID:      uid,
				Secret:      base32Secret(tc.key),
				ConfirmedAt: &confirmed,
				CreatedAt:   confirmed,
			}))

			step := now.Unix() / int64(mfa.DefaultPeriod.Seconds())
			code := hotpForKey(tc.key, uint64(step), mfa.DefaultDigits)

			err := svc.VerifyTOTP(ctx, "", uid, code)
			require.Error(t, err, "a %d-byte shared secret must never satisfy a second-factor check", len(tc.key))
			assert.ErrorIs(t, err, mfa.ErrWeakSecret)
		})
	}
}

func TestValidateSecret(t *testing.T) {
	good, err := mfa.GenerateSecret()
	require.NoError(t, err)
	require.NoError(t, mfa.ValidateSecret(good))

	assert.ErrorIs(t, mfa.ValidateSecret(""), mfa.ErrWeakSecret)
	assert.ErrorIs(t, mfa.ValidateSecret("AE"), mfa.ErrWeakSecret)
	assert.ErrorIs(t, mfa.ValidateSecret(base32Secret(make([]byte, mfa.MinSecretBytes-1))), mfa.ErrWeakSecret)
	require.NoError(t, mfa.ValidateSecret(base32Secret(make([]byte, mfa.MinSecretBytes))))
	assert.Error(t, mfa.ValidateSecret("not!base32"))
}

func TestGenerateCode_RejectsWeakSecret(t *testing.T) {
	_, err := mfa.GenerateCode("", time.Unix(1_700_000_000, 0), mfa.DefaultDigits, mfa.DefaultPeriod)
	assert.ErrorIs(t, err, mfa.ErrWeakSecret)
}

func TestConfirmTOTP_RejectsDegenerateStoredSecret(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	store := memory.NewStore()
	svc := mfa.NewService(store, mfa.WithClock(func() time.Time { return now }), mfa.WithIssuer("Acme"))
	uid := uuid.Must(uuid.NewV7())

	require.NoError(t, store.SaveTOTP(ctx, "", &mfa.TOTPEnrollment{
		UserID:    uid,
		Secret:    "",
		CreatedAt: now,
	}))

	step := now.Unix() / int64(mfa.DefaultPeriod.Seconds())
	_, err := svc.ConfirmTOTP(ctx, "", uid, hotpForKey([]byte{}, uint64(step), mfa.DefaultDigits))
	require.Error(t, err)
	assert.ErrorIs(t, err, mfa.ErrWeakSecret)
}
