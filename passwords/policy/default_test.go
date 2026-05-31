package policy_test

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultPolicy_Verify(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		password    string
		policy      *policy.DefaultPolicy
		expectedErr error
	}{
		{
			name:        "valid password",
			password:    "ValidPass123!",
			policy:      policy.NewDefaultPolicy(),
			expectedErr: nil,
		},
		{
			name:        "too short",
			password:    "Short1!",
			policy:      policy.NewDefaultPolicy(),
			expectedErr: passwords.ErrPasswordTooShort,
		},
		{
			name:        "too long",
			password:    "ThisPasswordIsWayTooLongAndExceedsTheMaximumAllowedLengthForOurSystem1234567890!@#",
			policy:      policy.NewDefaultPolicy(),
			expectedErr: passwords.ErrPasswordTooLong,
		},
		{
			name:        "missing uppercase",
			password:    "validpass123!",
			policy:      policy.NewDefaultPolicy(),
			expectedErr: passwords.ErrPasswordMissingUppercase,
		},
		{
			name:        "missing lowercase",
			password:    "VALIDPASS123!",
			policy:      policy.NewDefaultPolicy(),
			expectedErr: passwords.ErrPasswordMissingLowercase,
		},
		{
			name:        "missing number",
			password:    "ValidPassword!",
			policy:      policy.NewDefaultPolicy(),
			expectedErr: passwords.ErrPasswordMissingNumber,
		},
		{
			name:        "missing special",
			password:    "ValidPass123",
			policy:      policy.NewDefaultPolicy(),
			expectedErr: passwords.ErrPasswordMissingSpecial,
		},
		{
			name:     "custom policy - no special char required",
			password: "ValidPass123",
			policy: &policy.DefaultPolicy{
				MinLength:        8,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumber:    true,
				RequireSpecial:   false,
			},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Verify(ctx, tt.password)
			if tt.expectedErr == nil {
				require.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedErr)
			}
		})
	}
}

// TestDefaultPolicy_LengthCountsRunesNotBytes pins that MinLength/MaxLength measure characters
// (runes), not bytes — matching the passphrase policy. Byte counting both under-counts (lets a
// short multibyte password through MinLength) and over-restricts (rejects a within-limit
// multibyte password as too long).
func TestDefaultPolicy_LengthCountsRunesNotBytes(t *testing.T) {
	ctx := context.Background()
	p := policy.NewDefaultPolicy()

	// "Aa1!ééé" is 7 characters but 10 bytes and satisfies every complexity rule. Byte counting
	// would wrongly accept it against MinLength=8; it must be rejected as too short.
	short := "Aa1!ééé"
	require.Equal(t, 7, utf8.RuneCountInString(short))
	require.Greater(t, len(short), p.MinLength, "test fixture must have byte length >= MinLength to expose the bug")
	assert.ErrorIs(t, p.Verify(ctx, short), passwords.ErrPasswordTooShort,
		"a 7-character password must be too short regardless of its byte length")

	// "Aa1!" + 46×'é' is 50 characters but 96 bytes. It is comfortably within the 72-character
	// limit; byte counting would wrongly reject it as too long.
	long := "Aa1!" + strings.Repeat("é", 46)
	require.Equal(t, 50, utf8.RuneCountInString(long))
	require.Greater(t, len(long), p.MaxLength, "test fixture must have byte length > MaxLength to expose the bug")
	assert.NoError(t, p.Verify(ctx, long),
		"a 50-character password must be within the 72-character limit regardless of byte length")
}
