package policy_test

import (
	"context"
	"testing"

	"github.com/JLugagne/libauth/passwords"
	"github.com/JLugagne/libauth/passwords/internal/policy"
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
