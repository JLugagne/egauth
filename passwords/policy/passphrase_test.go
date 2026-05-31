package policy_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPassphrasePolicy_Defaults(t *testing.T) {
	ctx := context.Background()
	p := policy.NewPassphrasePolicy()

	t.Run("accepts a long passphrase with no special characters", func(t *testing.T) {
		// No uppercase/number/symbol — would fail the legacy DefaultPolicy, must pass here.
		require.NoError(t, p.Verify(ctx, "correct stapler battery ostrich"))
	})

	t.Run("rejects too-short", func(t *testing.T) {
		assert.ErrorIs(t, p.Verify(ctx, "short"), passwords.ErrPasswordTooShort)
	})

	t.Run("counts code points, not bytes", func(t *testing.T) {
		// 11 multi-byte runes < 12 min: must be rejected on rune count, not byte count.
		assert.ErrorIs(t, p.Verify(ctx, strings.Repeat("é", 11)), passwords.ErrPasswordTooShort)
		require.NoError(t, p.Verify(ctx, strings.Repeat("é", 12)))
	})

	t.Run("rejects over-max", func(t *testing.T) {
		assert.ErrorIs(t, p.Verify(ctx, strings.Repeat("a", policy.DefaultPassphraseMaxLength+1)), passwords.ErrPasswordTooLong)
	})

	t.Run("rejects a built-in common secret", func(t *testing.T) {
		assert.ErrorIs(t, p.Verify(ctx, "correcthorsebatterystaple"), passwords.ErrPasswordBreached)
	})

	t.Run("denylist is not bypassed by re-spacing a banned secret", func(t *testing.T) {
		// Cosmetic internal whitespace must not defeat the denylist.
		assert.ErrorIs(t, p.Verify(ctx, "correct horse battery staple"), passwords.ErrPasswordBreached)
		assert.ErrorIs(t, p.Verify(ctx, "password password"), passwords.ErrPasswordBreached)
	})
}

func TestPassphrasePolicy_Denylist(t *testing.T) {
	ctx := context.Background()
	p := policy.NewPassphrasePolicy(policy.WithDenylist("MyCompanyName2024"))

	// Case-insensitive, trimmed match.
	assert.ErrorIs(t, p.Verify(ctx, "  mycompanyname2024 "), passwords.ErrPasswordBreached)
	require.NoError(t, p.Verify(ctx, "a totally different phrase"))
}

func TestPassphrasePolicy_BreachChecker(t *testing.T) {
	ctx := context.Background()

	t.Run("rejects a breached password", func(t *testing.T) {
		p := policy.NewPassphrasePolicy(policy.WithBreachChecker(
			passwords.BreachCheckerFunc(func(_ context.Context, pw string) (bool, error) {
				return pw == "this is a breached passphrase", nil
			})))
		assert.ErrorIs(t, p.Verify(ctx, "this is a breached passphrase"), passwords.ErrPasswordBreached)
		require.NoError(t, p.Verify(ctx, "this one is perfectly fine"))
	})

	t.Run("propagates checker errors so the caller chooses fail-open/closed", func(t *testing.T) {
		boom := errors.New("hibp unreachable")
		p := policy.NewPassphrasePolicy(policy.WithBreachChecker(
			passwords.BreachCheckerFunc(func(_ context.Context, _ string) (bool, error) {
				return false, boom
			})))
		assert.ErrorIs(t, p.Verify(ctx, "a sufficiently long phrase"), boom)
	})
}

func TestPassphrasePolicy_NoCompositionRules(t *testing.T) {
	ctx := context.Background()
	p := policy.NewPassphrasePolicy()
	// All-lowercase, all-letters, spaces — explicitly allowed (the NIST stance).
	require.NoError(t, p.Verify(ctx, "the quick brown fox jumps"))
}
