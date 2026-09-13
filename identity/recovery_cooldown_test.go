package identity_test

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRecoveryChannelCooldown_DelaysUsability covers the window that turns "enrol a channel, use it
// immediately" into a two-step operation. A recovery channel is a credential the account holder may
// not have asked for — enrolment needs a live session, not a fresh factor — and the reset-via-recovery
// flow delivers a password-reset token to whatever address is enrolled. Without a window, an attacker
// who reaches a session once can convert it into a takeover within the same minute.
func TestRecoveryChannelCooldown_DelaysUsability(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	svc, _ := newVerificationService(t,
		identity.WithClock(clock),
		identity.WithRecoveryChannelCooldown(24*time.Hour),
	)

	const email = "cooldown@example.com"
	user, err := svc.Register(ctx, "", email, "Passw0rd-Original!")
	require.NoError(t, err)

	token, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "recovery@example.com")
	require.NoError(t, err)
	_, err = svc.ConfirmRecoveryEmail(ctx, "", token)
	require.NoError(t, err)

	t.Run("the channel is enrolled but not yet usable", func(t *testing.T) {
		channels, err := svc.RecoveryChannels(ctx, "", user.ID)
		require.NoError(t, err)
		assert.True(t, channels.Any(), "the channel is enrolled")
		assert.False(t, channels.Usable(now), "but it is still inside its cooling-off window")
		assert.Equal(t, now.Add(24*time.Hour), channels.NotBefore)
	})

	t.Run("the reset-via-recovery flow stays uniform while the window is open", func(t *testing.T) {
		token, u, chans, err := svc.RequestPasswordResetViaRecovery(ctx, "", email)
		require.NoError(t, err)
		assert.Empty(t, token, "no token may be minted to a channel that is not usable yet")
		assert.Nil(t, u)
		assert.False(t, chans.Any(), "the channel inventory stays uniform with the no-channel case")
	})

	t.Run("the channel becomes usable once the window elapses", func(t *testing.T) {
		now = now.Add(24*time.Hour + time.Second)

		channels, err := svc.RecoveryChannels(ctx, "", user.ID)
		require.NoError(t, err)
		assert.True(t, channels.Usable(now))

		resetToken, u, chans, err := svc.RequestPasswordResetViaRecovery(ctx, "", email)
		require.NoError(t, err)
		assert.NotEmpty(t, resetToken, "a channel past its window is usable again")
		require.NotNil(t, u)
		assert.True(t, chans.Any())
	})
}

// TestRecoveryChannelCooldown_DefaultIsOff is the compatibility control: without the option the
// behaviour is exactly as before, so existing deployments are unaffected.
func TestRecoveryChannelCooldown_DefaultIsOff(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t)

	const email = "no-cooldown@example.com"
	user, err := svc.Register(ctx, "", email, "Passw0rd-Original!")
	require.NoError(t, err)

	token, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "recovery@example.com")
	require.NoError(t, err)
	_, err = svc.ConfirmRecoveryEmail(ctx, "", token)
	require.NoError(t, err)

	channels, err := svc.RecoveryChannels(ctx, "", user.ID)
	require.NoError(t, err)
	assert.True(t, channels.Usable(time.Now()), "with no configured window a channel is immediately usable")
	assert.True(t, channels.NotBefore.IsZero())

	resetToken, _, _, err := svc.RequestPasswordResetViaRecovery(ctx, "", email)
	require.NoError(t, err)
	assert.NotEmpty(t, resetToken)
}

// TestRecoveryChannelCooldown_UsesTheLaterChannel pins the multi-channel rule: a reset may be
// delivered to either channel, so the account is only usable once BOTH have cleared their windows.
func TestRecoveryChannelCooldown_UsesTheLaterChannel(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	svc, _ := newVerificationService(t,
		identity.WithClock(clock),
		identity.WithRecoveryChannelCooldown(time.Hour),
	)
	user, err := svc.Register(ctx, "", "both@example.com", "Passw0rd-Original!")
	require.NoError(t, err)

	// Enrol the recovery email first...
	token, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "recovery@example.com")
	require.NoError(t, err)
	_, err = svc.ConfirmRecoveryEmail(ctx, "", token)
	require.NoError(t, err)

	// ...then the phone half an hour later.
	now = now.Add(30 * time.Minute)
	phoneToken, err := svc.RequestPhoneVerification(ctx, "", user.ID, "+15551234567")
	require.NoError(t, err)
	_, err = svc.ConfirmPhoneVerification(ctx, "", phoneToken)
	require.NoError(t, err)

	channels, err := svc.RecoveryChannels(ctx, "", user.ID)
	require.NoError(t, err)
	// The phone is the later enrolment, so its window governs.
	assert.Equal(t, now.Add(time.Hour), channels.NotBefore)

	// An hour after the EMAIL was enrolled, the phone window is still open.
	assert.False(t, channels.Usable(time.Date(2026, 9, 13, 13, 1, 0, 0, time.UTC)),
		"the later channel's window must govern")
	assert.True(t, channels.Usable(time.Date(2026, 9, 13, 13, 31, 0, 0, time.UTC)))
}

// TestRecoveryChannelCooldown_NegativeIsTreatedAsOff documents the boundary: a negative window has no
// meaning as a duration, so it collapses to "off" and the channel is usable immediately.
func TestRecoveryChannelCooldown_NegativeIsTreatedAsOff(t *testing.T) {
	ctx := context.Background()
	svc, _ := newVerificationService(t, identity.WithRecoveryChannelCooldown(-time.Hour))

	user, err := svc.Register(ctx, "", "neg@example.com", "Passw0rd-Original!")
	require.NoError(t, err)
	token, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "recovery@example.com")
	require.NoError(t, err)
	_, err = svc.ConfirmRecoveryEmail(ctx, "", token)
	require.NoError(t, err)

	channels, err := svc.RecoveryChannels(ctx, "", user.ID)
	require.NoError(t, err)
	assert.True(t, channels.Usable(time.Now()),
		"a negative window collapses to the default (off), so the channel is immediately usable")
	assert.True(t, channels.NotBefore.IsZero(), "no window is reported")
}

// recordingSink captures events so the alerting contract can be asserted.
type recordingSink struct{ events []event.Event }

func (s *recordingSink) EmitEvent(_ context.Context, e event.Event) { s.events = append(s.events, e) }

func (s *recordingSink) find(t event.Type) (event.Event, bool) {
	for _, e := range s.events {
		if e.Type == t {
			return e, true
		}
	}
	return event.Event{}, false
}

// TestContactChangesAreAlertable covers the notification contract. Changing the account email or
// adding a recovery channel needs only a live session — not a fresh factor — so the address that
// LOST access is frequently the only party still in a position to notice. The library does not send
// mail itself, so it carries the previous and new contact on the event and the application's sink
// decides what to send. Without that, an attacker who reaches a session once can move the account
// silently, and the previous owner's only signal is that their password stops working.
func TestContactChangesAreAlertable(t *testing.T) {
	ctx := context.Background()
	sink := &recordingSink{}
	svc, _ := newVerificationService(t, identity.WithEventSink(sink))

	const oldEmail = "previous-owner@example.com"
	user, err := svc.Register(ctx, "", oldEmail, "Passw0rd-Original!")
	require.NoError(t, err)

	t.Run("confirming an email change reports the outgoing address", func(t *testing.T) {
		const newEmail = "new-owner@example.com"
		token, err := svc.RequestEmailChange(ctx, "", user.ID, newEmail)
		require.NoError(t, err)
		_, err = svc.ConfirmEmailChange(ctx, "", token)
		require.NoError(t, err)

		ev, ok := sink.find(event.EmailChanged)
		require.True(t, ok, "an email change must be observable")
		assert.Equal(t, oldEmail, ev.Attrs[event.AttrPreviousEmail],
			"the outgoing address is what an alert must reach")
		assert.Equal(t, newEmail, ev.Attrs[event.AttrNewEmail])
	})

	t.Run("enrolling a recovery email reports the channel", func(t *testing.T) {
		token, err := svc.RequestRecoveryEmail(ctx, "", user.ID, "attacker-channel@evil.example")
		require.NoError(t, err)
		_, err = svc.ConfirmRecoveryEmail(ctx, "", token)
		require.NoError(t, err)

		ev, ok := sink.find(event.RecoveryChannelEnrolled)
		require.True(t, ok, "a recovery-channel enrolment must be observable")
		assert.Equal(t, "attacker-channel@evil.example", ev.Attrs[event.AttrRecoveryChannel],
			"the added channel is what the warning is about")
	})

	t.Run("verifying a phone reports the number", func(t *testing.T) {
		token, err := svc.RequestPhoneVerification(ctx, "", user.ID, "+15559876543")
		require.NoError(t, err)
		_, err = svc.ConfirmPhoneVerification(ctx, "", token)
		require.NoError(t, err)

		ev, ok := sink.find(event.PhoneVerified)
		require.True(t, ok)
		assert.Equal(t, "+15559876543", ev.Attrs[event.AttrRecoveryChannel])
	})

	t.Run("no credential is carried on the events", func(t *testing.T) {
		for _, e := range sink.events {
			for k, v := range e.Attrs {
				s, ok := v.(string)
				if !ok {
					continue
				}
				assert.NotContains(t, s, "selector",
					"event %s attr %s must not carry a verification token", e.Type, k)
				assert.NotContains(t, k, "token",
					"event %s must not carry a token attribute", e.Type)
			}
		}
	})
}
