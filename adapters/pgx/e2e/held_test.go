package e2e_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/adapters/pgx/pgxstore"
	"github.com/JLugagne/egauth/kek"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/identity"
)

func TestAHeldAccountAcceptsOnlyTheChangesThatProtectIt(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)
	loadDump(ctx, t, pool)
	require.NoError(t, pgxstore.Migrate(ctx, pool))
	held := map[string]uuid.UUID{
		"unrepresentable email": v016User(ctx, t, pool, "dan doe@example.test", ""),
		"unrepresentable phone": v016User(ctx, t, pool, "erin@example.test", "+0123456789"),
		"colliding email":       v016User(ctx, t, pool, "ｂob@example.test", ""),
	}
	st, err := pgxstore.New(ctx, pool)
	require.NoError(t, err)
	legacy, err := kek.LegacyLocalV016(legacyFixtureKey(t))
	require.NoError(t, err)
	_, err = egauth.UpgradeSecretsV016(ctx, st, legacy, newKEK(t))
	require.NoError(t, err)
	_, err = egauth.UpgradeIdentifiersV016(ctx, st)
	require.ErrorIs(t, err, egauth.ErrIdentifiersHeld)
	tenant, err := principal.ParseTenantID(e2eTenant)
	require.NoError(t, err)

	to, err := identity.NewIdentifier(identity.IdentifierEmail, "attacker@example.test")
	require.NoError(t, err)
	phone, err := identity.NewIdentifier(identity.IdentifierPhone, "+33612345678")
	require.NoError(t, err)
	backup, err := identity.NewIdentifier(identity.IdentifierRecoveryEmail, "backup@example.test")
	require.NoError(t, err)
	phc := identity.NewPasswordHash("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$new")
	for name, id := range held {
		sub := principal.Subject{Tenant: tenant, User: id}
		refused := map[string]identity.Mutation{
			"ChangeEmail":            identity.ChangeEmail{Subject: sub, Email: to},
			"SetPhone":               identity.SetPhone{Subject: sub, Phone: phone},
			"SetRecoveryEmail":       identity.SetRecoveryEmail{Subject: sub, RecoveryEmail: backup},
			"MarkEmailVerified":      identity.MarkEmailVerified{Subject: sub, PHC: phc},
			"LinkFederated":          identity.LinkFederated{Subject: sub, Identity: identity.FederatedIdentity{Provider: "corp", ProviderSubject: "c-1", Authority: "static"}},
			"password change":        identity.SetPassword{Subject: sub, PHC: phc, Reason: identity.RotationPasswordChanged},
			"password reset":         identity.SetPassword{Subject: sub, PHC: phc, Reason: identity.RotationPasswordReset},
			"TOTP enrolment":         identity.BumpEpoch{Subject: sub, Change: identity.FactorTOTPEnrolled},
			"passkey added":          identity.BumpEpoch{Subject: sub, Change: identity.FactorPasskeyAdded},
			"recovery codes renewed": identity.BumpEpoch{Subject: sub, Change: identity.FactorRecoveryCodesRegenerated},
		}
		for what, m := range refused {
			_, err := st.Identity.Apply(ctx, m)
			require.ErrorIs(t, err, identity.ErrIdentifiersHeld, "%s: %s adds to an account whose identifiers await repair", name, what)
		}
		allowed := []struct {
			what string
			m    identity.Mutation
		}{
			{"security revert password", identity.SetPassword{Subject: sub, PHC: phc, Reason: identity.RotationSecurityRevert}},
			{"temporary password", identity.SetPassword{Subject: sub, PHC: phc, Reason: identity.RotationTemporaryPassword}},
			{"SetMustChange", identity.SetMustChange{Subject: sub, MustChange: true}},
			{"TOTP removal", identity.BumpEpoch{Subject: sub, Change: identity.FactorTOTPRemoved}},
			{"passkey removal", identity.BumpEpoch{Subject: sub, Change: identity.FactorPasskeyRemoved}},
			{"recovery email removal", identity.SetRecoveryEmail{Subject: sub}},
			{"SetDisabledState", identity.SetDisabledState{Subject: sub, Disable: true}},
		}
		for _, a := range allowed {
			_, err := st.Identity.Apply(ctx, a.m)
			require.NoError(t, err, "%s: %s protects the account and must apply", name, a.what)
		}
	}
}
