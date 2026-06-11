package passkey_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Tests for the opt-in attestation policy (conveyance preference + AAGUID allow/deny)
// added in TASK-006/TASK-007. The zero AttestationConfig must preserve today's behavior.

// newAttestationService builds a Service with the secure-by-default requirements satisfied and
// the supplied attestation policy. The returned captureSink records any emitted events.
func newAttestationService(t *testing.T, att passkey.AttestationConfig) (*passkey.Service, *passkeymemory.Store, *captureSink) {
	t.Helper()
	store := passkeymemory.NewStore()
	sink := &captureSink{}
	svc, err := passkey.NewService(store, passkey.Config{
		RPID:           testRPID,
		RPDisplayName:  testRPName,
		RPOrigins:      []string{testOrigin},
		CookieKey:      testCookieKey,
		ChallengeStore: passkeymemory.NewChallengeStore(),
		Events:         sink,
		Attestation:    att,
	})
	require.NoError(t, err)
	return svc, store, sink
}

// attemptRegister runs a full Begin/Finish registration ceremony for an authenticator whose
// AAGUID is set to the supplied 16-byte value, returning the FinishRegistration error (if any).
func attemptRegister(t *testing.T, svc *passkey.Service, userID uuid.UUID, aaguid []byte) error {
	t.Helper()
	ctx := context.Background()
	auth := newSoftAuthenticator(t, testRPID, testOrigin)
	auth.aaguid = aaguid

	_, session, err := svc.BeginRegistration(ctx, "", userID, "user@example.com", "User")
	require.NoError(t, err)

	_, err = svc.FinishRegistration(ctx, "", userID, "user@example.com", "User", *session,
		auth.registrationRequest(t, session.Challenge))
	return err
}

func fixedAAGUID(b byte) []byte {
	a := make([]byte, 16)
	for i := range a {
		a[i] = b
	}
	return a
}

func TestAttestation_NoConfig_BehavesAsToday(t *testing.T) {
	ctx := context.Background()
	// Zero AttestationConfig: a registration from any AAGUID must succeed and be stored,
	// exactly as before this feature existed.
	svc, store, _ := newAttestationService(t, passkey.AttestationConfig{})
	userID := uuid.New()

	err := attemptRegister(t, svc, userID, fixedAAGUID(0xAB))
	require.NoError(t, err)

	creds, err := store.GetCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1, "with no attestation policy the credential must be stored")
}

func TestAttestation_AllowList_RejectsForeignAAGUID(t *testing.T) {
	ctx := context.Background()
	permitted := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	svc, store, sink := newAttestationService(t, passkey.AttestationConfig{
		PermittedAAGUIDs: []uuid.UUID{permitted},
	})
	userID := uuid.New()

	// The authenticator reports a DIFFERENT, non-zero AAGUID, so it is outside the allow-list.
	foreign := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	foreignBytes, err := foreign.MarshalBinary()
	require.NoError(t, err)

	err = attemptRegister(t, svc, userID, foreignBytes)
	require.ErrorIs(t, err, passkey.ErrAttestationRejected,
		"a foreign-AAGUID registration must surface ErrAttestationRejected")

	creds, err := store.GetCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Empty(t, creds, "no credential may be stored when attestation is rejected")

	ev, ok := sink.find(event.AccountBlocked)
	require.True(t, ok, "a rejection event must be emitted")
	require.Equal(t, "passkey_attestation_rejected", ev.Reason)
	require.Equal(t, userID.String(), ev.UserID)
}

func TestAttestation_AllowList_AcceptsPermittedAAGUID(t *testing.T) {
	ctx := context.Background()
	permitted := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	svc, store, _ := newAttestationService(t, passkey.AttestationConfig{
		PermittedAAGUIDs: []uuid.UUID{permitted},
	})
	userID := uuid.New()

	permittedBytes, err := permitted.MarshalBinary()
	require.NoError(t, err)

	err = attemptRegister(t, svc, userID, permittedBytes)
	require.NoError(t, err, "an authenticator on the allow-list must register")

	creds, err := store.GetCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Len(t, creds, 1)
}

func TestAttestation_DenyList_RejectsProhibitedAAGUID(t *testing.T) {
	ctx := context.Background()
	prohibited := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	svc, store, sink := newAttestationService(t, passkey.AttestationConfig{
		ProhibitedAAGUIDs: []uuid.UUID{prohibited},
	})
	userID := uuid.New()

	prohibitedBytes, err := prohibited.MarshalBinary()
	require.NoError(t, err)

	err = attemptRegister(t, svc, userID, prohibitedBytes)
	require.ErrorIs(t, err, passkey.ErrAttestationRejected)

	creds, err := store.GetCredentials(ctx, "", userID)
	require.NoError(t, err)
	require.Empty(t, creds)

	_, ok := sink.find(event.AccountBlocked)
	require.True(t, ok, "a rejection event must be emitted on deny-list rejection")
}

func TestAttestation_ConveyancePropagatedIntoCeremony(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newAttestationService(t, passkey.AttestationConfig{
		ConveyancePreference: protocol.PreferDirectAttestation,
	})
	userID := uuid.New()

	cc, _, err := svc.BeginRegistration(ctx, "", userID, "user@example.com", "User")
	require.NoError(t, err)
	require.Equal(t, protocol.PreferDirectAttestation, cc.Response.Attestation,
		"the configured conveyance preference must flow into the registration ceremony options")
}
