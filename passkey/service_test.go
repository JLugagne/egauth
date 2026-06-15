package passkey_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/JLugagne/egauth/passkey"
	"github.com/JLugagne/egauth/passkey/memory"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testService(t *testing.T) (*passkey.Service, *memory.Store) {
	t.Helper()
	store := memory.NewStore()
	svc, err := passkey.NewService(store, passkey.Config{
		RPID:           "example.com",
		RPDisplayName:  "Example",
		RPOrigins:      []string{"https://example.com"},
		CookieKey:      testCookieKey,
		ChallengeStore: memory.NewChallengeStore(),
	})
	require.NoError(t, err)
	return svc, store
}

// saveTestCredential stores a minimal credential so BeginLogin has something to offer.
func saveTestCredential(t *testing.T, store *memory.Store, uid uuid.UUID, id []byte) {
	t.Helper()
	data, err := json.Marshal(webauthn.Credential{ID: id})
	require.NoError(t, err)
	require.NoError(t, store.SaveCredential(context.Background(), "t1", &passkey.Credential{
		UserID: uid, ID: id, Data: data, CreatedAt: time.Now(),
	}))
}

func TestNewService_RejectsEmptyConfig(t *testing.T) {
	_, err := passkey.NewService(memory.NewStore(), passkey.Config{})
	assert.Error(t, err, "an empty config must be rejected")
}

// secureCfg returns a Config that satisfies every secure-by-default requirement, so individual
// tests can drop one field to assert the corresponding construction failure.
func secureCfg() passkey.Config {
	return passkey.Config{
		RPID:           "example.com",
		RPDisplayName:  "Example",
		RPOrigins:      []string{"https://example.com"},
		CookieKey:      testCookieKey,
		ChallengeStore: memory.NewChallengeStore(),
	}
}

func TestNewService_RequiresCookieKey(t *testing.T) {
	cfg := secureCfg()
	cfg.CookieKey = nil
	_, err := passkey.NewService(memory.NewStore(), cfg)
	assert.ErrorIs(t, err, passkey.ErrCookieKeyMissing,
		"construction must fail fast when no cookie key is supplied")
}

func TestNewService_RejectsShortCookieKey(t *testing.T) {
	cfg := secureCfg()
	cfg.CookieKey = []byte("too-short")
	_, err := passkey.NewService(memory.NewStore(), cfg)
	assert.ErrorIs(t, err, passkey.ErrCookieKeyMissing,
		"a cookie key shorter than MinCookieKeyLength must be rejected at construction")
}

func TestNewService_RequiresChallengeStore(t *testing.T) {
	cfg := secureCfg()
	cfg.ChallengeStore = nil
	_, err := passkey.NewService(memory.NewStore(), cfg)
	assert.ErrorIs(t, err, passkey.ErrChallengeStoreMissing,
		"construction must fail fast when no challenge store is supplied")
}

func TestNewService_ChallengeStoreOptOut(t *testing.T) {
	cfg := secureCfg()
	cfg.ChallengeStore = nil
	cfg.InsecureNoChallengeStore = true
	svc, err := passkey.NewService(memory.NewStore(), cfg)
	require.NoError(t, err, "the explicit opt-out must allow construction without a challenge store")
	assert.NotNil(t, svc)
}

func TestBeginRegistration(t *testing.T) {
	svc, _ := testService(t)
	creation, session, err := svc.BeginRegistration(context.Background(), "t1", uuid.Must(uuid.NewV7()), "alice", "Alice")
	require.NoError(t, err)
	require.NotNil(t, creation)
	assert.NotEmpty(t, creation.Response.Challenge)
	assert.NotEmpty(t, session.Challenge)
}

func TestBeginLogin_NoCredentials(t *testing.T) {
	svc, _ := testService(t)
	_, _, err := svc.BeginLogin(context.Background(), "t1", uuid.Must(uuid.NewV7()))
	assert.ErrorIs(t, err, passkey.ErrNoCredentials)
}

func TestBeginLogin_OffersRegisteredCredential(t *testing.T) {
	svc, store := testService(t)
	uid := uuid.Must(uuid.NewV7())
	saveTestCredential(t, store, uid, []byte{0x01, 0x02, 0x03, 0x04})

	assertion, session, err := svc.BeginLogin(context.Background(), "t1", uid)
	require.NoError(t, err)
	require.NotNil(t, assertion)
	assert.NotEmpty(t, session.Challenge)
	require.Len(t, assertion.Response.AllowedCredentials, 1)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, []byte(assertion.Response.AllowedCredentials[0].CredentialID))
}

func TestListAndDeleteCredentials(t *testing.T) {
	svc, store := testService(t)
	uid := uuid.Must(uuid.NewV7())
	saveTestCredential(t, store, uid, []byte{0xaa})

	creds, err := svc.ListCredentials(context.Background(), "t1", uid)
	require.NoError(t, err)
	require.Len(t, creds, 1)

	require.NoError(t, svc.DeleteCredential(context.Background(), "t1", uid, []byte{0xaa}))
	creds, err = svc.ListCredentials(context.Background(), "t1", uid)
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestPasskeyNewServiceNilStoreErrors(t *testing.T) {
	cfg := secureCfg()
	_, err := passkey.NewService(nil, cfg)
	assert.ErrorIs(t, err, passkey.ErrNilStore,
		"NewService with a nil store must return ErrNilStore at construction, not nil-panic on first request")
}
