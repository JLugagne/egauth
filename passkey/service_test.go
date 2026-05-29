package passkey_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/JLugagne/libauth/passkey"
	"github.com/JLugagne/libauth/passkey/memory"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testService(t *testing.T) (*passkey.Service, *memory.Store) {
	t.Helper()
	store := memory.NewStore()
	svc, err := passkey.NewService(store, passkey.Config{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	})
	require.NoError(t, err)
	return svc, store
}

// saveTestCredential stores a minimal credential so BeginLogin has something to offer.
func saveTestCredential(t *testing.T, store *memory.Store, uid uuid.UUID, id []byte) {
	t.Helper()
	data, err := json.Marshal(webauthn.Credential{ID: id})
	require.NoError(t, err)
	require.NoError(t, store.SaveCredential(context.Background(), &passkey.Credential{
		UserID: uid, ID: id, Data: data, CreatedAt: time.Now(),
	}, passkey.WithTenant("t1")))
}

func TestNewService_RejectsEmptyConfig(t *testing.T) {
	_, err := passkey.NewService(memory.NewStore(), passkey.Config{})
	assert.Error(t, err, "an empty relying-party config must be rejected")
}

func TestBeginRegistration(t *testing.T) {
	svc, _ := testService(t)
	creation, session, err := svc.BeginRegistration(context.Background(), uuid.New(), "alice", "Alice", passkey.WithTenant("t1"))
	require.NoError(t, err)
	require.NotNil(t, creation)
	assert.NotEmpty(t, creation.Response.Challenge)
	assert.NotEmpty(t, session.Challenge)
}

func TestBeginLogin_NoCredentials(t *testing.T) {
	svc, _ := testService(t)
	_, _, err := svc.BeginLogin(context.Background(), uuid.New(), passkey.WithTenant("t1"))
	assert.ErrorIs(t, err, passkey.ErrNoCredentials)
}

func TestBeginLogin_OffersRegisteredCredential(t *testing.T) {
	svc, store := testService(t)
	uid := uuid.New()
	saveTestCredential(t, store, uid, []byte{0x01, 0x02, 0x03, 0x04})

	assertion, session, err := svc.BeginLogin(context.Background(), uid, passkey.WithTenant("t1"))
	require.NoError(t, err)
	require.NotNil(t, assertion)
	assert.NotEmpty(t, session.Challenge)
	require.Len(t, assertion.Response.AllowedCredentials, 1)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04}, []byte(assertion.Response.AllowedCredentials[0].CredentialID))
}

func TestListAndDeleteCredentials(t *testing.T) {
	svc, store := testService(t)
	uid := uuid.New()
	saveTestCredential(t, store, uid, []byte{0xaa})

	creds, err := svc.ListCredentials(context.Background(), uid, passkey.WithTenant("t1"))
	require.NoError(t, err)
	require.Len(t, creds, 1)

	require.NoError(t, svc.DeleteCredential(context.Background(), uid, []byte{0xaa}, passkey.WithTenant("t1")))
	creds, err = svc.ListCredentials(context.Background(), uid, passkey.WithTenant("t1"))
	require.NoError(t, err)
	assert.Empty(t, creds)
}
