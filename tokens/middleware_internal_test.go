package tokens

import (
	"testing"

	"github.com/JLugagne/egauth"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestActorFromClaims_PrincipalMapping(t *testing.T) {
	subject := uuid.Must(uuid.NewV7())

	t.Run("Service subject is the key id (KeyID set, UserID zero)", func(t *testing.T) {
		actor := actorFromClaims(&Claims[struct{}]{
			Subject:  subject,
			TenantID: "tenant-1",
			Kind:     egauth.Service,
		})
		assert.Equal(t, subject, actor.KeyID, "Service subject must land on KeyID")
		assert.Equal(t, uuid.Nil, actor.UserID, "Service must not carry a UserID")
		assert.Equal(t, egauth.Service, actor.Kind)
		assert.True(t, actor.IsMachine())
	})

	t.Run("PAT subject is the owning user (UserID set, KeyID zero)", func(t *testing.T) {
		actor := actorFromClaims(&Claims[struct{}]{
			Subject:  subject,
			TenantID: "tenant-1",
			Kind:     egauth.PAT,
		})
		assert.Equal(t, subject, actor.UserID, "PAT subject must land on UserID")
		assert.Equal(t, uuid.Nil, actor.KeyID, "JWT path cannot carry a PAT key id")
		assert.Equal(t, egauth.PAT, actor.Kind)
		assert.True(t, actor.IsHuman())
	})

	t.Run("User (zero Kind) subject is the user (UserID set, KeyID zero)", func(t *testing.T) {
		actor := actorFromClaims(&Claims[struct{}]{
			Subject:  subject,
			TenantID: "tenant-1",
		})
		assert.Equal(t, subject, actor.UserID)
		assert.Equal(t, uuid.Nil, actor.KeyID)
		assert.Equal(t, egauth.PrincipalKind(""), actor.Kind)
		assert.True(t, actor.IsHuman())
	})
}
