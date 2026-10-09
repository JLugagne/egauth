package stateful

import (
	"context"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/principal"
)

func (b *Backend) revokeSubject(ctx context.Context, s principal.Subject, keep uuid.UUID) error {
	if err := b.sessions.RevokeForSubject(ctx, s, keep); err != nil {
		return unavailable(err)
	}
	return nil
}

// OnCredentialRotated ends every session of the subject except those of lineage e.Keep.
func (b *Backend) OnCredentialRotated(ctx context.Context, e lifecycle.CredentialRotated) error {
	return b.revokeSubject(ctx, e.Subject, e.Keep)
}

// OnFactorsChanged ends every session of the subject except those of lineage e.Keep.
func (b *Backend) OnFactorsChanged(ctx context.Context, e lifecycle.FactorsChanged) error {
	return b.revokeSubject(ctx, e.Subject, e.Keep)
}

// OnIdentifierChanged ends every session of the subject.
func (b *Backend) OnIdentifierChanged(ctx context.Context, e lifecycle.IdentifierChanged) error {
	return b.revokeSubject(ctx, e.Subject, uuid.Nil)
}

// OnDisabled ends every session of the subject.
func (b *Backend) OnDisabled(ctx context.Context, e lifecycle.AccountEvent) error {
	return b.revokeSubject(ctx, e.Subject, uuid.Nil)
}

// OnEnabled does nothing: an ended session never comes back.
func (b *Backend) OnEnabled(context.Context, lifecycle.AccountEvent) error { return nil }

// OnDeleted ends and erases every session row of the subject.
func (b *Backend) OnDeleted(ctx context.Context, e lifecycle.AccountEvent) error {
	if err := b.sessions.DeleteForSubject(ctx, e.Subject); err != nil {
		return unavailable(err)
	}
	return nil
}

// OnTenantErased erases the tenant's session rows.
func (b *Backend) OnTenantErased(ctx context.Context, e lifecycle.TenantErased) error {
	if err := b.sessions.EraseTenant(ctx, e.Tenant); err != nil {
		return unavailable(err)
	}
	return nil
}

// OnSessionEnded ends the session row e.Family of the subject, appending it to the revocation
// feed.
func (b *Backend) OnSessionEnded(ctx context.Context, e lifecycle.SessionEnded) error {
	if err := b.sessions.RevokeSession(ctx, e.Subject, e.Family); err != nil {
		return unavailable(err)
	}
	return nil
}
