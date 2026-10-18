package jwt

import (
	"context"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/principal"
)

func (b *Backend) revokeSubject(ctx context.Context, s principal.Subject, keep uuid.UUID) error {
	defer b.families.ForgetSubject(s, keep)
	if err := b.tokens.RevokeForSubject(ctx, s, keep); err != nil {
		return unavailable(err)
	}
	return nil
}

// OnCredentialRotated revokes every family of the subject except those of lineage e.Keep.
func (b *Backend) OnCredentialRotated(ctx context.Context, e lifecycle.CredentialRotated) error {
	return b.revokeSubject(ctx, e.Subject, e.Keep)
}

// OnFactorsChanged revokes every family of the subject except those of lineage e.Keep.
func (b *Backend) OnFactorsChanged(ctx context.Context, e lifecycle.FactorsChanged) error {
	return b.revokeSubject(ctx, e.Subject, e.Keep)
}

// OnIdentifierChanged revokes every family of the subject.
func (b *Backend) OnIdentifierChanged(ctx context.Context, e lifecycle.IdentifierChanged) error {
	return b.revokeSubject(ctx, e.Subject, uuid.Nil)
}

// OnDisabled revokes every family of the subject.
func (b *Backend) OnDisabled(ctx context.Context, e lifecycle.AccountEvent) error {
	return b.revokeSubject(ctx, e.Subject, uuid.Nil)
}

// OnEnabled does nothing: a revoked family never comes back.
func (b *Backend) OnEnabled(context.Context, lifecycle.AccountEvent) error { return nil }

// OnDeleted revokes every family of the subject.
func (b *Backend) OnDeleted(ctx context.Context, e lifecycle.AccountEvent) error {
	return b.revokeSubject(ctx, e.Subject, uuid.Nil)
}

// OnTenantErased erases the tenant's families and API keys from the tokens store.
func (b *Backend) OnTenantErased(ctx context.Context, e lifecycle.TenantErased) error {
	if err := b.tokens.EraseTenant(ctx, e.Tenant); err != nil {
		return unavailable(err)
	}
	return nil
}

// OnSessionEnded revokes the ended family, appending it to the revocation feed.
func (b *Backend) OnSessionEnded(ctx context.Context, e lifecycle.SessionEnded) error {
	return b.revoke(ctx, e.Subject.Tenant, e.Family)
}
