package jwt

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/tokens"
)

type familyStore interface {
	Durability() store.Durability
	Create(ctx context.Context, r tokens.RefreshRecord) error
	Get(ctx context.Context, t principal.TenantID, tokenHash []byte) (tokens.RefreshRecord, error)
	ConsumeForRotation(ctx context.Context, req tokens.RotationRequest) (tokens.Rotation, error)
	Reissue(ctx context.Context, req tokens.ReissueRequest) error
	RevokeFamily(ctx context.Context, t principal.TenantID, family uuid.UUID) error
	RevokeForSubject(ctx context.Context, s principal.Subject, keep uuid.UUID) error
	EraseTenant(ctx context.Context, t principal.TenantID) error
}

type forgetting struct {
	tokens   tokens.Store
	families *revoke.Families
}

func (f forgetting) Durability() store.Durability { return f.tokens.Durability() }

func (f forgetting) Create(ctx context.Context, r tokens.RefreshRecord) error {
	return f.tokens.Create(ctx, r)
}

func (f forgetting) Get(ctx context.Context, t principal.TenantID, tokenHash []byte) (tokens.RefreshRecord, error) {
	return f.tokens.Get(ctx, t, tokenHash)
}

func (f forgetting) ConsumeForRotation(ctx context.Context, req tokens.RotationRequest) (tokens.Rotation, error) {
	r, err := f.tokens.ConsumeForRotation(ctx, req)
	if errors.Is(err, tokens.ErrReused) {
		f.families.Forget(req.Next.Tenant(), req.Next.Family())
	}
	return r, err
}

func (f forgetting) Reissue(ctx context.Context, req tokens.ReissueRequest) error {
	defer f.families.Forget(req.Next.Tenant(), req.Family)
	return f.tokens.Reissue(ctx, req)
}

func (f forgetting) RevokeFamily(ctx context.Context, t principal.TenantID, family uuid.UUID) error {
	defer f.families.Forget(t, family)
	return f.tokens.RevokeFamily(ctx, t, family)
}

func (f forgetting) RevokeForSubject(ctx context.Context, s principal.Subject, keep uuid.UUID) error {
	defer f.families.ForgetSubject(s, keep)
	return f.tokens.RevokeForSubject(ctx, s, keep)
}

func (f forgetting) EraseTenant(ctx context.Context, t principal.TenantID) error {
	defer f.families.ForgetTenant(t)
	return f.tokens.EraseTenant(ctx, t)
}
