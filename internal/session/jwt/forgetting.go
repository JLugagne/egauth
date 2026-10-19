package jwt

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/revoke"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/tokens"
)

type forgetting struct {
	tokens.Store
	families *revoke.Families
}

func (f forgetting) ConsumeForRotation(ctx context.Context, req tokens.RotationRequest) (tokens.Rotation, error) {
	r, err := f.Store.ConsumeForRotation(ctx, req)
	if errors.Is(err, tokens.ErrReused) {
		f.families.Forget(req.Next.Tenant(), req.Next.Family())
	}
	return r, err
}

func (f forgetting) Reissue(ctx context.Context, req tokens.ReissueRequest) error {
	defer f.families.Forget(req.Next.Tenant(), req.Family)
	return f.Store.Reissue(ctx, req)
}

func (f forgetting) RevokeFamily(ctx context.Context, t principal.TenantID, family uuid.UUID) error {
	defer f.families.Forget(t, family)
	return f.Store.RevokeFamily(ctx, t, family)
}

func (f forgetting) RevokeForSubject(ctx context.Context, s principal.Subject, keep uuid.UUID) error {
	defer f.families.ForgetSubject(s, keep)
	return f.Store.RevokeForSubject(ctx, s, keep)
}

func (f forgetting) DeleteForSubject(ctx context.Context, s principal.Subject) error {
	defer f.families.ForgetSubject(s, uuid.Nil)
	return f.Store.DeleteForSubject(ctx, s)
}

func (f forgetting) EraseTenant(ctx context.Context, t principal.TenantID) error {
	defer f.families.ForgetTenant(t)
	return f.Store.EraseTenant(ctx, t)
}
