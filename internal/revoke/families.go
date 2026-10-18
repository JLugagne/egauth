package revoke

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/tokens"
)

// FamilySource is the part of tokens.Store the family cache reads.
type FamilySource interface {
	FamilyState(ctx context.Context, t principal.TenantID, family uuid.UUID) (tokens.FamilyState, error)
	RevocationsSince(ctx context.Context, c store.Cursor) ([]tokens.Revocation, store.Cursor, error)
}

// Family names the session family an access token's sid claims, with the lineage sealed in it.
type Family struct {
	ID      uuid.UUID
	Lineage uuid.UUID
}

type familyKey struct {
	tenant principal.TenantID
	id     uuid.UUID
}

// Families caches refresh-family states, keyed by tenant and sid, following RevocationsSince. It is
// safe for concurrent use.
type Families struct {
	*follower[familyKey, tokens.FamilyState]
}

// NewFamilies returns a stopped family cache over src. It returns ErrInvalidConfig for a nil src or
// a negative capacity.
func NewFamilies(src FamilySource, cfg Config) (*Families, error) {
	if src == nil {
		return nil, errors.Join(ErrInvalidConfig, errors.New("revoke: nil family source"))
	}
	feed := func(ctx context.Context, c store.Cursor) ([]familyKey, store.Cursor, error) {
		revs, next, err := src.RevocationsSince(ctx, c)
		if err != nil {
			return nil, c, err
		}
		out := make([]familyKey, len(revs))
		for i, r := range revs {
			out[i] = familyKey{tenant: r.Tenant, id: r.Family}
		}
		return out, next, nil
	}
	lookup := func(ctx context.Context, k familyKey) (tokens.FamilyState, error) {
		return src.FamilyState(ctx, k.tenant, k.id)
	}
	scope := func(k familyKey) audit.Scope { return audit.Scope{TenantID: k.tenant.String()} }
	f, err := newFollower("families", cfg, feed, lookup, scope)
	if err != nil {
		return nil, err
	}
	return &Families{follower: f}, nil
}

// Forget drops the cached state of family in tenant t, so the next Live reads the store. Call it
// after revoking the family, or a revocation made on this instance is served stale until the next
// poll.
func (f *Families) Forget(t principal.TenantID, family uuid.UUID) {
	f.forget(familyKey{tenant: t, id: family})
}

// ForgetSubject drops the cached state of every family of s outside lineage keep (every family
// when keep is uuid.Nil), matching tokens.Store.RevokeForSubject.
func (f *Families) ForgetSubject(s principal.Subject, keep uuid.UUID) {
	f.forgetWhere(func(_ familyKey, st tokens.FamilyState) bool {
		return st.Subject == s && (keep == uuid.Nil || st.Lineage != keep)
	})
}

// Live returns nil when family exists in s's tenant, belongs to s and to family.Lineage, is not
// revoked and is not past its absolute expiry. It returns ErrNotLive otherwise, and ErrUnavailable
// when the store cannot answer.
func (f *Families) Live(ctx context.Context, s principal.Subject, family Family) error {
	st, err := f.get(ctx, familyKey{tenant: s.Tenant, id: family.ID})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errors.Join(ErrNotLive, err)
		}
		return err
	}
	switch {
	case st.Subject != s:
		return errors.Join(ErrNotLive, errors.New("revoke: family of another subject"))
	case st.Lineage != family.Lineage:
		return errors.Join(ErrNotLive, errors.New("revoke: family of another lineage"))
	case !st.Live(f.clk.Now()):
		return errors.Join(ErrNotLive, errors.New("revoke: family revoked or expired"))
	}
	return nil
}
