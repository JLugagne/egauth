package identitysvc

import (
	"context"
	"errors"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

// Apply is the shared mutation path: identity.Store.Apply changes the account, bumps the security
// epoch and writes the lifecycle outbox in one transaction, then the outbox rows are handed to the
// dispatcher as the fast path. Once Apply has committed the mutation it reports success; undone rows
// are retried by the reaper (DESIGN §7.1).
func (s *Service) Apply(ctx context.Context, m identity.Mutation) (identity.Applied, error) {
	a, err := s.identity.Apply(ctx, m)
	if err != nil {
		return identity.Applied{}, err
	}
	s.auditIdentifierChanges(ctx, a.Outbox)
	if s.dispatcher != nil && len(a.Outbox) > 0 {
		s.dispatcher.DispatchOutbox(context.WithoutCancel(ctx), a.Outbox)
	}
	return a, nil
}

func (s *Service) auditIdentifierChanges(ctx context.Context, items []identity.OutboxItem) {
	if s.audit == nil {
		return
	}
	seen := map[identity.IdentifierKind]bool{}
	for _, it := range items {
		if it.Event != identity.EventIdentifierChanged || seen[it.Identifier] {
			continue
		}
		seen[it.Identifier] = true
		_ = s.audit.Emit(ctx, event.IdentifierChanged, scopeOf(it.Subject), audit.Detail{}, nil,
			audit.A(event.KeyIdentifierKind, it.Identifier.String()))
	}
}

// VerifyEmailOwnership records the first verified proof that the owner of sub's unverified email
// controls it (registration confirm, /email/verify) and wipes every credential set before that proof
// (C-39): passkeys and TOTP, each behind its own epoch bump, then the password and federated links
// with identity.MarkEmailVerified, which sets phc as the only password when it is non-zero. A crash
// between steps leaves the account unverified and retryable, never verified with a pre-verification
// credential. Before each wipe it re-reads the account and stops unless it is still unverified at the
// epoch its own bump produced, so a proof or security change committed before that re-read aborts it
// instead of being wiped. The factor stores have no delete conditioned on the account, so the re-read
// and the delete are two operations: a factor enrolled between them, after a racing proof verified
// the account, is still wiped; the bump that precedes the delete has then queued its FactorsChanged
// notice to the owner. It returns store.ErrConflict, before wiping anything further, when the
// email is verified or the epoch moved; store.ErrNotFound for an unknown subject and
// identity.ErrTombstoned for a deleted one.
func (s *Service) VerifyEmailOwnership(ctx context.Context, sub core.Subject, phc identity.PasswordHash) (identity.Applied, error) {
	if err := s.stillUnverified(ctx, sub, 0); err != nil {
		return identity.Applied{}, err
	}
	if err := s.wipe(ctx, sub, identity.FactorPasskeyRemoved, s.passkeys.DeleteForSubject); err != nil {
		return identity.Applied{}, errors.Join(errors.New("identitysvc: wiping passkeys"), err)
	}
	if err := s.wipe(ctx, sub, identity.FactorTOTPRemoved, s.mfa.DeleteForSubject); err != nil {
		return identity.Applied{}, errors.Join(errors.New("identitysvc: wiping TOTP"), err)
	}
	return s.Apply(ctx, identity.MarkEmailVerified{Subject: sub, PHC: phc})
}

func (s *Service) wipe(ctx context.Context, sub core.Subject, change identity.FactorChange, del func(context.Context, core.Subject) error) error {
	a, err := s.Apply(ctx, identity.BumpEpoch{Subject: sub, Change: change})
	if err != nil {
		return err
	}
	if err := s.stillUnverified(ctx, sub, a.NewEpoch); err != nil {
		return err
	}
	return del(ctx, sub)
}

func (s *Service) stillUnverified(ctx context.Context, sub core.Subject, epoch uint64) error {
	u, err := s.identity.GetUser(ctx, sub)
	switch {
	case err != nil:
		return err
	case !u.DeletedAt.IsZero():
		return identity.ErrTombstoned
	case !u.EmailVerifiedAt.IsZero(), epoch != 0 && u.SecurityEpoch != epoch:
		return store.ErrConflict
	}
	return nil
}
