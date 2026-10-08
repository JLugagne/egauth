package memory

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

var errReservedProvider = errors.New(`federated provider "password" is reserved for the password credential`)

func reserved(m identity.Mutation) error {
	switch x := m.(type) {
	case identity.LinkFederated:
		if x.Identity.Provider == passwordProvider {
			return errors.Join(identity.ErrInvalidMutation, errReservedProvider)
		}
	case identity.CreateVerified:
		if x.Federated.Provider == passwordProvider {
			return errors.Join(identity.ErrInvalidMutation, errReservedProvider)
		}
	case identity.UnlinkFederated:
		if x.Provider == passwordProvider {
			return errors.Join(identity.ErrInvalidMutation, errReservedProvider)
		}
	}
	return nil
}

type txn struct {
	s         *Store
	ctx       context.Context
	now       time.Time
	acc       *account
	evicted   *account
	subject   principal.Subject
	epochs    []epochRow
	outbox    []*outboxRow
	epochSeq  uint64
	outboxSeq int64
}

func (tx *txn) step() error {
	return tx.ctx.Err()
}

func (s *Store) Apply(ctx context.Context, m identity.Mutation) (identity.Applied, error) {
	if err := ctx.Err(); err != nil {
		return identity.Applied{}, err
	}
	if err := identity.Validate(m); err != nil {
		return identity.Applied{}, err
	}
	if err := reserved(m); err != nil {
		return identity.Applied{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx := &txn{s: s, ctx: ctx, now: s.now(), epochSeq: s.epochSeq, outboxSeq: s.outboxSeq}
	old, err := tx.mutate(m)
	if err != nil {
		return identity.Applied{}, err
	}
	applied, err := tx.effects(m, old)
	if err != nil {
		return identity.Applied{}, err
	}
	if err := tx.step(); err != nil {
		return identity.Applied{}, err
	}
	s.accounts[tx.subject] = tx.acc
	if tx.evicted != nil {
		s.accounts[tx.evicted.user.Subject] = tx.evicted
	}
	s.epochs = append(s.epochs, tx.epochs...)
	s.outbox = append(s.outbox, tx.outbox...)
	s.epochSeq, s.outboxSeq = tx.epochSeq, tx.outboxSeq
	return applied, nil
}

func subjectOf(m identity.Mutation) principal.Subject {
	switch x := m.(type) {
	case identity.SetPassword:
		return x.Subject
	case identity.MarkEmailVerified:
		return x.Subject
	case identity.ChangeEmail:
		return x.Subject
	case identity.SetPhone:
		return x.Subject
	case identity.SetRecoveryEmail:
		return x.Subject
	case identity.SetDisabledState:
		return x.Subject
	case identity.SetMustChange:
		return x.Subject
	case identity.Tombstone:
		return x.Subject
	case identity.BumpEpoch:
		return x.Subject
	case identity.LinkFederated:
		return x.Subject
	case identity.UnlinkFederated:
		return x.Subject
	}
	return principal.Subject{}
}

func (tx *txn) load(sub principal.Subject) error {
	if err := tx.step(); err != nil {
		return err
	}
	a := tx.s.accounts[sub]
	if a == nil {
		return store.ErrNotFound
	}
	if !a.user.DeletedAt.IsZero() {
		return identity.ErrTombstoned
	}
	tx.subject, tx.acc = sub, a.clone()
	return nil
}

func (tx *txn) mutate(m identity.Mutation) (identity.Identifier, error) {
	if cv, ok := m.(identity.CreateVerified); ok {
		return identity.Identifier{}, tx.create(cv)
	}
	if err := tx.load(subjectOf(m)); err != nil {
		return identity.Identifier{}, err
	}
	if err := tx.step(); err != nil {
		return identity.Identifier{}, err
	}
	a, now := tx.acc, tx.now
	var old identity.Identifier
	switch x := m.(type) {
	case identity.SetPassword:
		a.password = &password{phc: x.PHC, changedAt: now, mustChange: x.Reason.ForcesChange()}
	case identity.MarkEmailVerified:
		if !a.user.EmailVerifiedAt.IsZero() {
			return old, errors.Join(store.ErrConflict, errors.New("identity: email is already verified"))
		}
		a.user.EmailVerifiedAt = now
		a.password, a.links = nil, nil
		if !x.PHC.IsZero() {
			a.password = &password{phc: x.PHC, changedAt: now}
		}
	case identity.ChangeEmail:
		if tx.s.owner(tx.subject.Tenant, x.Email, tx.subject.User) != nil {
			return old, identity.ErrIdentifierTaken
		}
		old = a.user.Email
		a.user.Email, a.user.EmailVerifiedAt = x.Email, now
	case identity.SetPhone:
		if !x.Phone.IsZero() && tx.s.owner(tx.subject.Tenant, x.Phone, tx.subject.User) != nil {
			return old, identity.ErrIdentifierTaken
		}
		old = a.user.Phone
		a.user.Phone, a.user.PhoneVerifiedAt = x.Phone, verifiedAt(x.Phone, now)
	case identity.SetRecoveryEmail:
		old = a.user.RecoveryEmail
		a.user.RecoveryEmail, a.user.RecoveryEmailVerifiedAt = x.RecoveryEmail, verifiedAt(x.RecoveryEmail, now)
	case identity.SetDisabledState:
		switch {
		case !x.Disable:
			a.user.DisabledAt = time.Time{}
		case a.user.DisabledAt.IsZero():
			a.user.DisabledAt = now
		}
	case identity.SetMustChange:
		if a.password == nil {
			if x.MustChange {
				return old, errors.Join(identity.ErrInvalidMutation, errors.New("must change requires a password"))
			}
			break
		}
		a.password.mustChange = x.MustChange
	case identity.Tombstone:
		a.user.DeletedAt = now
	case identity.LinkFederated:
		if err := tx.link(x.Identity); err != nil {
			return old, err
		}
	case identity.UnlinkFederated:
		i := slices.IndexFunc(a.links, func(l identity.FederatedLink) bool {
			return l.Identity.Provider == x.Provider && l.Identity.ProviderSubject == x.ProviderSubject
		})
		if i < 0 {
			return old, store.ErrNotFound
		}
		a.links = slices.Delete(a.links, i, i+1)
	}
	return old, nil
}

func verifiedAt(id identity.Identifier, now time.Time) time.Time {
	if id.IsZero() {
		return time.Time{}
	}
	return now
}

func (tx *txn) link(f identity.FederatedIdentity) error {
	if owner, ok := tx.s.linkOwner(tx.subject.Tenant, f.Provider, f.ProviderSubject); ok {
		switch {
		case owner.user.Subject == tx.subject:
			return errors.Join(store.ErrConflict, errors.New("identity: provider account already linked to this subject"))
		case owner.user.DeletedAt.IsZero():
			return identity.ErrIdentifierTaken
		}
		tx.evicted = owner.clone()
		tx.evicted.links = slices.DeleteFunc(tx.evicted.links, func(l identity.FederatedLink) bool {
			return l.Identity.Provider == f.Provider && l.Identity.ProviderSubject == f.ProviderSubject
		})
	}
	tx.acc.links = append(tx.acc.links, identity.FederatedLink{Subject: tx.subject, Identity: f, LinkedAt: tx.now})
	return nil
}

func (tx *txn) create(m identity.CreateVerified) error {
	if err := tx.step(); err != nil {
		return err
	}
	if tx.s.owner(m.Tenant, m.Email, uuid.Nil) != nil {
		return identity.ErrIdentifierTaken
	}
	id, err := uuid.NewV7()
	if err != nil {
		return errors.Join(errors.New("identity: user id"), err)
	}
	tx.subject = principal.Subject{Tenant: m.Tenant, User: id}
	tx.acc = &account{user: identity.User{Subject: tx.subject, Email: m.Email, EmailVerifiedAt: tx.now, CreatedAt: tx.now}}
	if !m.PHC.IsZero() {
		tx.acc.password = &password{phc: m.PHC, changedAt: tx.now, mustChange: m.MustChange}
	}
	if err := tx.step(); err != nil {
		return err
	}
	if m.Federated != (identity.FederatedIdentity{}) {
		return tx.link(m.Federated)
	}
	return nil
}

func (tx *txn) effects(m identity.Mutation, old identity.Identifier) (identity.Applied, error) {
	fx := identity.EffectsOf(m)
	if fx.BumpsEpoch {
		if err := tx.step(); err != nil {
			return identity.Applied{}, err
		}
		tx.acc.user.SecurityEpoch++
		tx.epochSeq++
		tx.epochs = append(tx.epochs, epochRow{
			seq:    tx.epochSeq,
			change: identity.EpochChange{Subject: tx.subject, NewEpoch: tx.acc.user.SecurityEpoch, Reason: fx.Event},
			at:     tx.now,
		})
	}
	items := identity.OutboxFor(m, tx.subject, old)
	for i := range items {
		if err := tx.step(); err != nil {
			return identity.Applied{}, err
		}
		tx.outboxSeq++
		items[i].ID, items[i].NextAttemptAt, items[i].CreatedAt = tx.outboxSeq, tx.now, tx.now
		tx.outbox = append(tx.outbox, &outboxRow{item: items[i]})
	}
	return identity.Applied{Subject: tx.subject, NewEpoch: tx.acc.user.SecurityEpoch, Outbox: items}, nil
}
