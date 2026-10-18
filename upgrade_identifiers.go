package egauth

import (
	"context"
	"errors"

	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
)

// ErrIdentifiersHeld is returned by UpgradeIdentifiersV016, with the report, when a v0.16
// identifier could not be made canonical. It does not stop New: a held account stays readable by
// subject and accepts only protective changes (disable, forced password change, ending sessions,
// unlinking, deletion). Email, phone, password and factor changes answer 409
// identifier_repair_required, and no login finds it by the held identifier, until an operator
// repairs the stored value and runs the upgrade again.
var ErrIdentifiersHeld = errors.New("egauth: v0.16 identifiers remain that v0.17 cannot represent or that collide")

// IdentifierProblem says why UpgradeIdentifiersV016 held an identifier back.
type IdentifierProblem uint8

const (
	// IdentifierUnrepresentable is a value v0.17 normalisation refuses, such as a quoted local part
	// ("john doe"@example.com stored as john doe@example.com), consecutive dots, or a phone whose
	// first digit after '+' is 0. A value NewIdentifier also refuses reads as the zero Identifier.
	IdentifierUnrepresentable IdentifierProblem = iota + 1
	// IdentifierCollides is an email or phone whose canonical form (v0.17 folds compatibility
	// characters: ｊｏｈｎ@ is john@) is owned by another live account of the tenant. Nothing is
	// merged: the held value stays verbatim.
	IdentifierCollides
)

// HeldIdentifier names a held identifier without its value.
type HeldIdentifier struct {
	Subject principal.Subject
	Kind    identity.IdentifierKind
	Problem IdentifierProblem
}

// IdentifierUpgradeReport is the outcome of one UpgradeIdentifiersV016 run. Upgraded counts the
// accounts this run marked canonical, Rewritten the identifier values it changed, Concurrent the
// accounts another writer changed first, and Held lists every identifier left in place; held
// accounts are listed again by every run.
type IdentifierUpgradeReport struct {
	Upgraded   int
	Rewritten  int
	Concurrent int
	Held       []HeldIdentifier
}

// UpgradeIdentifiersV016 re-normalises the email, phone and recovery email of every account a v0.16
// deployment wrote, with the normalisation v0.17 applies to logins, and marks the account checked.
// v0.16 kept compatibility characters (NFC instead of NFKC), quoted local parts and phones that are
// not E.164, so without it some accounts are not found by their own identifier and a second account
// can register the folded address. It writes through the store's compare-and-swap, bumps no epoch,
// is idempotent and safe to run concurrently. An identifier that cannot be made canonical is
// reported and left verbatim, and the run returns ErrIdentifiersHeld after every other account was
// handled. A store failure or a cancelled ctx stops the run and returns it. New refuses to start
// while an account is unchecked, so run it once at startup, before New, after draining the v0.16
// replicas.
func UpgradeIdentifiersV016(ctx context.Context, s Storage) (IdentifierUpgradeReport, error) {
	var rep IdentifierUpgradeReport
	if !present(s.Identity) {
		return rep, errors.New("egauth: UpgradeIdentifiersV016 needs Storage.Identity")
	}
	var after principal.Subject
	for {
		rows, err := s.Identity.V016Identifiers(ctx, after, upgradePageSize)
		if err != nil {
			return rep, errors.Join(errors.New("egauth: listing v0.16 identifiers"), err)
		}
		if len(rows) == 0 {
			break
		}
		if rows[len(rows)-1].Subject == after {
			return rep, errors.New("egauth: v0.16 identifier listing did not advance")
		}
		for _, r := range rows {
			if err := upgradeIdentifiers(ctx, s.Identity, r, &rep); err != nil {
				return rep, err
			}
		}
		after = rows[len(rows)-1].Subject
	}
	if len(rep.Held) > 0 {
		return rep, ErrIdentifiersHeld
	}
	return rep, nil
}

type identifierPlan struct {
	up        identity.IdentifierUpgrade
	held      []HeldIdentifier
	rewritten []identity.IdentifierKind
}

func planIdentifiers(ctx context.Context, st identity.Store, r identity.V016Identifiers) (identifierPlan, error) {
	p := identifierPlan{up: identity.IdentifierUpgrade{Old: r, State: identity.IdentifiersCanonical}}
	for _, f := range []struct {
		kind   identity.IdentifierKind
		stored string
		dst    **identity.Identifier
	}{
		{identity.IdentifierEmail, r.Email, &p.up.Email},
		{identity.IdentifierPhone, r.Phone, &p.up.Phone},
		{identity.IdentifierRecoveryEmail, r.RecoveryEmail, &p.up.RecoveryEmail},
	} {
		if f.stored == "" {
			continue
		}
		id, err := identitysvc.NormalizeAs(f.kind, f.stored)
		if err != nil {
			p.held = append(p.held, HeldIdentifier{Subject: r.Subject, Kind: f.kind, Problem: IdentifierUnrepresentable})
			continue
		}
		if id.Value() == f.stored {
			continue
		}
		taken, err := ownedByAnother(ctx, st, r, id)
		if err != nil {
			return identifierPlan{}, err
		}
		if taken {
			p.held = append(p.held, HeldIdentifier{Subject: r.Subject, Kind: f.kind, Problem: IdentifierCollides})
			continue
		}
		*f.dst = &id
		p.rewritten = append(p.rewritten, f.kind)
	}
	if len(p.held) > 0 {
		p.up.State = identity.IdentifiersHeld
	}
	return p, nil
}

func ownedByAnother(ctx context.Context, st identity.Store, r identity.V016Identifiers, id identity.Identifier) (bool, error) {
	if r.Tombstoned || id.Kind() == identity.IdentifierRecoveryEmail {
		return false, nil
	}
	u, err := st.FindUser(ctx, r.Subject.Tenant, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	case err != nil:
		return false, errors.Join(errors.New("egauth: looking up a canonical v0.16 identifier"), err)
	}
	return u.Subject != r.Subject, nil
}

func upgradeIdentifiers(ctx context.Context, st identity.Store, r identity.V016Identifiers, rep *IdentifierUpgradeReport) error {
	p, err := planIdentifiers(ctx, st, r)
	if err != nil {
		return err
	}
	ok, err := st.UpgradeIdentifiers(ctx, p.up)
	if errors.Is(err, identity.ErrIdentifierTaken) {
		p = collided(r, p)
		ok, err = st.UpgradeIdentifiers(ctx, p.up)
	}
	if err != nil {
		return errors.Join(errors.New("egauth: storing a re-normalised v0.16 identifier"), err)
	}
	switch {
	case !ok:
		rep.Concurrent++
	case p.up.State == identity.IdentifiersHeld:
		rep.Rewritten += len(p.rewritten)
		rep.Held = append(rep.Held, p.held...)
	default:
		rep.Upgraded++
		rep.Rewritten += len(p.rewritten)
	}
	return nil
}

func collided(r identity.V016Identifiers, p identifierPlan) identifierPlan {
	out := identifierPlan{up: identity.IdentifierUpgrade{Old: r, State: identity.IdentifiersHeld}, held: p.held}
	for _, k := range p.rewritten {
		if k == identity.IdentifierRecoveryEmail {
			out.up.RecoveryEmail = p.up.RecoveryEmail
			out.rewritten = append(out.rewritten, k)
			continue
		}
		out.held = append(out.held, HeldIdentifier{Subject: r.Subject, Kind: k, Problem: IdentifierCollides})
	}
	return out
}
