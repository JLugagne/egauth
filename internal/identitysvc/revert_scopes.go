package identitysvc

import (
	"context"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
)

// Scope returns the ceremony scope of id (ScopeKey.Scope).
func (a *Accounts) Scope(id identity.Identifier) (ceremony.Scope, error) {
	return a.scopes.Scope(id)
}

// RevertScopes returns every ceremony scope that holds SecurityRevert data of sub beyond the
// current identifiers: the anchors of each previous email address still on record and of current,
// and the span, lock and tenure bookkeeping. The tenure scope comes last because it is the only
// record of the previous addresses: a caller deleting the scopes in order and stopping at the first
// failure can retry the rest. The revert links sent to a previous address are not included: that
// scope is per address, so it may hold another account's links; they expire with their TTL.
// Addresses already dropped from the tenure records cannot be enumerated.
func (a *Accounts) RevertScopes(ctx context.Context, sub core.Subject, current []identity.Identifier) ([]ceremony.Scope, error) {
	tenures, err := a.tenures(ctx, sub)
	if err != nil {
		return nil, err
	}
	var scopes []ceremony.Scope
	var macs [][]byte
	anchored := map[identity.Identifier]bool{}
	anchor := func(id identity.Identifier) {
		if !id.IsZero() && !anchored[id] {
			anchored[id] = true
			macs = append(macs, a.keyed(labelRevertAnchor, sub, []byte(id.Value())))
		}
	}
	for _, id := range current {
		anchor(id)
	}
	for _, t := range tenures {
		if !t.live || t.addr == "" {
			continue
		}
		id, err := identity.NewIdentifier(identity.IdentifierEmail, t.addr)
		if err != nil {
			continue
		}
		anchor(id)
	}
	macs = append(macs, a.keyed(labelRevertSpan, sub), a.keyed(labelRevertLock, sub), a.keyed(labelRevertTenure, sub))
	for _, mac := range macs {
		s, err := ceremony.IdentifierScope(mac)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, s)
	}
	return scopes, nil
}
