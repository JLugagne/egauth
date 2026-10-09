package lifecycle

import "github.com/JLugagne/egauth/store/identity"

// Cell names what one component does for one event: one cell of the DESIGN §7.2 matrix. Every
// adapter of this package declares its row of cells and its tests prove each cell by the store calls
// it makes, so the declared matrix and the behaviour cannot drift apart.
type Cell string

const (
	CellNone              Cell = "none"
	CellAbsent            Cell = "absent"
	CellRevokeAllButKeep  Cell = "revoke all but Keep"
	CellRevokeAll         Cell = "revoke all"
	CellRevokeFamily      Cell = "revoke family"
	CellEraseTenant       Cell = "EraseTenant"
	CellOwnerState        Cell = "unusable via owner state"
	CellOwnerStateRestore Cell = "usable again"
	CellEraseAPIKeys      Cell = "revoke all by erasure"
	// CellDeleteRotated deletes the subject's reset links and codes, sign-in links and codes and MFA
	// flows.
	CellDeleteRotated Cell = "delete reset, link, code and flow"
	// CellDeleteFactorFlows deletes the subject's MFA flows and MFA passkey challenges.
	CellDeleteFactorFlows Cell = "delete MFA flow and MFA passkey"
	// CellDeleteIdentifier deletes sign-in links and codes of the old and current identifiers, and the
	// subject's reset and verification ceremonies.
	CellDeleteIdentifier Cell = "delete link, code, reset and verification"
	// CellDeleteAllButRevert deletes every stored ceremony of the subject except SecurityRevert, which
	// is the owner's way back; a deliberate narrowing of DESIGN 7.2 "delete all".
	CellDeleteAllButRevert Cell = "delete all but revert"
	CellDeleteAll          Cell = "delete all"
	CellErase              Cell = "erase"
	CellNotice             Cell = "notice to the current email with revert link"
	CellNoticeOld          Cell = "notice to the old address with revert link"
	CellTombstoneErase     Cell = "tombstone + erase"
	CellHookAccountDeleted Cell = "Hooks.AccountDeleted"
	CellHookTenantErased   Cell = "Hooks.TenantErased"
	CellHardDelete         Cell = "hard delete when every other outbox row of the subject is done"
	CellEraseTenantLast    Cell = "EraseTenant (last)"
)

// Cells is one row of the matrix: what a component does for each event of Subscriber.
type Cells struct {
	CredentialRotated Cell
	FactorsChanged    Cell
	IdentifierChanged Cell
	Disable           Cell
	Enable            Cell
	Delete            Cell
	TenantErased      Cell
	SessionEnded      Cell
}

func uniform(c Cell) Cells {
	return Cells{c, c, c, c, c, c, c, c}
}

// Golden returns the DESIGN §7.2 matrix, one row per outbox component. The epoch row is not a
// component: identity.Store.Apply bumps it in the mutation transaction. G18 compares
// Dispatcher.Matrix of the composed Auth with it, cell by cell.
func Golden() map[identity.Component]Cells {
	return map[identity.Component]Cells{
		identity.ComponentSessions: {
			CredentialRotated: CellRevokeAllButKeep, FactorsChanged: CellRevokeAllButKeep,
			IdentifierChanged: CellRevokeAll, Disable: CellRevokeAll, Enable: CellNone,
			Delete: CellRevokeAll, TenantErased: CellEraseTenant, SessionEnded: CellRevokeFamily,
		},
		identity.ComponentAPIKeys: {
			CredentialRotated: CellNone, FactorsChanged: CellNone, IdentifierChanged: CellNone,
			Disable: CellOwnerState, Enable: CellOwnerStateRestore, Delete: CellEraseAPIKeys,
			TenantErased: CellEraseTenant, SessionEnded: CellNone,
		},
		identity.ComponentCeremonies: {
			CredentialRotated: CellDeleteRotated, FactorsChanged: CellDeleteFactorFlows,
			IdentifierChanged: CellDeleteIdentifier, Disable: CellDeleteAllButRevert, Enable: CellNone,
			Delete: CellDeleteAll, TenantErased: CellEraseTenant, SessionEnded: CellNone,
		},
		identity.ComponentMFA:        eraseOnDelete(),
		identity.ComponentPasskeys:   eraseOnDelete(),
		identity.ComponentFederation: eraseOnDelete(),
		identity.ComponentNotices: {
			CredentialRotated: CellNotice, FactorsChanged: CellNotice, IdentifierChanged: CellNoticeOld,
			Disable: CellNone, Enable: CellNone, Delete: CellNone, TenantErased: CellNone,
			SessionEnded: CellNone,
		},
		identity.ComponentKeys: withCell(uniform(CellNone), func(c *Cells) { c.TenantErased = CellTombstoneErase }),
		identity.ComponentHooks: withCell(uniform(CellNone), func(c *Cells) {
			c.Delete, c.TenantErased = CellHookAccountDeleted, CellHookTenantErased
		}),
		identity.ComponentIdentity: withCell(uniform(CellNone), func(c *Cells) {
			c.Delete, c.TenantErased = CellHardDelete, CellEraseTenantLast
		}),
	}
}

func eraseOnDelete() Cells {
	return withCell(uniform(CellNone), func(c *Cells) { c.Delete, c.TenantErased = CellErase, CellEraseTenant })
}

func withCell(c Cells, f func(*Cells)) Cells {
	f(&c)
	return c
}

func optional(c identity.Component) bool {
	switch c {
	case identity.ComponentAPIKeys, identity.ComponentFederation, identity.ComponentKeys:
		return true
	}
	return false
}

func accepts(c identity.Component, got Cells) bool {
	want := Golden()[c]
	switch {
	case got == want:
		return true
	case optional(c) && got == uniform(CellAbsent):
		return true
	case c == identity.ComponentHooks:
		relaxed := got
		if got.Delete == CellNone {
			relaxed.Delete = want.Delete
		}
		if got.TenantErased == CellNone {
			relaxed.TenantErased = want.TenantErased
		}
		return relaxed == want
	}
	return false
}
