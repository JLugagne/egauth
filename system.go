package egauth

import (
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/principal"
)

// System returns a caller for background jobs acting on tenant, the only tenant it may then act
// on. Every facade refuses it with ErrSystemCallerInRequest when the context descends from a
// request served through Routes, and every use emits event.SystemCallerUsed carrying reason; a
// handler the integrator mounts outside Routes is not detected, so never pass its context. reason
// is exported as a public event attribute, so it must name the job, never a person: 1 to 128 bytes
// of printable ASCII, otherwise ErrInvalidRequest. A tenant the Tenancy can never serve returns
// ErrTenantNotServed, here and at every use, also for a caller another Auth minted. A System caller
// cannot act through APIKeys, whose keys belong to a user.
func (a *Auth[C]) System(tenant principal.TenantID, reason string) (principal.Caller, error) {
	if err := checkSystemReason(reason); err != nil {
		return principal.Caller{}, err
	}
	if err := a.facade().served(tenant); err != nil {
		return principal.Caller{}, err
	}
	return core.SystemCaller(tenant, reason)
}
