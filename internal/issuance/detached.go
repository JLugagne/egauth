package issuance

import (
	"context"
	"errors"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/redirect"
)

// Detached returns the unbound Pending of t that a ceremony created outside any request seals,
// such as the revert link of a security notice (identitysvc.PendingSource). It applies the
// deployment's remember-me policy with no remember intent, no return target and cookie transport;
// a later request that redeems the ceremony starts its own journey through Begin.
func (i *Issuer) Detached(_ context.Context, t core.TenantID) (core.Pending, error) {
	var none redirect.Target
	p, err := core.NewPending(t, core.RememberDeclined, none, core.TransportCookies, i.remember, i.clock.Now())
	if err != nil {
		return core.Pending{}, errors.Join(httpx.ErrInternal, err)
	}
	return p, nil
}
