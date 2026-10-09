package identitysvc

import (
	"net/http"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/store/identity"
)

const stateAccountDeleted = "account_deleted"

func (h *acctHandlers) deleteAccount(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	c, err := h.currentAccount(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	sub := c.user.Subject
	if _, err := h.Apply(ctx, identity.Tombstone{Subject: sub}); err != nil {
		r.Fail(w, mutationProblem(err))
		return
	}
	_ = h.audit.Emit(ctx, event.AccountDeleted, scopeOf(sub), audit.Detail{}, nil)
	if c.attrs.Transport() == core.TransportCookies {
		cookie.Discard(w)
		for _, n := range []cookie.Name{cookie.AccessToken, cookie.RefreshToken, cookie.StatefulSession} {
			h.cookies.Clear(w, n)
		}
	}
	r.Respond(w, httpx.Response{Body: journeyBody{State: stateAccountDeleted}})
}
