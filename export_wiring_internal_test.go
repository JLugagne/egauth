package egauth

import (
	"context"
	"net/http"
	"time"

	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/issuance"
	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/internal/session"
	"github.com/JLugagne/egauth/store/ceremony"
)

type OwnedView struct {
	Backend    session.Backend
	Dispatcher *lifecycle.Dispatcher
	Identity   *identitysvc.Service
	Accounts   *identitysvc.Accounts
	Issuer     *issuance.Issuer
	Renewer    *session.Renewer
	Env        httpx.Env
	Patterns   []string
	DataKey    []byte
	Limiter    httpx.Limiter
	Fields     map[string]bool
}

func OwnedOf[C any](a *Auth[C]) OwnedView {
	o := a.owned
	return OwnedView{
		Backend: o.backend, Dispatcher: o.dispatcher, Identity: o.identity, Accounts: o.accounts, Issuer: o.issuer,
		Renewer: o.renewer, Env: o.env, Patterns: o.table.Patterns(a.cfg.BasePath), DataKey: o.dataKey, Limiter: o.limiter,
		Fields: map[string]bool{
			"clock": true, "events": o.events != nil, "audit": o.audit != nil, "dataKey": len(o.dataKey) == dataKeyLen,
			"cookies": o.cookies != (cookie.Policy{}), "clients": o.clients != nil, "trusted": !o.trusted.IsZero(),
			"outbound": o.outbound != nil, "limiter": o.limiter != nil, "epochs": o.epochs != nil, "families": o.families != nil,
			"keys": o.keys != nil, "codec": o.codec != nil, "renewer": o.renewer != nil, "backend": o.backend != nil,
			"enrollment": o.enrollment != nil, "identity": o.identity != nil, "accounts": o.accounts != nil,
			"issuer": o.issuer != nil, "flow": o.flow != nil, "mfa": o.mfa != nil, "passkeys": o.passkeys != nil,
			"codes": o.codes != nil, "federation": o.federation != nil, "external": o.external != nil,
			"dispatcher": o.dispatcher != nil, "reaper": o.reaper != nil, "preamble": o.preamble != nil,
			"instance": o.instance.String() != "", "heartbeat": o.beat != nil,
		},
	}
}

func SetStartupTimeout(d time.Duration) (restore func()) {
	old := startupTimeout
	startupTimeout = d
	return func() { startupTimeout = old }
}

func LinkOf[C any](a *Auth[C], t core.TenantID, k ceremony.Kind, handle string) (string, error) {
	return links{origins: a.owned.origins, pages: a.cfg.Pages}.Link(context.Background(), t, k, handle)
}

func Pulse[C any](a *Auth[C]) error {
	return a.owned.pulse(context.Background(), a.cfg.Storage.Deployment)
}

func ClaimsFingerprint[C any]() string { return claimsFingerprint[C]() }

func Handler[C any](a *Auth[C]) http.Handler {
	mux := http.NewServeMux()
	_ = a.owned.table.Mount(mux, a.cfg.BasePath, a.owned.preamble)
	return mux
}

func MountTwice[C any](a *Auth[C]) (first, second error) {
	mux := http.NewServeMux()
	first = mountProbe(mux, a.owned.table, a.cfg.BasePath, a.owned.preamble)
	second = mountProbe(mux, a.owned.table, a.cfg.BasePath, a.owned.preamble)
	return first, second
}
