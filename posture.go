package egauth

import (
	"context"
	"errors"

	"github.com/JLugagne/egauth/store"
)

var (
	errNotConstructed = errors.New("egauth: Auth was not built by New")
	errSecondInstance = errors.New("egauth: a second live instance runs on Ephemeral state, which is not shared between instances")
	errStaleCache     = errors.New("egauth: a revocation cache is stale")
	errOutboxStale    = errors.New("egauth: the lifecycle outbox is stale")
)

// Posture is the security posture of a running Auth, for operators and for the golden-config
// assertion of the journey suite.
type Posture struct {
	// OptOuts lists the set InsecureOptOuts fields in declaration order; it is empty for a
	// production configuration.
	OptOuts []OptOut
	// Durability is the one level every security store reports; New refuses a mix.
	Durability store.Durability
	// Instances is the live instance count from the last heartbeat; it is 1 until another instance
	// of the deployment is seen.
	Instances int
}

// OptOut is one acknowledged InsecureOptOuts field.
type OptOut struct {
	Name   string
	Reason string
}

// Ready reports the first unmet readiness condition: ErrClosed after Close, a store whose Ping
// fails (a schema older than the embedded migrations included), a revocation poll older than
// revoke.PollBound, a lifecycle outbox row pending for more than an hour, or a second live
// instance on Ephemeral state. It is safe to call from a readiness probe.
func (a *Auth[C]) Ready(ctx context.Context) error {
	if a.closed.Load() {
		return ErrClosed
	}
	if a.owned == nil {
		return errNotConstructed
	}
	for _, s := range a.stores() {
		if err := s.base.Ping(ctx); err != nil {
			return errors.Join(errors.New("egauth: "+s.field+" is not ready"), err)
		}
	}
	for _, p := range a.owned.pollers {
		if err := p.Ready(); err != nil {
			return errors.Join(errStaleCache, err)
		}
	}
	if err := a.owned.dispatcher.Ready(); err != nil {
		return errors.Join(errOutboxStale, err)
	}
	if a.durability == store.Ephemeral && a.owned.instances.Load() > 1 {
		return errSecondInstance
	}
	return nil
}

// Posture lists the set InsecureOptOuts with their acknowledged reasons, the storage durability
// and the live instance count.
func (a *Auth[C]) Posture() Posture {
	var out []OptOut
	for _, o := range optOuts(&a.cfg.Insecure) {
		if o.set {
			out = append(out, OptOut{Name: o.name, Reason: o.ack.Reason()})
		}
	}
	n := 1
	if a.owned != nil {
		n = max(int(a.owned.instances.Load()), 1)
	}
	return Posture{OptOuts: out, Durability: a.durability, Instances: n}
}

func scalesLimiter[C any](cfg *Config[C], common store.Durability) bool {
	return common == store.Shared && cfg.RateLimit.Durability() == store.Ephemeral
}
