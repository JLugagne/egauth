package lifecycle_test

import (
	"context"
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/internal/lifecycle"
	"github.com/JLugagne/egauth/internal/principalctx"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/federation"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/keys"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/passkey"
	"github.com/JLugagne/egauth/store/tokens"
)

type calls struct {
	mu   sync.Mutex
	log  []string
	fail map[string]error
}

func newCalls() *calls { return &calls{fail: map[string]error{}} }

func (c *calls) add(call string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log = append(c.log, call)
	for prefix, err := range c.fail {
		if strings.HasPrefix(call, prefix) {
			return err
		}
	}
	return nil
}

func (c *calls) failOn(prefix string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		delete(c.fail, prefix)
		return
	}
	c.fail[prefix] = err
}

func (c *calls) take() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.log
	c.log = nil
	return out
}

func mustTenant(t *testing.T, s string) principal.TenantID {
	t.Helper()
	tid, err := principal.ParseTenantID(s)
	if err != nil {
		t.Fatal(err)
	}
	return tid
}

func mustID(t *testing.T, k identity.IdentifierKind, v string) identity.Identifier {
	t.Helper()
	id, err := identity.NewIdentifier(k, v)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type fakeTokens struct {
	tokens.Store
	c *calls
}

func (f fakeTokens) DeleteForSubject(_ context.Context, s principal.Subject) error {
	return f.c.add("tokens.DeleteForSubject " + s.User.String())
}

func (f fakeTokens) EraseTenant(_ context.Context, t principal.TenantID) error {
	return f.c.add("tokens.EraseTenant " + t.String())
}

type fakeCeremonies struct {
	ceremony.Store
	c      *calls
	labels map[string]string
}

func (f fakeCeremonies) DeleteForScope(_ context.Context, t principal.TenantID, scopeHash []byte, kinds ...ceremony.Kind) (int64, error) {
	label, ok := f.labels[string(scopeHash)]
	if !ok {
		label = "unknown"
	}
	names := make([]string, 0, len(kinds))
	for _, k := range kinds {
		names = append(names, k.String())
	}
	return 0, f.c.add("ceremony.DeleteForScope " + t.String() + " " + label + " " + strings.Join(names, ","))
}

func (f fakeCeremonies) EraseTenant(_ context.Context, t principal.TenantID) error {
	return f.c.add("ceremony.EraseTenant " + t.String())
}

type fakeScoper struct {
	labels map[string]string
	err    error
}

func (f fakeScoper) RevertScopes(context.Context, principal.Subject, []identity.Identifier) ([]ceremony.Scope, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []ceremony.Scope
	for _, label := range []string{"revert-history", "revert-tenure"} {
		sum := sha256.Sum256([]byte(label))
		f.labels[string(sum[:])] = label
		s, err := ceremony.IdentifierScope(sum[:])
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (f fakeScoper) Scope(id identity.Identifier) (ceremony.Scope, error) {
	sum := sha256.Sum256([]byte(id.Kind().String() + "/" + id.Value()))
	f.labels[string(sum[:])] = id.Kind().String() + ":" + id.Value()
	return ceremony.IdentifierScope(sum[:])
}

type fakeAccounts struct {
	user identity.User
	err  error
}

func (f fakeAccounts) GetUser(context.Context, principal.Subject) (identity.User, error) {
	return f.user, f.err
}

type fakeMFA struct {
	mfa.Store
	c *calls
}

func (f fakeMFA) DeleteForSubject(_ context.Context, s principal.Subject) error {
	return f.c.add("mfa.DeleteForSubject " + s.User.String())
}

func (f fakeMFA) EraseTenant(_ context.Context, t principal.TenantID) error {
	return f.c.add("mfa.EraseTenant " + t.String())
}

type fakePasskeys struct {
	passkey.Store
	c *calls
}

func (f fakePasskeys) DeleteForSubject(_ context.Context, s principal.Subject) error {
	return f.c.add("passkey.DeleteForSubject " + s.User.String())
}

func (f fakePasskeys) EraseTenant(_ context.Context, t principal.TenantID) error {
	return f.c.add("passkey.EraseTenant " + t.String())
}

type fakeFederation struct {
	federation.Store
	c *calls
}

func (f fakeFederation) DeleteForSubject(_ context.Context, s principal.Subject) error {
	return f.c.add("federation.DeleteForSubject " + s.User.String())
}

func (f fakeFederation) EraseTenant(_ context.Context, t principal.TenantID) error {
	return f.c.add("federation.EraseTenant " + t.String())
}

type fakeKeys struct {
	keys.Store
	c *calls
}

func (f fakeKeys) Tombstone(_ context.Context, t principal.TenantID) error {
	return f.c.add("keys.Tombstone " + t.String())
}

func (f fakeKeys) EraseTenant(_ context.Context, t principal.TenantID) error {
	return f.c.add("keys.EraseTenant " + t.String())
}

type fakeIdentity struct {
	store.Base
	c *calls
}

func (f fakeIdentity) EraseUser(_ context.Context, s principal.Subject) error {
	return f.c.add("identity.EraseUser " + s.User.String())
}

func (f fakeIdentity) EraseTenant(_ context.Context, t principal.TenantID) error {
	return f.c.add("identity.EraseTenant " + t.String())
}

type fakeBackend struct {
	c *calls
}

func (b fakeBackend) OnCredentialRotated(_ context.Context, e lifecycle.CredentialRotated) error {
	return b.c.add("backend.OnCredentialRotated keep=" + e.Keep.String())
}

func (b fakeBackend) OnFactorsChanged(_ context.Context, e lifecycle.FactorsChanged) error {
	return b.c.add("backend.OnFactorsChanged keep=" + e.Keep.String())
}

func (b fakeBackend) OnIdentifierChanged(context.Context, lifecycle.IdentifierChanged) error {
	return b.c.add("backend.OnIdentifierChanged")
}

func (b fakeBackend) OnDisabled(context.Context, lifecycle.AccountEvent) error {
	return b.c.add("backend.OnDisabled")
}

func (b fakeBackend) OnEnabled(context.Context, lifecycle.AccountEvent) error {
	return b.c.add("backend.OnEnabled")
}

func (b fakeBackend) OnDeleted(context.Context, lifecycle.AccountEvent) error {
	return b.c.add("backend.OnDeleted")
}

func (b fakeBackend) OnTenantErased(context.Context, lifecycle.TenantErased) error {
	return b.c.add("backend.OnTenantErased")
}

func (b fakeBackend) OnSessionEnded(_ context.Context, e lifecycle.SessionEnded) error {
	return b.c.add("backend.OnSessionEnded " + e.Family.String())
}

type hookLog struct {
	c         *calls
	mu        sync.Mutex
	ids       []uuid.UUID
	inRequest []bool
}

func (h *hookLog) accountDeleted(ctx context.Context, id uuid.UUID, s principal.Subject) error {
	h.mu.Lock()
	h.ids = append(h.ids, id)
	h.inRequest = append(h.inRequest, principalctx.InRequest(ctx))
	h.mu.Unlock()
	return h.c.add("hooks.AccountDeleted " + s.User.String())
}

func (h *hookLog) tenantErased(_ context.Context, id uuid.UUID, t principal.TenantID) error {
	h.mu.Lock()
	h.ids = append(h.ids, id)
	h.mu.Unlock()
	return h.c.add("hooks.TenantErased " + t.String())
}

func (h *hookLog) sawRequest() []bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]bool(nil), h.inRequest...)
}

func (h *hookLog) deliveryIDs() []uuid.UUID {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]uuid.UUID(nil), h.ids...)
}

type retries struct {
	mu  sync.Mutex
	got []lifecycle.Retry
}

func (r *retries) ReportRetry(_ context.Context, x lifecycle.Retry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, x)
}

func (r *retries) all() []lifecycle.Retry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]lifecycle.Retry(nil), r.got...)
}

type fakeWorld struct {
	c       *calls
	labels  map[string]string
	hooks   *hookLog
	notices []identity.OutboxItem
	nmu     sync.Mutex
	wiring  lifecycle.Wiring
}

func (w *fakeWorld) SecurityNotice(_ context.Context, item identity.OutboxItem) error {
	w.nmu.Lock()
	w.notices = append(w.notices, item)
	w.nmu.Unlock()
	return w.c.add("notices.Send " + item.Event.String())
}

func newFakeWorld(t *testing.T, user identity.User) *fakeWorld {
	t.Helper()
	c := newCalls()
	w := &fakeWorld{c: c, labels: map[string]string{}, hooks: &hookLog{c: c}}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var err error
	w.wiring.Sessions, err = lifecycle.NewSessions(fakeBackend{c: c})
	must(err)
	w.wiring.APIKeys, err = lifecycle.NewAPIKeys(fakeTokens{c: c})
	must(err)
	w.wiring.Ceremonies, err = lifecycle.NewCeremonies(fakeCeremonies{c: c, labels: w.labels}, fakeAccounts{user: user}, fakeScoper{labels: w.labels})
	must(err)
	w.wiring.MFA, err = lifecycle.NewMFA(fakeMFA{c: c})
	must(err)
	w.wiring.Passkeys, err = lifecycle.NewPasskeys(fakePasskeys{c: c})
	must(err)
	w.wiring.Federation, err = lifecycle.NewFederation(fakeFederation{c: c})
	must(err)
	w.wiring.Notices, err = lifecycle.NewNotices(w)
	must(err)
	w.wiring.Keys, err = lifecycle.NewKeys(fakeKeys{c: c})
	must(err)
	w.wiring.Hooks = lifecycle.NewHooks(w.hooks.accountDeleted, w.hooks.tenantErased)
	w.wiring.Identity, err = lifecycle.NewIdentity(fakeIdentity{c: c})
	must(err)
	w.labels[string(ceremony.SubjectScope(user.Subject).Hash())] = "subject"
	return w
}

func principalSubject(t principal.TenantID) principal.Subject {
	return principal.Subject{Tenant: t, User: uuid.New()}
}

type memOutboxStub struct{}

func (*memOutboxStub) PendingOutbox(context.Context, int) ([]identity.OutboxItem, error) {
	return nil, nil
}
func (*memOutboxStub) AckOutbox(context.Context, int64) error { return nil }
func (*memOutboxStub) FailOutbox(context.Context, int64, time.Time) error {
	return nil
}
