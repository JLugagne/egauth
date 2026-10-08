package identitysvc_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/outbound"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/breach"
	"github.com/JLugagne/egauth/passwords/policy"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
	identitymem "github.com/JLugagne/egauth/store/identity/memory"
)

type gatedCeremonies struct {
	ceremony.Store
	gate chan struct{}
	puts atomic.Int64
}

func (c *gatedCeremonies) Put(ctx context.Context, r ceremony.Record) (int, error) {
	<-c.gate
	c.puts.Add(1)
	return c.Store.Put(ctx, r)
}

func TestForgotDoesNoCeremonyWorkOnTheRequestPath(t *testing.T) {
	gated := &gatedCeremonies{gate: make(chan struct{})}
	w := newWorld(t, func(c *identitysvc.Config) {
		gated.Store = c.Ceremonies
		c.Ceremonies = gated
	})
	w.createVerified("taken@example.com", goodPass)
	bodies := make(chan string, 2)
	go func() {
		bodies <- forgot(w, "taken@example.com").Body.String()
		bodies <- forgot(w, "fresh@example.com").Body.String()
	}()
	var got []string
	for range 2 {
		select {
		case b := <-bodies:
			got = append(got, b)
		case <-time.After(5 * time.Second):
			close(gated.gate)
			t.Fatal("/password/forgot waited for a ceremony write: an existing account answers slower than an unknown one (C-46)")
		}
	}
	if got[0] != got[1] {
		t.Fatalf("bodies differ: %q vs %q", got[0], got[1])
	}
	if n := gated.puts.Load(); n != 0 {
		t.Fatalf("ceremony writes before release = %d", n)
	}
	close(gated.gate)
	msgs := w.waitMail(1)
	if len(msgs) != 1 || msgs[0].to != "taken@example.com" || msgs[0].kind != "reset" || msgs[0].link == "" {
		t.Fatalf("deliveries = %+v", msgs)
	}
	if rec := reset(w, tokenOf(t, msgs[0].link), "a fresh new password"); rec.Code != http.StatusOK {
		t.Fatalf("the background link does not reset: %d %s", rec.Code, rec.Body.String())
	}
}

func TestForgotReportsABackgroundCeremonyFailure(t *testing.T) {
	cer := &countingCeremonies{putErr: errors.New("pool exhausted")}
	w := newWorld(t, func(c *identitysvc.Config) {
		cer.Store = c.Ceremonies
		c.Ceremonies = cer
	})
	w.createVerified("taken@example.com", goodPass)
	if rec := forgot(w, "taken@example.com"); rec.Code != http.StatusAccepted {
		t.Fatalf("status %d", rec.Code)
	}
	w.flush()
	if len(w.mailer.all()) != 0 || !w.sink.has("delivery.failed") {
		t.Fatalf("mails %v events %v", w.mailer.all(), w.sink.types())
	}
}

type chargingStore struct {
	identity.Store
	mu      sync.Mutex
	charges []core.Subject
}

func (s *chargingStore) RecordPasswordFailure(ctx context.Context, sub core.Subject, p identity.LockoutPolicy) (identity.Lockout, error) {
	s.mu.Lock()
	s.charges = append(s.charges, sub)
	s.mu.Unlock()
	return s.Store.RecordPasswordFailure(ctx, sub, p)
}

func (s *chargingStore) take() []core.Subject {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.charges
	s.charges = nil
	return out
}

func TestEveryLoginRefusalChargesOneLockoutWrite(t *testing.T) {
	var cs *chargingStore
	w := newWorldWrapping(t, func(s identity.Store) identity.Store {
		cs = &chargingStore{Store: s}
		return cs
	})
	ctx := context.Background()
	good := w.createVerified("good@example.com", goodPass)
	disabled := w.createVerified("disabled@example.com", goodPass)
	if _, err := w.identity.Apply(ctx, identity.SetDisabledState{Subject: disabled, Disable: true}); err != nil {
		t.Fatal(err)
	}
	w.createVerified("nopass@example.com", "")
	locked := w.createVerified("locked@example.com", goodPass)
	for range identitysvc.LockoutThreshold {
		if _, err := cs.Store.RecordPasswordFailure(ctx, locked, identity.LockoutPolicy{Threshold: identitysvc.LockoutThreshold, Window: identitysvc.LockoutWindow}); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		id, pw string
		real   core.Subject
	}{
		{"good@example.com", "wrong password", good},
		{"nobody@example.com", "wrong password", core.Subject{}},
		{"disabled@example.com", goodPass, core.Subject{}},
		{"nopass@example.com", goodPass, core.Subject{}},
		{"locked@example.com", goodPass, core.Subject{}},
	}
	for _, c := range cases {
		if code, _ := login(w, c.id, c.pw); code != http.StatusUnauthorized {
			t.Fatalf("%s: status %d", c.id, code)
		}
		got := cs.take()
		if len(got) != 1 {
			t.Fatalf("%s: %d lockout writes, want exactly 1 on every refusal (C-46)", c.id, len(got))
		}
		if !c.real.IsZero() && got[0] != c.real {
			t.Fatalf("%s: charged %v, want the account", c.id, got[0])
		}
		if c.real.IsZero() && (got[0] == good || got[0] == disabled || got[0] == locked) {
			t.Fatalf("%s: charged a real account %v", c.id, got[0])
		}
	}
}

func TestNewRefusesTypedNilMembers(t *testing.T) {
	w := newWorld(t)
	base := func() identitysvc.Config {
		return identitysvc.Config{
			Identity: w.identity, Ceremonies: w.ceremonies, MFA: w.mfa, Passkeys: w.passkeys,
			Hasher: w.hasher, Policy: acceptAll{}, Mailer: w.mailer, Links: fakeLinks{}, Cookies: w.cookies,
			DataKey: testDataKey(1), Audit: noAudit(),
		}
	}
	for name, opt := range map[string]func(*identitysvc.Config){
		"Policy":     func(c *identitysvc.Config) { c.Policy = (*policy.DefaultPolicy)(nil) },
		"Breach":     func(c *identitysvc.Config) { c.Breach = passwords.BreachCheckerFunc(nil) },
		"Identity":   func(c *identitysvc.Config) { c.Identity = (*identitymem.Store)(nil) },
		"Hasher":     func(c *identitysvc.Config) { c.Hasher = (*fakeHasher)(nil) },
		"Mailer":     func(c *identitysvc.Config) { c.Mailer = (*fakeMailer)(nil) },
		"Dispatcher": func(c *identitysvc.Config) { c.Dispatcher = (*nopDispatcher)(nil) },
	} {
		cfg := base()
		opt(&cfg)
		svc, err := identitysvc.New(cfg)
		if !errors.Is(err, identitysvc.ErrInvalidConfig) || !strings.Contains(err.Error(), name) {
			if svc != nil {
				_ = svc.Close()
			}
			t.Errorf("typed nil %s: New = %v, want ErrInvalidConfig naming it (I-25)", name, err)
		}
	}
}

type nopDispatcher struct{}

func (*nopDispatcher) DispatchOutbox(context.Context, []identity.OutboxItem) {}

type pathObserver struct {
	mu   sync.Mutex
	urls []string
}

func (o *pathObserver) OutboundStart(req *http.Request) func(*http.Response, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.urls = append(o.urls, req.URL.String())
	return nil
}

func TestBreachLookupGoesThroughTheSecretPathClient(t *testing.T) {
	w := newWorld(t)
	obs := &pathObserver{}
	svc, err := identitysvc.New(identitysvc.Config{
		Identity: w.identity, Ceremonies: w.ceremonies, MFA: w.mfa, Passkeys: w.passkeys,
		Hasher: w.hasher, Policy: acceptAll{}, Mailer: w.mailer, Links: fakeLinks{}, Cookies: w.cookies,
		DataKey: testDataKey(1), Audit: noAudit(),
		Breach: breach.HIBP(), Outbound: outbound.New(outbound.Config{Observer: obs}).Static(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.AcceptPassword(ctx, goodPass); !errors.Is(err, breach.ErrLookup) {
		t.Fatalf("AcceptPassword = %v", err)
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.urls) != 1 || obs.urls[0] != "https://api.pwnedpasswords.com" {
		t.Fatalf("observed %v: the hash prefix path must never reach the observer", obs.urls)
	}
}
