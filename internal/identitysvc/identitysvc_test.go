package identitysvc_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/outbound"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/passwords"
	"github.com/JLugagne/egauth/passwords/breach"
)

func TestNewReportsEveryMissingDependency(t *testing.T) {
	_, err := identitysvc.New(identitysvc.Config{})
	if !errors.Is(err, identitysvc.ErrInvalidConfig) {
		t.Fatalf("New(zero) = %v, want ErrInvalidConfig", err)
	}
	for _, name := range []string{"Identity", "Ceremonies", "MFA", "Passkeys", "Hasher", "Policy", "Mailer", "Links", "Audit", "Cookies", "DataKey"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("New(zero) does not name %s: %v", name, err)
		}
	}
}

func TestNewRefusesANilHasherOrPolicy(t *testing.T) {
	for name, opt := range map[string]option{
		"Hasher": func(c *identitysvc.Config) { c.Hasher = nil },
		"Policy": func(c *identitysvc.Config) { c.Policy = nil },
		"Mailer": func(c *identitysvc.Config) { c.Mailer = nil },
	} {
		w := newWorld(t)
		cfg := identitysvc.Config{
			Identity: w.identity, Ceremonies: w.ceremonies, MFA: w.mfa, Passkeys: w.passkeys,
			Hasher: w.hasher, Policy: acceptAll{}, Mailer: w.mailer, Links: fakeLinks{}, Cookies: w.cookies,
			DataKey: testDataKey(1), Audit: noAudit(),
		}
		opt(&cfg)
		if _, err := identitysvc.New(cfg); !errors.Is(err, identitysvc.ErrInvalidConfig) || !strings.Contains(err.Error(), name) {
			t.Errorf("nil %s: New = %v", name, err)
		}
	}
}

type brokenHasher struct{ fakeHasher }

func (*brokenHasher) Hash(context.Context, string) (string, error) {
	return "", errors.New("hasher down")
}

func TestNewRefusesAHasherThatCannotHash(t *testing.T) {
	w := newWorld(t)
	_, err := identitysvc.New(identitysvc.Config{
		Identity: w.identity, Ceremonies: w.ceremonies, MFA: w.mfa, Passkeys: w.passkeys,
		Hasher: &brokenHasher{}, Policy: acceptAll{}, Mailer: w.mailer, Links: fakeLinks{}, Cookies: w.cookies,
		DataKey: testDataKey(1), Audit: noAudit(),
	})
	if !errors.Is(err, identitysvc.ErrInvalidConfig) {
		t.Fatalf("New = %v", err)
	}
}

func TestNewResolvesABreachSpecOnlyThroughOutbound(t *testing.T) {
	w := newWorld(t)
	base := func() identitysvc.Config {
		return identitysvc.Config{
			Identity: w.identity, Ceremonies: w.ceremonies, MFA: w.mfa, Passkeys: w.passkeys,
			Hasher: w.hasher, Policy: acceptAll{}, Mailer: w.mailer, Links: fakeLinks{}, Cookies: w.cookies,
			DataKey: testDataKey(1), Audit: noAudit(),
		}
	}
	cfg := base()
	cfg.Breach = breach.HIBP()
	if _, err := identitysvc.New(cfg); !errors.Is(err, identitysvc.ErrInvalidConfig) || !strings.Contains(err.Error(), "Outbound") {
		t.Fatalf("spec without outbound client: %v", err)
	}
	cfg.Breach = breach.Spec{}
	cfg.Outbound = outbound.New(outbound.Config{}).Static()
	if _, err := identitysvc.New(cfg); !errors.Is(err, identitysvc.ErrInvalidConfig) {
		t.Fatalf("zero spec: %v", err)
	}
	cfg.Breach = breach.HIBP()
	svc, err := identitysvc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = svc.AcceptPassword(ctx, goodPass)
	var p *httpx.Problem
	if !errors.As(err, &p) || p.Status() != http.StatusServiceUnavailable || !errors.Is(err, breach.ErrLookup) {
		t.Fatalf("a failed breach lookup must fail closed with 503 through the outbound client: %v", err)
	}
}

type countingPolicy struct{ seen []string }

func (p *countingPolicy) Verify(_ context.Context, pw string) error {
	p.seen = append(p.seen, pw)
	return nil
}

type alwaysBreached struct{}

func (alwaysBreached) IsBreached(context.Context, string) (bool, error) { return true, nil }

func TestAcceptPasswordAppliesTheFloorBeforePolicy(t *testing.T) {
	pol := &countingPolicy{}
	w := newWorld(t, func(c *identitysvc.Config) { c.Policy = pol })
	cases := map[string]string{
		"short":   "seven77",
		"long":    strings.Repeat("a", passwords.MaxPasswordLength+1),
		"invalid": "abcdefgh\xff",
	}
	for name, pw := range cases {
		if _, err := w.svc.AcceptPassword(context.Background(), pw); err == nil {
			t.Errorf("%s password accepted by an accept-all policy", name)
		}
	}
	if len(pol.seen) != 0 {
		t.Fatalf("policy ran on passwords the floor refused: %d calls", len(pol.seen))
	}
	phc, err := w.svc.AcceptPassword(context.Background(), "Ｃｏｒｒｅｃｔ horse")
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.seen) != 1 || pol.seen[0] != "Correct horse" || phc.PHC() != "$fake$Correct horse" {
		t.Fatalf("policy saw %q, stored %q; both must be the NFKC form", pol.seen, phc.PHC())
	}
}

func TestAcceptPasswordMapsRefusals(t *testing.T) {
	w := newWorld(t, func(c *identitysvc.Config) { c.Breach = alwaysBreached{} })
	_, err := w.svc.AcceptPassword(context.Background(), goodPass)
	if !errors.Is(err, identitysvc.ErrPasswordBreached) {
		t.Fatalf("breached: %v", err)
	}
	_, err = w.svc.AcceptPassword(context.Background(), "short")
	if !errors.Is(err, identitysvc.ErrPasswordTooShort) {
		t.Fatalf("short: %v", err)
	}
}

func TestEndpointsRefuseANilIssuer(t *testing.T) {
	w := newWorld(t)
	if _, err := w.svc.Endpoints(nil); !errors.Is(err, identitysvc.ErrNilIssuer) {
		t.Fatalf("Endpoints(nil) = %v", err)
	}
}

func TestEndpointsFollowTheRegistrationMode(t *testing.T) {
	paths := func(w *world) []string {
		eps, err := w.svc.Endpoints(w.issuer)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range eps {
			out = append(out, e.Path)
		}
		return out
	}
	open := paths(newWorld(t))
	want := []string{routes.Login, routes.PasswordForgot, routes.PasswordReset, routes.Register, routes.RegisterConfirm}
	if strings.Join(open, " ") != strings.Join(want, " ") {
		t.Fatalf("open registration = %v", open)
	}
	closed := newWorld(t, func(c *identitysvc.Config) { c.OpenRegistration = false })
	if got := paths(closed); strings.Join(got, " ") != strings.Join(want[:3], " ") {
		t.Fatalf("invite-only = %v", got)
	}
	rec := closed.do(req{path: routes.Register, fields: map[string]string{"identifier": "a@example.com", "password": goodPass}})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/register under invite-only = %d", rec.Code)
	}
}

func TestDeliveryFailuresAreReported(t *testing.T) {
	w := newWorld(t)
	w.mailer.err = errors.New("smtp down")
	rec := w.do(req{path: routes.Register, fields: map[string]string{"identifier": "new@example.com", "password": goodPass}})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d", rec.Code)
	}
	w.flush()
	if !w.sink.has("delivery.failed") {
		t.Fatalf("events = %v", w.sink.types())
	}
	rec = w.do(req{path: routes.Register, fields: map[string]string{"identifier": "late@example.com", "password": goodPass}})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("after Close: status %d", rec.Code)
	}
}

func TestNewResolvesABreachSpecPointer(t *testing.T) {
	w := newWorld(t)
	cfg := identitysvc.Config{
		Identity: w.identity, Ceremonies: w.ceremonies, MFA: w.mfa, Passkeys: w.passkeys,
		Hasher: w.hasher, Policy: acceptAll{}, Mailer: w.mailer, Links: fakeLinks{}, Cookies: w.cookies,
		DataKey: testDataKey(1), Audit: noAudit(),
	}
	spec := breach.HIBP()
	cfg.Breach = &spec
	if _, err := identitysvc.New(cfg); !errors.Is(err, identitysvc.ErrInvalidConfig) || !strings.Contains(err.Error(), "Outbound") {
		t.Fatalf("*breach.Spec without outbound client: %v", err)
	}
	cfg.Outbound = outbound.New(outbound.Config{}).Static()
	cfg.Breach = (*breach.Spec)(nil)
	if _, err := identitysvc.New(cfg); !errors.Is(err, identitysvc.ErrInvalidConfig) {
		t.Fatalf("nil *breach.Spec: %v", err)
	}
	cfg.Breach = &spec
	svc, err := identitysvc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.AcceptPassword(ctx, goodPass); errors.Is(err, breach.ErrUnresolved) || !errors.Is(err, breach.ErrLookup) {
		t.Fatalf("a *breach.Spec must be resolved through the outbound client: %v", err)
	}
}
