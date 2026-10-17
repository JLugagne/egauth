package issuance

import (
	"context"
	"testing"
	"time"

	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/core"
)

func TestDetachedIsAnUnboundCookiePendingWithNoRememberIntent(t *testing.T) {
	tenant, err := core.ParseTenantID("acme")
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewTest(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	i := &Issuer{remember: core.RememberUserChoice, clock: clk.Clock()}

	p, err := i.Detached(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	if p.Tenant() != tenant || p.Bound() || p.RememberMe() || p.ReturnTo() != "" || p.Transport() != core.TransportCookies {
		t.Fatalf("pending = tenant %v bound %v remember %v returnTo %q transport %v", p.Tenant(), p.Bound(), p.RememberMe(), p.ReturnTo(), p.Transport())
	}
	if !p.ExpiresAt().After(clk.Now()) {
		t.Fatalf("expires at %v, not after %v", p.ExpiresAt(), clk.Now())
	}
}
