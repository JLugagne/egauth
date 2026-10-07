package ceremony_test

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/redirect"
	"github.com/JLugagne/egauth/store/ceremony"
)

func TestSessionAdmittingKindsLiveNoLongerThanPending(t *testing.T) {
	admitting := 0
	for _, k := range ceremony.All() {
		if !k.AdmitsSession() {
			continue
		}
		admitting++
		if k.TTL() > core.PendingTTL {
			t.Errorf("kind %s lives %s but its sealed Pending expires after %s", k, k.TTL(), core.PendingTTL)
		}
	}
	for _, k := range []ceremony.Kind{
		ceremony.MFAFlow, ceremony.MagicLink, ceremony.EmailCode, ceremony.SMSCode,
		ceremony.PendingRegistration, ceremony.Exchange, ceremony.DiscoverablePasskey,
		ceremony.UsernameFirstPasskey, ceremony.OAuthState, ceremony.ExternalLogin,
	} {
		if !k.AdmitsSession() {
			t.Errorf("kind %s admits a session but is not declared so", k)
		}
	}
	for _, k := range []ceremony.Kind{
		ceremony.PasswordReset, ceremony.PasswordResetCode, ceremony.SecurityRevert, ceremony.PasskeyRegistration,
	} {
		if k.AdmitsSession() {
			t.Errorf("kind %s must never admit a session", k)
		}
	}
	if admitting == 0 {
		t.Fatal("no session-admitting kind")
	}
}

var chainT0 = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func newChainPending(t *testing.T) (core.Pending, core.Subject) {
	t.Helper()
	tenant, err := core.ParseTenantID("tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	alice := core.Subject{Tenant: tenant, User: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")}
	o, err := redirect.NewOrigins("https://app.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := redirect.Parse("/after", o)
	if err != nil {
		t.Fatal(err)
	}
	p, err := core.NewPending(tenant, core.RememberDeclined, rt, core.TransportCookies, core.RememberUserChoice, chainT0)
	if err != nil {
		t.Fatal(err)
	}
	return p, alice
}

func TestPrimaryStepThenMFAFitsPending(t *testing.T) {
	chains := [][]ceremony.Kind{
		{ceremony.MagicLink, ceremony.MFAFlow},
		{ceremony.EmailCode, ceremony.MFAFlow},
		{ceremony.SMSCode, ceremony.MFAFlow},
		{ceremony.PendingRegistration, ceremony.MFAFlow},
		{ceremony.DiscoverablePasskey, ceremony.MFAFlow},
		{ceremony.UsernameFirstPasskey, ceremony.MFAFlow},
		{ceremony.ExternalLogin, ceremony.MFAFlow},
		{ceremony.OAuthState, ceremony.Exchange, ceremony.MFAFlow},
		{ceremony.ExternalLogin, ceremony.Exchange, ceremony.MFAFlow},
	}
	for _, chain := range chains {
		var total time.Duration
		for _, k := range chain {
			total += k.TTL()
		}
		if total > core.PendingTTL {
			t.Errorf("chain %v lasts %s, longer than the Pending (%s)", chain, total, core.PendingTTL)
		}
	}
}

func TestTOTPAcceptedWhileMFAFlowAfterLateMagicLinkIsLive(t *testing.T) {
	p, alice := newChainPending(t)
	link := ceremony.MagicLink.ExpiresAt(p.ExpiresAt(), chainT0)
	clicked := link.Add(-time.Minute)
	v, err := factors.EmailLink(alice, clicked)
	if err != nil {
		t.Fatal(err)
	}
	st := core.NewAccountState(true, false, false, false, true, 0)
	p, err = p.Add(v, st)
	if err != nil {
		t.Fatalf("magic link clicked while live refused: %v", err)
	}
	flowEnd := ceremony.MFAFlow.ExpiresAt(p.ExpiresAt(), clicked)
	if got := flowEnd.Sub(clicked); got != ceremony.MFAFlow.TTL() {
		t.Errorf("MFA flow after a late magic link lives %s, want its full %s", got, ceremony.MFAFlow.TTL())
	}
	entered := flowEnd.Add(-time.Second)
	v, err = factors.TOTP(alice, entered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Add(v, st); err != nil {
		t.Fatalf("TOTP entered while the MFAFlow record is live (%s after creation) refused: %v",
			entered.Sub(clicked), err)
	}
}

func TestNoAdmittingArtefactOutlivesItsPending(t *testing.T) {
	p, _ := newChainPending(t)
	for _, k := range ceremony.All() {
		if !k.AdmitsSession() {
			continue
		}
		for _, created := range []time.Time{chainT0, chainT0.Add(core.PendingTTL - time.Minute), chainT0.Add(core.PendingTTL)} {
			if end := k.ExpiresAt(p.ExpiresAt(), created); end.After(p.ExpiresAt()) {
				t.Errorf("kind %s created at +%s expires %s after its Pending", k, created.Sub(chainT0), end.Sub(p.ExpiresAt()))
			}
		}
	}
	flowStart := chainT0.Add(ceremony.MagicLink.TTL() - time.Second)
	passkeyStart := flowStart.Add(ceremony.MFAFlow.TTL() - time.Second)
	if end := ceremony.MFAPasskey.ExpiresAt(p.ExpiresAt(), passkeyStart); end.After(p.ExpiresAt()) {
		t.Fatalf("MFA passkey at the end of a magic link chain outlives its Pending by %s", end.Sub(p.ExpiresAt()))
	}
	notice := chainT0.Add(time.Hour)
	if got := ceremony.SecurityRevert.ExpiresAt(p.ExpiresAt(), notice); !got.Equal(notice.Add(ceremony.SecurityRevert.TTL())) {
		t.Fatalf("a non-admitting kind must keep its own lifetime, got %s", got.Sub(notice))
	}
	if !ceremony.Kind(0).ExpiresAt(p.ExpiresAt(), chainT0).IsZero() {
		t.Fatal("an invalid kind must expire at the zero time")
	}
	if !ceremony.MagicLink.ExpiresAt(time.Time{}, chainT0).IsZero() {
		t.Fatal("an admitting kind without a Pending must be born expired")
	}
}

func putRevert(rows map[string][]string, scope, link string) {
	rows[scope] = append(rows[scope], link)
	if over := len(rows[scope]) - ceremony.SecurityRevert.MaxLivePerScope(); over > 0 {
		rows[scope] = rows[scope][over:]
	}
}

func revertScope(subject, recipient string) string {
	switch ceremony.SecurityRevert.Scope() {
	case ceremony.Subject:
		return "subject:" + subject
	case ceremony.Identifier:
		return "identifier:" + recipient
	}
	return ""
}

func TestHijackerCannotEvictOwnersRevertLink(t *testing.T) {
	if ceremony.SecurityRevert.Scope() != ceremony.Identifier {
		t.Errorf("security revert must be scoped by the receiving address, got scope %d", ceremony.SecurityRevert.Scope())
	}
	if ceremony.SecurityRevert.MaxLivePerTenant() != 0 {
		t.Error("a tenant ceiling would let any address evict the owner's revert link")
	}
	rows := map[string][]string{}
	owner := revertScope("alice", "owner@example.com")
	putRevert(rows, owner, "email_changed")
	for range ceremony.SecurityRevert.MaxLivePerScope() + 5 {
		putRevert(rows, revertScope("alice", "attacker@example.com"), "factors_changed")
	}
	if !slices.Contains(rows[owner], "email_changed") {
		t.Fatal("factor changes notified to the hijacker's address evicted the owner's revert link (C-45)")
	}
}

func TestRegistrationLinkAcceptedForWholeRecordLifetime(t *testing.T) {
	p, alice := newChainPending(t)
	t0 := chainT0
	clicked := t0.Add(ceremony.PendingRegistration.TTL() - time.Second)
	v, err := factors.EmailLink(alice, clicked)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Add(v, core.NewAccountState(true, false, false, false, true, 0)); err != nil {
		t.Fatalf("registration link clicked while its record is live (%s of %s) refused: %v",
			clicked.Sub(t0), ceremony.PendingRegistration.TTL(), err)
	}
}

func TestKindValuesArePinned(t *testing.T) {
	want := map[ceremony.Kind]uint8{
		ceremony.MFAFlow: 1, ceremony.PasskeyRegistration: 2, ceremony.MFAPasskey: 3, ceremony.MagicLink: 4,
		ceremony.EmailCode: 5, ceremony.SMSCode: 6, ceremony.PhoneVerification: 7, ceremony.PasswordReset: 8,
		ceremony.PendingRegistration: 9, ceremony.EmailVerification: 10, ceremony.EmailChange: 11,
		ceremony.RecoveryEmail: 12, ceremony.SecurityRevert: 13, ceremony.Exchange: 14,
		ceremony.DiscoverablePasskey: 15, ceremony.UsernameFirstPasskey: 16, ceremony.OAuthState: 17,
		ceremony.ExternalLogin: 18, ceremony.PasswordResetCode: 19,
	}
	names := map[uint8]string{
		1: "mfa_flow", 2: "passkey_registration", 3: "mfa_passkey", 4: "magic_link", 5: "email_code",
		6: "sms_code", 7: "phone_verification", 8: "password_reset", 9: "pending_registration",
		10: "email_verification", 11: "email_change", 12: "recovery_email", 13: "security_revert",
		14: "exchange", 15: "discoverable_passkey", 16: "username_first_passkey", 17: "oauth_state",
		18: "external_login", 19: "password_reset_code",
	}
	for k, n := range want {
		if uint8(k) != n || k.String() != names[n] {
			t.Errorf("kind %s: persisted value %d, want %d (%s)", k, uint8(k), n, names[n])
		}
	}
	if len(ceremony.All()) != len(want) {
		t.Fatalf("want %d kinds, got %d", len(want), len(ceremony.All()))
	}
}

func TestKindsAreFullyDefined(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range ceremony.All() {
		if !k.Valid() || k.String() == "invalid" || seen[k.String()] {
			t.Fatalf("kind %d: bad or duplicate name %q", k, k.String())
		}
		seen[k.String()] = true
		if k.TTL() <= 0 || k.SecretClass() == 0 || k.Scope() == 0 {
			t.Fatalf("kind %s is missing a constant", k)
		}
		if k.Stateless() != (k.MaxAttempts() == 0) {
			t.Fatalf("kind %s: a stored kind needs an attempt bound and a stateless kind has no row to charge", k)
		}
		if k.Stateless() != (k.MaxLivePerScope() == 0) {
			t.Fatalf("kind %s: stateless and row cap disagree", k)
		}
	}
}

func TestInvalidKindFailsClosed(t *testing.T) {
	for _, k := range []ceremony.Kind{0, 20, 200} {
		if k.Valid() || k.TTL() != 0 || k.MaxLivePerScope() != 0 || k.MaxLivePerTenant() != 0 ||
			k.MaxAttempts() != 0 || k.SecretClass() != 0 || k.Scope() != 0 || k.AdmitsSession() ||
			k.Stateless() || k.String() != "invalid" {
			t.Fatalf("kind %d must fail closed", k)
		}
	}
}

func TestShortCodeKinds(t *testing.T) {
	want := map[ceremony.Kind]bool{
		ceremony.EmailCode: true, ceremony.SMSCode: true, ceremony.PhoneVerification: true,
		ceremony.PasswordResetCode: true,
	}
	for _, k := range ceremony.All() {
		if (k.SecretClass() == ceremony.ShortCode) != want[k] {
			t.Fatalf("kind %s: unexpected secret class", k)
		}
	}
}

func TestSMSPasswordResetHasItsOwnKind(t *testing.T) {
	k := ceremony.PasswordResetCode
	if k == ceremony.SMSCode || k == ceremony.EmailCode || k == ceremony.PasswordReset {
		t.Fatal("an SMS reset code must not share a sign-in or link kind")
	}
	if k.SecretClass() != ceremony.ShortCode || k.Scope() != ceremony.Subject || k.AdmitsSession() {
		t.Fatalf("kind %s: want a subject-scoped short code that never admits a session", k)
	}
	if _, ok := reflect.TypeFor[egauth.SMSDeliverer]().MethodByName("PasswordResetCode"); !ok {
		t.Fatal("SMS password reset must be deliverable (I-21)")
	}
}

func TestCodeKindsNameTheirFactor(t *testing.T) {
	if ceremony.EmailCode.String() != core.FactorEmailCode.Code() || ceremony.SMSCode.String() != core.FactorSMSCode.Code() {
		t.Fatal("a sign-in code kind must name the factor it yields")
	}
}

func TestStatelessKinds(t *testing.T) {
	want := map[ceremony.Kind]bool{
		ceremony.DiscoverablePasskey: true, ceremony.UsernameFirstPasskey: true,
		ceremony.OAuthState: true, ceremony.ExternalLogin: true,
	}
	for _, k := range ceremony.All() {
		if k.Stateless() != want[k] {
			t.Fatalf("kind %s: unexpected stateless flag", k)
		}
	}
}

func TestTenantCeilingOnlyOnIdentifierKinds(t *testing.T) {
	if c := ceremony.PendingRegistration.MaxLivePerTenant(); c <= ceremony.PendingRegistration.MaxLivePerScope() {
		t.Fatalf("pending registration needs a tenant ceiling above its scope cap, got %d", c)
	}
	for _, k := range ceremony.All() {
		c := k.MaxLivePerTenant()
		if c == 0 {
			continue
		}
		if k.Scope() != ceremony.Identifier {
			t.Errorf("kind %s: a %d-row tenant ceiling would let other scopes evict its rows", k, c)
		}
		if c < k.MaxLivePerScope() {
			t.Errorf("kind %s: tenant ceiling %d below scope cap %d", k, c, k.MaxLivePerScope())
		}
	}
}

func TestAttemptBoundOnlyWhereARecordIsCharged(t *testing.T) {
	charged := map[ceremony.Kind]bool{ceremony.MFAFlow: true, ceremony.MFAPasskey: true}
	for _, k := range ceremony.All() {
		if k.SecretClass() == ceremony.ShortCode {
			charged[k] = true
		}
	}
	for _, k := range ceremony.All() {
		switch {
		case k.Stateless():
			if k.MaxAttempts() != 0 {
				t.Errorf("stateless kind %s has no row to charge but reports %d attempts", k, k.MaxAttempts())
			}
		case charged[k]:
			if k.MaxAttempts() < 1 {
				t.Errorf("kind %s compares a secret against a found record and needs an attempt bound", k)
			}
		default:
			if k.MaxAttempts() < 1 || k.MaxAttempts() > ceremony.EmailCode.MaxAttempts() {
				t.Errorf("kind %s: fail-safe bound %d out of range", k, k.MaxAttempts())
			}
		}
	}
}
