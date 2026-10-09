package webauthntest_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/JLugagne/egauth/webauthntest"
)

const (
	origin = "https://auth.example.com"
	rpID   = "auth.example.com"
)

type user struct {
	id    uuid.UUID
	creds []webauthn.Credential
}

func (u *user) WebAuthnID() []byte                         { return u.id[:] }
func (u *user) WebAuthnName() string                       { return "alice@example.com" }
func (u *user) WebAuthnDisplayName() string                { return "Alice" }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func relyingParty(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  rpID,
		RPDisplayName:         "Example",
		RPOrigins:             []string{origin},
		AttestationPreference: protocol.PreferNoAttestation,
	})
	if err != nil {
		t.Fatal(err)
	}
	return wa
}

func selection(rk protocol.ResidentKeyRequirement, require *bool) protocol.AuthenticatorSelection {
	return protocol.AuthenticatorSelection{
		ResidentKey:        rk,
		RequireResidentKey: require,
		UserVerification:   protocol.VerificationRequired,
	}
}

func beginRegistration(t *testing.T, wa *webauthn.WebAuthn, u *user, sel protocol.AuthenticatorSelection) ([]byte, *webauthn.SessionData) {
	t.Helper()
	creation, session, err := wa.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(sel),
		webauthn.WithExtensions(webauthn.WithExtensionCredProps()),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(creation)
	if err != nil {
		t.Fatal(err)
	}
	return raw, session
}

func finishRegistration(t *testing.T, wa *webauthn.WebAuthn, u *user, session *webauthn.SessionData, body []byte) *protocol.ParsedCredentialCreationData {
	t.Helper()
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		t.Fatalf("parse registration: %v", err)
	}
	cred, err := wa.CreateCredential(u, *session, parsed)
	if err != nil {
		t.Fatalf("create credential: %v", err)
	}
	u.creds = append(u.creds, *cred)
	return parsed
}

func rkOf(p *protocol.ParsedCredentialCreationData) *bool {
	if p.ClientExtensionResults.CredProps == nil {
		return nil
	}
	return p.ClientExtensionResults.CredProps.RK
}

func discoverableOptions(t *testing.T, wa *webauthn.WebAuthn) ([]byte, *webauthn.SessionData) {
	t.Helper()
	assertion, session, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(assertion)
	if err != nil {
		t.Fatal(err)
	}
	return raw, session
}

func registered(t *testing.T, a *webauthntest.Authenticator, wa *webauthn.WebAuthn, u *user, sel protocol.AuthenticatorSelection) *protocol.ParsedCredentialCreationData {
	t.Helper()
	opts, session := beginRegistration(t, wa, u, sel)
	return finishRegistration(t, wa, u, session, a.Register(t, opts))
}

func TestRegisterHonoursRequiredResidentKey(t *testing.T) {
	wa := relyingParty(t)
	u := &user{id: uuid.New()}
	a := webauthntest.New(origin)
	parsed := registered(t, a, wa, u, selection(protocol.ResidentKeyRequirementRequired, new(true)))
	if rk := rkOf(parsed); rk == nil || !*rk {
		t.Fatalf("credProps.rk = %v, want true", rk)
	}
	creds := a.Credentials()
	if len(creds) != 1 || !creds[0].Resident || creds[0].RPID != rpID || !bytes.Equal(creds[0].UserHandle, u.id[:]) {
		t.Fatalf("credentials = %+v", creds)
	}
	opts, session := discoverableOptions(t, wa)
	body := a.DiscoverableLogin(t, opts)
	parsedLogin, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		t.Fatal(err)
	}
	if !parsedLogin.Response.AuthenticatorData.Flags.HasUserVerified() {
		t.Fatal("UV flag missing")
	}
	got, _, err := wa.ValidatePasskeyLogin(func(_, handle []byte) (webauthn.User, error) {
		if !bytes.Equal(handle, u.id[:]) {
			return nil, errors.New("unknown handle")
		}
		return u, nil
	}, *session, parsedLogin)
	if err != nil || got == nil {
		t.Fatalf("discoverable login: %v", err)
	}
}

func TestRequireResidentKeyAloneMeansRequired(t *testing.T) {
	wa := relyingParty(t)
	u := &user{id: uuid.New()}
	a := webauthntest.New(origin)
	parsed := registered(t, a, wa, u, selection("", new(true)))
	if rk := rkOf(parsed); rk == nil || !*rk {
		t.Fatalf("credProps.rk = %v, want true", rk)
	}
	if !a.Credentials()[0].Resident {
		t.Fatal("requireResidentKey true created a server-side credential")
	}
}

func TestG24DiscouragedResidentKeyBreaksDiscoverableLogin(t *testing.T) {
	wa := relyingParty(t)
	u := &user{id: uuid.New()}
	a := webauthntest.New(origin)
	parsed := registered(t, a, wa, u, selection(protocol.ResidentKeyRequirementDiscouraged, new(false)))
	if rk := rkOf(parsed); rk == nil || *rk {
		t.Fatalf("credProps.rk = %v, want false", rk)
	}
	opts, _ := discoverableOptions(t, wa)
	if _, err := a.Get(opts); !errors.Is(err, webauthntest.ErrNotAllowed) {
		t.Fatalf("discoverable get = %v, want ErrNotAllowed", err)
	}
	ft := &fakeT{}
	a.DiscoverableLogin(ft, opts)
	if !ft.failed {
		t.Fatal("DiscoverableLogin did not fail without a resident credential")
	}
}

func TestRequiredResidentKeyFailsWhenUnsupported(t *testing.T) {
	wa := relyingParty(t)
	u := &user{id: uuid.New()}
	a := webauthntest.New(origin)
	a.ResidentKeyUnsupported = true
	opts, _ := beginRegistration(t, wa, u, selection(protocol.ResidentKeyRequirementRequired, new(true)))
	if _, err := a.Create(opts); !errors.Is(err, webauthntest.ErrNotAllowed) {
		t.Fatalf("create = %v, want ErrNotAllowed", err)
	}
	if len(a.Credentials()) != 0 {
		t.Fatal("a failed create stored a credential")
	}
	optsPreferred, session := beginRegistration(t, wa, u, selection(protocol.ResidentKeyRequirementPreferred, nil))
	parsed := finishRegistration(t, wa, u, session, a.Register(t, optsPreferred))
	if rk := rkOf(parsed); rk == nil || *rk {
		t.Fatalf("preferred on a server-side-only authenticator: rk = %v, want false", rk)
	}
}

func TestCredPropsOmittedOnRequest(t *testing.T) {
	wa := relyingParty(t)
	u := &user{id: uuid.New()}
	a := webauthntest.New(origin)
	a.OmitCredProps = true
	parsed := registered(t, a, wa, u, selection(protocol.ResidentKeyRequirementRequired, new(true)))
	if parsed.ClientExtensionResults.CredProps != nil {
		t.Fatalf("credProps reported: %+v", parsed.ClientExtensionResults.CredProps)
	}
	if !a.Credentials()[0].Resident {
		t.Fatal("omitting the output changed residency")
	}
}

func TestClientRewritingResidentKeyReportsFalse(t *testing.T) {
	wa := relyingParty(t)
	u := &user{id: uuid.New()}
	a := webauthntest.New(origin)
	a.ClientResidentKey = "discouraged"
	parsed := registered(t, a, wa, u, selection(protocol.ResidentKeyRequirementRequired, new(true)))
	if rk := rkOf(parsed); rk == nil || *rk {
		t.Fatalf("credProps.rk = %v, want false", rk)
	}
	if a.Credentials()[0].Resident {
		t.Fatal("rewritten options still created a resident credential")
	}
}

func TestLoginWithAllowListAndCounters(t *testing.T) {
	wa := relyingParty(t)
	u := &user{id: uuid.New()}
	a := webauthntest.New(origin)
	registered(t, a, wa, u, selection(protocol.ResidentKeyRequirementDiscouraged, nil))
	login := func(auth *webauthntest.Authenticator) (*webauthn.Credential, error) {
		assertion, session, err := wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			t.Fatal(err)
		}
		opts, err := json.Marshal(assertion)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := protocol.ParseCredentialRequestResponseBytes(auth.Login(t, opts))
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Response.UserHandle != nil {
			t.Fatal("a server-side credential returned a user handle")
		}
		return wa.ValidateLogin(u, *session, parsed)
	}
	clone := a.Clone()
	first, err := login(a)
	if err != nil {
		t.Fatal(err)
	}
	if first.Authenticator.SignCount != 1 || first.Authenticator.CloneWarning {
		t.Fatalf("first login: count %d clone %v", first.Authenticator.SignCount, first.Authenticator.CloneWarning)
	}
	u.creds[0] = *first
	second, err := login(clone)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Authenticator.CloneWarning {
		t.Fatal("a cloned authenticator replaying counter 1 raised no clone warning")
	}
	if a.Credentials()[0].SignCount != 1 || clone.Credentials()[0].SignCount != 1 {
		t.Fatal("clone shares counters with the original")
	}
}

func TestCounterlessKeepsZero(t *testing.T) {
	wa := relyingParty(t)
	u := &user{id: uuid.New()}
	a := webauthntest.New(origin)
	a.Counterless = true
	registered(t, a, wa, u, selection(protocol.ResidentKeyRequirementRequired, new(true)))
	for range 2 {
		opts, session := discoverableOptions(t, wa)
		parsed, err := protocol.ParseCredentialRequestResponseBytes(a.DiscoverableLogin(t, opts))
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Response.AuthenticatorData.Counter != 0 {
			t.Fatalf("counter = %d", parsed.Response.AuthenticatorData.Counter)
		}
		if _, _, err := wa.ValidatePasskeyLogin(func(_, _ []byte) (webauthn.User, error) { return u, nil }, *session, parsed); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExcludedCredentialIsInvalidState(t *testing.T) {
	wa := relyingParty(t)
	u := &user{id: uuid.New()}
	a := webauthntest.New(origin)
	registered(t, a, wa, u, selection(protocol.ResidentKeyRequirementRequired, new(true)))
	creation, _, err := wa.BeginRegistration(u, webauthn.WithExclusions(webauthn.Credentials(u.creds).CredentialDescriptors()))
	if err != nil {
		t.Fatal(err)
	}
	opts, err := json.Marshal(creation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Create(opts); !errors.Is(err, webauthntest.ErrInvalidState) {
		t.Fatalf("create = %v, want ErrInvalidState", err)
	}
}

func TestRelyingPartyOutsideOriginIsSecurityError(t *testing.T) {
	wa, err := webauthn.New(&webauthn.Config{RPID: "other.org", RPDisplayName: "Other", RPOrigins: []string{"https://other.org"}})
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := beginRegistration(t, wa, &user{id: uuid.New()}, selection(protocol.ResidentKeyRequirementRequired, new(true)))
	if _, err := webauthntest.New(origin).Create(opts); !errors.Is(err, webauthntest.ErrSecurity) {
		t.Fatalf("create = %v, want ErrSecurity", err)
	}
}

func TestClientDroppingUserVerificationIsRefusedByTheRelyingParty(t *testing.T) {
	wa := relyingParty(t)
	u := &user{id: uuid.New()}
	a := webauthntest.New(origin)
	registered(t, a, wa, u, selection(protocol.ResidentKeyRequirementRequired, new(true)))
	a.ClientUserVerification = "discouraged"
	opts, session := discoverableOptions(t, wa)
	parsed, err := protocol.ParseCredentialRequestResponseBytes(a.DiscoverableLogin(t, opts))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		t.Fatal("UV performed although the client asked for none")
	}
	if _, _, err := wa.ValidatePasskeyLogin(func(_, _ []byte) (webauthn.User, error) { return u, nil }, *session, parsed); err == nil {
		t.Fatal("the relying party accepted an assertion without UV")
	}
}

func TestMalformedOptions(t *testing.T) {
	a := webauthntest.New(origin)
	for _, raw := range []string{``, `{}`, `{"publicKey":{"challenge":"***"}}`, `[1]`} {
		if _, err := a.Create([]byte(raw)); !errors.Is(err, webauthntest.ErrInvalidOptions) {
			t.Errorf("Create(%q) = %v", raw, err)
		}
		if _, err := a.Get([]byte(raw)); !errors.Is(err, webauthntest.ErrInvalidOptions) {
			t.Errorf("Get(%q) = %v", raw, err)
		}
	}
}

type fakeT struct {
	testing.TB
	failed bool
}

func (f *fakeT) Helper() {}

func (f *fakeT) Fatalf(string, ...any) { f.failed = true }
