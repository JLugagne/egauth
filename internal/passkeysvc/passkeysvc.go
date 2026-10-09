// Package passkeysvc owns the WebAuthn passkey factor (DESIGN §8, §4.3): registration, primary
// login (discoverable and username-first), the step-up ceremony the MFA flow drives, and credential
// management. Every ceremony requires user verification and every registration a discoverable
// credential; the factor of a verified assertion comes only from internal/factors with the flags of
// that assertion (P-03), and login ends in the single admission path, httpx.Issuer.Complete, whose
// Pending.Add enforces that the credential's owner is the subject bound at begin (P-02).
// Anonymous begins are stateless sealed handles (D3); the WebAuthn timeout of each ceremony is its
// ceremony.Kind TTL (P-09).
package passkeysvc

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"hash/maphash"
	"log/slog"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/clock"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/csrf"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/passkey"
)

const (
	redacted    = "REDACTED"
	decoyInfo   = "egauth/passkey-decoy/v1"
	decoyBytes  = 32
	lockStripes = 64
)

var (
	// ErrInvalidConfig is returned by New, joined with one error per missing or invalid member.
	ErrInvalidConfig = errors.New("passkeysvc: invalid service configuration")
	ErrNilIssuer     = errors.New("passkeysvc: nil issuer")
)

// The problems the passkey endpoints and the step-up ceremony answer besides those of httpx.
var (
	// ErrPasskeyRejected answers every failed login or step-up assertion alike: unknown, foreign,
	// suspended or cloned credential, bad signature, missing user verification, expired, replayed
	// or foreign-tenant handle.
	ErrPasskeyRejected = httpx.NewProblem(http.StatusUnauthorized, "passkey_rejected")
	// ErrUnboundCeremony answers a login finish without the browser-binding secret of its begin.
	ErrUnboundCeremony = httpx.NewProblem(http.StatusBadRequest, "unbound_ceremony")
	// ErrCannotStorePasskey answers a registration whose client reported credProps.rk false: the
	// credential is not discoverable and nothing is stored (P-11, C-16).
	ErrCannotStorePasskey  = httpx.NewProblem(http.StatusConflict, "authenticator_cannot_store_passkey")
	ErrRegistrationFailed  = httpx.NewProblem(http.StatusBadRequest, "passkey_registration_failed")
	ErrAlreadyRegistered   = httpx.NewProblem(http.StatusConflict, "passkey_already_registered")
	ErrCredentialNotFound  = httpx.NewProblem(http.StatusNotFound, "credential_not_found")
	ErrInvalidCredentialID = httpx.NewProblem(http.StatusBadRequest, "invalid_credential_id")
	ErrInvalidNickname     = httpx.NewProblem(http.StatusBadRequest, "invalid_nickname")
	ErrInvalidIdentifier   = httpx.NewProblem(http.StatusBadRequest, "invalid_identifier")
	// ErrNoPasskey answers a step-up for a subject without an active credential.
	ErrNoPasskey = httpx.NewProblem(http.StatusConflict, "no_passkey")
)

// Accounts answers the authoritative account state; identitysvc.Service satisfies it.
type Accounts interface {
	AccountState(ctx context.Context, sub core.Subject) (core.AccountState, error)
}

// Mutator is the shared mutation path of identitysvc.Service: Apply bumps the security epoch and
// writes the lifecycle outbox in one transaction, then dispatches it.
type Mutator interface {
	Apply(ctx context.Context, m identity.Mutation) (identity.Applied, error)
}

// Config is what New needs. Every member is required except Clock, whose zero value reads the wall
// clock.
type Config struct {
	Passkeys passkey.Store
	// MFA is read and pruned when a credential is deleted: recovery codes exist only while a
	// confirmed TOTP or an active passkey does (D1).
	MFA        mfa.Store
	Identity   identity.Store
	Accounts   Accounts
	Mutations  Mutator
	Ceremonies ceremony.Store
	// Origins are the trusted origins; the relying party id of a tenant is the host of its first
	// origin (the tenant-expanded public origin), and every origin of the tenant is accepted.
	Origins csrf.Origins
	Cookies cookie.Policy
	// DisplayName is the relying party name shown by authenticators (Modules.Passkey.DisplayName).
	DisplayName string
	// DataKey is the 32-byte deployment data key; only HKDF subkeys of it are kept.
	DataKey []byte
	Clock   clock.Clock
	Audit   httpx.Audit
}

func (c Config) String() string {
	return "passkeysvc.Config{DisplayName: " + strconv.Quote(c.DisplayName) + ", DataKey: " + redacted + "}"
}

func (c Config) GoString() string { return c.String() }

func (c Config) LogValue() slog.Value {
	return slog.GroupValue(slog.String("display_name", c.DisplayName), slog.String("data_key", redacted))
}

// Service is the passkey service, safe for concurrent use. Within one instance, the metadata
// read-modify-write of a credential (rename, last use) is serialized per credential; across
// instances the last Update wins.
type Service struct {
	passkeys    passkey.Store
	mfa         mfa.Store
	identity    identity.Store
	accounts    Accounts
	mutations   Mutator
	ceremonies  ceremony.Store
	origins     csrf.Origins
	cookies     cookie.Policy
	displayName string
	sealer      *ceremonycodec.Sealer
	decoyKey    []byte
	lockSeed    maphash.Seed
	locks       *[lockStripes]sync.Mutex
	clock       clock.Clock
	audit       httpx.Audit
}

// String renders s without its derived keys: the decoy key would tell fake username-first options
// from real ones.
func (s Service) String() string {
	return "passkeysvc.Service{DisplayName: " + strconv.Quote(s.displayName) + ", Keys: " + redacted + "}"
}

// GoString renders s for %#v without its derived keys.
func (s Service) GoString() string { return s.String() }

// LogValue renders s for slog without its derived keys.
func (s Service) LogValue() slog.Value {
	return slog.GroupValue(slog.String("display_name", s.displayName), slog.String("keys", redacted))
}

// New validates cfg and reports every problem at once as ErrInvalidConfig joined with the member
// names; a typed nil counts as missing.
func New(cfg Config) (*Service, error) {
	var errs []error
	need := func(ok bool, name string) {
		if !ok {
			errs = append(errs, errors.New(name))
		}
	}
	need(present(cfg.Passkeys), "Passkeys")
	need(present(cfg.MFA), "MFA")
	need(present(cfg.Identity), "Identity")
	need(present(cfg.Accounts), "Accounts")
	need(present(cfg.Mutations), "Mutations")
	need(present(cfg.Ceremonies), "Ceremonies")
	need(!cfg.Origins.IsZero(), "Origins")
	need(cfg.Cookies != (cookie.Policy{}), "Cookies")
	need(strings.TrimSpace(cfg.DisplayName) != "", "DisplayName")
	need(present(cfg.Audit), "Audit")
	sealer, err := ceremonycodec.NewSealer(cfg.DataKey, cfg.Clock)
	if err != nil {
		errs = append(errs, errors.Join(errors.New("DataKey"), err))
	}
	var decoyKey []byte
	if err == nil {
		if decoyKey, err = hkdf.Key(sha256.New, cfg.DataKey, nil, decoyInfo, decoyBytes); err != nil {
			errs = append(errs, errors.Join(errors.New("DataKey"), err))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(ErrInvalidConfig, errors.Join(errs...))
	}
	return &Service{
		passkeys:    cfg.Passkeys,
		mfa:         cfg.MFA,
		identity:    cfg.Identity,
		accounts:    cfg.Accounts,
		mutations:   cfg.Mutations,
		ceremonies:  cfg.Ceremonies,
		origins:     cfg.Origins,
		cookies:     cfg.Cookies,
		displayName: cfg.DisplayName,
		sealer:      sealer,
		decoyKey:    decoyKey,
		lockSeed:    maphash.MakeSeed(),
		locks:       new([lockStripes]sync.Mutex),
		clock:       cfg.Clock,
		audit:       cfg.Audit,
	}, nil
}

func present(v any) bool {
	if v == nil {
		return false
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return !rv.IsNil()
	}
	return true
}

// Endpoints returns the passkey endpoints served by s through issuer. It returns ErrNilIssuer or the
// error of routes.NewEndpoint. /mfa/passkey/* belong to the MFA flow, which drives BeginStepUp and
// FinishStepUp.
//
// A begin answers {state, options, handle} (plus bind for a Bearer login); options is the
// navigator.credentials JSON. A finish body is the PublicKeyCredential JSON with handle (and bind
// under Bearer, nickname at registration) beside its members.
//
// Their guarantees:
//   - /passkey/register/begin takes the subject from the session principal, never from the request
//     (P-01), and always asks for residentKey required, requireResidentKey true, userVerification
//     required and credProps, excluding the subject's credentials. /passkey/register/finish stores
//     the credential Confirmed when credProps.rk is true and Inferred when credProps is absent,
//     answers 409 authenticator_cannot_store_passkey when rk is false and then stores nothing; a
//     stored credential bumps the epoch (FactorPasskeyAdded) before it is saved and reissues the
//     session with pk_stepup enrolled, secondAt unchanged.
//   - /passkey/login/begin binds the browser and writes no row. Without identifier it is a
//     discoverable begin; with one it is username-first and the subject is bound in the sealed
//     Pending, while an unknown or unusable identifier gets options with HMAC(dataKey, tenant ‖
//     identifier)-derived credential ids, deterministic per identifier, and a decoy binding.
//   - /passkey/login/finish refuses a suspended credential, verifies the assertion with UV
//     required, marks the handle consumed, applies the conditional sign-count update and suspends
//     the credential on the clone signal (P-12), then hands factors.Passkey(flags) to
//     Issuer.Complete with the Pending sealed at begin (remember, return_to, transport).
//   - /passkey/credentials lists the §8 view, /passkey/credentials/rename and
//     /passkey/credentials/delete take its base64url credential_id (P-05); delete bumps the epoch
//     (FactorPasskeyRemoved), ending every session of the subject, and removes the recovery codes
//     when no confirmed TOTP and no active passkey remains (D1).
func (s *Service) Endpoints(issuer httpx.Issuer) ([]routes.Endpoint, error) {
	if issuer == nil {
		return nil, ErrNilIssuer
	}
	h := &handlers{Service: s, issuer: issuer}
	fns := []struct {
		path string
		f    httpx.EndpointFunc
	}{
		{routes.PasskeyRegisterBegin, h.registerBegin},
		{routes.PasskeyRegisterFinish, h.registerFinish},
		{routes.PasskeyLoginBegin, h.loginBegin},
		{routes.PasskeyLoginFinish, h.loginFinish},
		{routes.PasskeyCredentials, h.list},
		{routes.PasskeyCredentialsRename, h.rename},
		{routes.PasskeyCredentialsDelete, h.remove},
	}
	out := make([]routes.Endpoint, 0, len(fns))
	for _, e := range fns {
		ep, err := routes.NewEndpoint(e.path, e.f)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, nil
}

type handlers struct {
	*Service
	issuer httpx.Issuer
}

func (s *Service) lockCredential(id passkey.CredentialID) func() {
	m := &s.locks[maphash.Bytes(s.lockSeed, id)%lockStripes]
	m.Lock()
	return m.Unlock
}

func scopeOf(sub core.Subject) audit.Scope {
	return audit.Scope{TenantID: sub.Tenant.String(), UserID: sub.User.String()}
}

func unavailable(err error) error {
	return errors.Join(httpx.ErrServiceUnavailable, err)
}

func current(r *httpx.Request) (core.SessionAttrs, error) {
	res, ok := r.Session()
	if !ok {
		return core.SessionAttrs{}, httpx.ErrUnauthenticated
	}
	return res.Attrs(), nil
}
