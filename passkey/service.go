package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// ErrCredentialCloned is returned by FinishLogin when the authenticator's signature counter
// went backwards, which indicates a possibly cloned authenticator. The login is rejected.
var ErrCredentialCloned = errors.New("passkey: authenticator signature counter regressed (possible clone)")

// MinCookieKeyLength is the minimum length (in bytes) accepted for the ceremony-cookie HMAC
// key. The cookie is authenticated with HMAC-SHA-256, so a key shorter than the 32-byte hash
// output weakens the tag; NewService rejects anything shorter. Use a stable, random secret of
// at least this length.
const MinCookieKeyLength = 32

// ErrCookieKeyMissing is returned by NewService when Config.CookieKey is unset or shorter than
// MinCookieKeyLength. The ceremony cookie carries the WebAuthn challenge and the
// user-verification requirement, which the server treats as trusted state; without an
// authenticated cookie a client could forge them (e.g. downgrade user verification), so the key
// is required at construction.
var ErrCookieKeyMissing = errors.New("passkey: Config.CookieKey is required and must be at least 32 bytes")

// ErrChallengeStoreMissing is returned by NewService when no Config.ChallengeStore is provided
// and the insecure opt-out (Config.InsecureNoChallengeStore) was not set. The challenge store
// provides single-use, server-side replay protection for the ceremony; without it replay
// protection degrades to the cookie alone, which a captured raw Finish request can bypass. A
// secure passwordless/step-up deployment must wire a ChallengeStore.
var ErrChallengeStoreMissing = errors.New("passkey: a ChallengeStore is required for replay protection; set Config.ChallengeStore, or set Config.InsecureNoChallengeStore to knowingly accept cookie-only protection")

// Config configures the WebAuthn Relying Party.
type Config struct {
	// RPID is the Relying Party ID — the registrable domain, without scheme or port (e.g.
	// "example.com"). Credentials are scoped to it and cannot be used on other domains.
	RPID string
	// RPDisplayName is a human-friendly name shown by the authenticator (e.g. "Example Inc").
	RPDisplayName string
	// RPOrigins is the list of allowed origins (scheme + host[/+port]) the ceremony responses
	// must come from, e.g. ["https://example.com"].
	RPOrigins []string
	// UserVerification controls whether the authenticator must verify the user (PIN, biometric,
	// etc.) during registration and login — i.e. whether the User Verified (UV) flag is enforced.
	//
	// SECURE BY DEFAULT: the zero value now means protocol.VerificationRequired — any assertion
	// whose UV flag is unset is rejected at Finish. This is the correct default for passwordless
	// and step-up use cases. To deliberately relax it (e.g. a second-factor flow where the
	// password already authenticated the user), set it explicitly to
	// protocol.VerificationPreferred or protocol.VerificationDiscouraged. The chosen requirement
	// is propagated into the ceremony options and the SessionData, so go-webauthn enforces the UV
	// bit at FinishRegistration, FinishLogin and FinishDiscoverableLogin.
	UserVerification protocol.UserVerificationRequirement
	// CookieKey is the secret key used to HMAC-authenticate the short-lived ceremony cookie that
	// carries the WebAuthn challenge and the user-verification requirement between Begin and
	// Finish. It is REQUIRED and validated at construction (NewService fails fast with
	// ErrCookieKeyMissing if it is unset or shorter than MinCookieKeyLength), matching jwt.New's
	// fail-fast behavior. Use a stable, random secret of at least 32 bytes. The per-request
	// WithCookieKey HandlerOption can still override it for a specific handler, but a service-wide
	// key here is the recommended way to configure it once.
	CookieKey []byte
	// ChallengeStore enables server-side, single-use replay protection for the ceremony challenge
	// (SEC-05): the issued challenge is recorded on Begin and atomically consumed on Finish, so a
	// captured Finish request replayed within the cookie TTL is rejected. It is REQUIRED by
	// default: NewService fails with ErrChallengeStoreMissing if it is nil unless
	// InsecureNoChallengeStore is set. The per-request WithChallengeStore HandlerOption overrides
	// it for a specific handler.
	ChallengeStore ChallengeStore
	// InsecureNoChallengeStore is the explicit, greppable opt-out for callers who knowingly accept
	// cookie-only replay protection (no ChallengeStore). When true, NewService no longer requires
	// ChallengeStore. Do NOT set this for a passwordless/step-up deployment: a captured raw Finish
	// request can then be replayed within the cookie TTL.
	InsecureNoChallengeStore bool
	// Events is an optional security-event sink (see the event package). When set it receives a
	// LoginSucceeded event on each completed passkey login and an AccountBlocked event when a
	// regressed signature counter flags a possible cloned authenticator. A nil sink disables
	// emission.
	Events event.Sink
	// Attestation is the opt-in attestation policy (conveyance preference + AAGUID allow/deny +
	// optional MDS trust validation). Its zero value preserves today's behavior: no preference, no
	// filtering, no MDS. See AttestationConfig.
	Attestation AttestationConfig
}

// Service runs the WebAuthn registration and login ceremonies over a credential Store.
type Service struct {
	wa         *webauthn.WebAuthn
	store      Store
	events     event.Sink
	cookieKey  []byte
	challenges ChallengeStore
}

// ceremonyTimeout bounds how long an in-flight registration/login ceremony stays valid.
const ceremonyTimeout = 5 * time.Minute

// NewService builds a passkey Service for the given relying-party Config. It is SECURE BY
// DEFAULT and FAILS FAST on a misconfigured passwordless/step-up setup (mirroring jwt.New):
//
//   - A nil store is rejected immediately with ErrNilStore; the store is always required and
//     failing at construction is clearer than a nil-pointer panic on the first request.
//   - User verification defaults to protocol.VerificationRequired when Config.UserVerification
//     is the zero value, so a UV-cleared assertion is rejected at Finish unless the caller
//     explicitly relaxes it.
//   - A ceremony-cookie HMAC key is required: NewService returns ErrCookieKeyMissing if
//     Config.CookieKey is unset or shorter than MinCookieKeyLength.
//   - A ChallengeStore is required for single-use replay protection: NewService returns
//     ErrChallengeStoreMissing unless Config.ChallengeStore is set or the explicit opt-out
//     Config.InsecureNoChallengeStore is true.
//
// Ceremony timeouts are enforced server-side (the challenge expiry is written into the signed
// ceremony cookie and re-checked at Finish), so a captured/forged ceremony cannot be completed
// late.
func NewService(store Store, cfg Config) (*Service, error) {
	// Fail fast: a nil store is always a programming error.
	if store == nil {
		return nil, ErrNilStore
	}
	// Fail fast on an unusable security configuration before building anything.
	if len(cfg.CookieKey) < MinCookieKeyLength {
		return nil, ErrCookieKeyMissing
	}
	if cfg.ChallengeStore == nil && !cfg.InsecureNoChallengeStore {
		return nil, ErrChallengeStoreMissing
	}

	// Secure-by-default: an unset UserVerification means REQUIRED (reject UV-cleared assertions).
	// A caller wanting the weaker behavior sets VerificationPreferred/Discouraged explicitly.
	uv := cfg.UserVerification
	if uv == "" {
		uv = protocol.VerificationRequired
	}

	waCfg := &webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
		// AuthenticatorSelection.UserVerification drives the UV requirement that go-webauthn
		// copies into the registration/login ceremony options and the SessionData. At Finish,
		// shouldVerifyUser is derived from SessionData.UserVerification == VerificationRequired,
		// so wiring it here enforces the UV flag across register, login and discoverable login.
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: uv,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTimeout, TimeoutUVD: ceremonyTimeout},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTimeout, TimeoutUVD: ceremonyTimeout},
		},
		// Attestation policy passthrough. AttestationPreference and MDS are zero-safe ("" and nil),
		// so a caller who never touches Config.Attestation gets exactly the prior behavior.
		AttestationPreference: cfg.Attestation.ConveyancePreference,
		MDS:                   cfg.Attestation.MDS,
	}
	// Build Filtering ONLY when an AAGUID/backup rule is set; otherwise leave it nil so the
	// no-attestation-config path is byte-for-byte unchanged (go-webauthn skips
	// ValidateFilteredCredential when Filtering is nil).
	if len(cfg.Attestation.PermittedAAGUIDs) > 0 || len(cfg.Attestation.ProhibitedAAGUIDs) > 0 || cfg.Attestation.ProhibitBackupEligibility {
		waCfg.Filtering = &webauthn.FilteringConfig{
			PermittedAAGUIDs:          cfg.Attestation.PermittedAAGUIDs,
			ProhibitedAAGUIDs:         cfg.Attestation.ProhibitedAAGUIDs,
			ProhibitBackupEligibility: cfg.Attestation.ProhibitBackupEligibility,
		}
	}

	wa, err := webauthn.New(waCfg)
	if err != nil {
		return nil, err
	}
	return &Service{
		wa:         wa,
		store:      store,
		events:     cfg.Events,
		cookieKey:  cfg.CookieKey,
		challenges: cfg.ChallengeStore,
	}, nil
}

// BeginRegistration starts adding a passkey for the user, returning the creation options to
// hand to navigator.credentials.create() and the SessionData to carry to FinishRegistration.
func (s *Service) BeginRegistration(ctx context.Context, tenantID string, userID uuid.UUID, name, displayName string) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	u, err := s.loadUser(ctx, tenantID, userID, name, displayName)
	if err != nil {
		return nil, nil, err
	}
	// Exclude already-registered credentials so the same authenticator isn't enrolled twice.
	exclusions := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for _, c := range u.creds {
		exclusions = append(exclusions, c.Descriptor())
	}
	return s.wa.BeginRegistration(u, webauthn.WithExclusions(exclusions))
}

// FinishRegistration verifies the attestation response and persists the new credential.
func (s *Service) FinishRegistration(ctx context.Context, tenantID string, userID uuid.UUID, name, displayName string, session webauthn.SessionData, r *http.Request) (*Credential, error) {
	u, err := s.loadUser(ctx, tenantID, userID, name, displayName)
	if err != nil {
		return nil, err
	}
	cred, err := s.wa.FinishRegistration(u, session, r)
	if err != nil {
		// go-webauthn runs ValidateFilteredCredential when Config.Filtering is set and returns a
		// *protocol.Error with Type=="policy_restriction" when the authenticator is outside the
		// configured AAGUID allow/deny or backup-eligibility policy. Map that to
		// ErrAttestationRejected, emit a rejection event, and return BEFORE any SaveCredential so
		// nothing is stored.
		if isAttestationPolicyError(err) {
			s.emit(ctx, event.Event{Type: event.AccountBlocked, UserID: userID.String(), TenantID: tenantID, Reason: "passkey_attestation_rejected"})
			return nil, ErrAttestationRejected
		}
		return nil, err
	}
	stored, err := toStored(userID, cred)
	if err != nil {
		return nil, err
	}
	if err := s.store.SaveCredential(ctx, tenantID, stored); err != nil {
		return nil, err
	}
	return stored, nil
}

// BeginLogin starts a login ceremony for a user that has at least one passkey, returning the
// assertion options for navigator.credentials.get() and the SessionData.
func (s *Service) BeginLogin(ctx context.Context, tenantID string, userID uuid.UUID) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	u, err := s.loadUser(ctx, tenantID, userID, "", "")
	if err != nil {
		return nil, nil, err
	}
	if len(u.creds) == 0 {
		return nil, nil, ErrNoCredentials
	}
	return s.wa.BeginLogin(u)
}

// FinishLogin verifies the assertion response, updates the signature counter (rejecting a
// regressed counter as a possible clone) and returns the credential that was used.
func (s *Service) FinishLogin(ctx context.Context, tenantID string, userID uuid.UUID, session webauthn.SessionData, r *http.Request) (*Credential, error) {
	u, err := s.loadUser(ctx, tenantID, userID, "", "")
	if err != nil {
		return nil, err
	}
	cred, err := s.wa.FinishLogin(u, session, r)
	if err != nil {
		return nil, err
	}
	if cred.Authenticator.CloneWarning {
		s.emit(ctx, event.Event{Type: event.AccountBlocked, UserID: userID.String(), TenantID: tenantID, Reason: "passkey_clone_detected"})
		return nil, ErrCredentialCloned
	}
	stored, err := toStored(userID, cred)
	if err != nil {
		return nil, err
	}
	// Preserve the registration-time metadata the assertion response does not carry (nickname,
	// transports, created-at) and stamp LastUsedAt; UpdateCredential is a full-record replace.
	existing, err := s.findStoredCredential(ctx, tenantID, userID, stored.ID)
	if err != nil {
		return nil, err
	}
	if err := s.applyLoginMetadata(ctx, tenantID, existing, stored); err != nil {
		return nil, err
	}
	// amr=["hwk"] (hardware-key authenticator per RFC 8176) + method="passkey" for uniform
	// login.succeeded audit trail across all authentication paths (M9 SC-1).
	s.emit(ctx, event.Event{
		Type:     event.LoginSucceeded,
		UserID:   userID.String(),
		TenantID: tenantID,
		Attrs:    map[string]any{"amr": []string{"hwk"}, "method": "passkey"},
	})
	return stored, nil
}

// BeginDiscoverableLogin starts a usernameless ("discoverable credential" / resident-key) login
// ceremony. Unlike BeginLogin it needs no prior userID: the returned assertion options carry an
// empty allowCredentials list, so the authenticator offers whichever resident key the user picks
// and reveals the account via the credential's user handle at FinishDiscoverableLogin. It returns
// the assertion options for navigator.credentials.get() and the SessionData.
func (s *Service) BeginDiscoverableLogin() (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return s.wa.BeginDiscoverableLogin()
}

// FinishDiscoverableLogin verifies a usernameless assertion. It resolves the account from the
// credential's user handle (the account UUID egauth set as the WebAuthn ID), verifies the
// assertion against that account's credentials, updates the signature counter (rejecting a
// regressed counter as a possible clone) and returns the credential used together with the
// resolved user ID.
//
// In a multi-tenant deployment the user handle is globally unique but credential lookup is still
// tenant-scoped, so pass the tenantID the same way you would for the username-based flow —
// derive it from the request (host/subdomain) before calling.
func (s *Service) FinishDiscoverableLogin(ctx context.Context, tenantID string, session webauthn.SessionData, r *http.Request) (*Credential, uuid.UUID, error) {
	var resolvedID uuid.UUID
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		uid, err := uuid.FromBytes(userHandle)
		if err != nil {
			return nil, err
		}
		resolvedID = uid
		return s.loadUser(ctx, tenantID, uid, "", "")
	}

	cred, err := s.wa.FinishDiscoverableLogin(handler, session, r)
	if err != nil {
		return nil, uuid.Nil, err
	}
	if cred.Authenticator.CloneWarning {
		s.emit(ctx, event.Event{Type: event.AccountBlocked, UserID: resolvedID.String(), TenantID: tenantID, Reason: "passkey_clone_detected"})
		return nil, uuid.Nil, ErrCredentialCloned
	}
	stored, err := toStored(resolvedID, cred)
	if err != nil {
		return nil, uuid.Nil, err
	}
	// Preserve registration-time metadata and stamp LastUsedAt (full-record replace), same as the
	// username-based login path.
	existing, err := s.findStoredCredential(ctx, tenantID, resolvedID, stored.ID)
	if err != nil {
		return nil, uuid.Nil, err
	}
	if err := s.applyLoginMetadata(ctx, tenantID, existing, stored); err != nil {
		return nil, uuid.Nil, err
	}
	// amr=["hwk"] (hardware-key authenticator per RFC 8176) + method="passkey" for uniform
	// login.succeeded audit trail. Reason="passkey_discoverable" is kept alongside so consumers
	// can distinguish the usernameless flow from the username-based passkey flow.
	s.emit(ctx, event.Event{
		Type:     event.LoginSucceeded,
		UserID:   resolvedID.String(),
		TenantID: tenantID,
		Reason:   "passkey_discoverable",
		Attrs:    map[string]any{"amr": []string{"hwk"}, "method": "passkey"},
	})
	return stored, resolvedID, nil
}

// ListCredentials returns the user's registered credentials.
func (s *Service) ListCredentials(ctx context.Context, tenantID string, userID uuid.UUID) ([]*Credential, error) {
	return s.store.GetCredentials(ctx, tenantID, userID)
}

// DeleteCredential removes one of the user's credentials.
func (s *Service) DeleteCredential(ctx context.Context, tenantID string, userID uuid.UUID, credentialID []byte) error {
	return s.store.DeleteCredential(ctx, tenantID, userID, credentialID)
}

// loadUser builds the go-webauthn User adapter from the user's stored credentials.
func (s *Service) loadUser(ctx context.Context, tenantID string, userID uuid.UUID, name, displayName string) (*waUser, error) {
	stored, err := s.store.GetCredentials(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, sc := range stored {
		var c webauthn.Credential
		if err := json.Unmarshal(sc.Data, &c); err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return &waUser{id: userID, name: name, displayName: displayName, creds: creds}, nil
}

func toStored(userID uuid.UUID, cred *webauthn.Credential) (*Credential, error) {
	data, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	// Capture the management metadata carried by the ceremony response: transports (only present on
	// the attestation/registration response), and the BE/BS backup flags from the authenticator
	// data. The assertion (login) response carries no transports, so applyLoginMetadata preserves
	// the registration-time values across logins.
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	if len(transports) == 0 {
		transports = nil
	}
	return &Credential{
		UserID:         userID,
		ID:             cred.ID,
		PublicKey:      cred.PublicKey,
		SignCount:      cred.Authenticator.SignCount,
		Data:           data,
		CreatedAt:      time.Now().UTC(),
		Transports:     transports,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
	}, nil
}

// waUser adapts a egauth user to the go-webauthn User interface. The WebAuthn user handle is
// the account's UUID bytes (opaque, stable, not displayed).
type waUser struct {
	id          uuid.UUID
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.id[:] }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

var _ webauthn.User = (*waUser)(nil)

// emit sends a security event to the configured sink (a no-op when none is set).
func (s *Service) emit(ctx context.Context, e event.Event) { event.Emit(ctx, s.events, e) }

// AttestationConfig is the opt-in attestation policy for a passkey Service. Every field's zero
// value reproduces today's behavior: no conveyance preference, no AAGUID filtering, no MDS trust
// validation. Set it on Config.Attestation to enforce a stricter policy at FinishRegistration.
type AttestationConfig struct {
	// ConveyancePreference is the attestation conveyance preference flowed into the registration
	// ceremony options via webauthn.Config.AttestationPreference (e.g. protocol.PreferNoAttestation,
	// protocol.PreferDirectAttestation). The zero value ("") keeps go-webauthn's default.
	ConveyancePreference protocol.ConveyancePreference
	// PermittedAAGUIDs, when non-empty, restricts registration to authenticators whose AAGUID is in
	// the list (allow-list). Mutually exclusive with ProhibitedAAGUIDs.
	PermittedAAGUIDs []uuid.UUID
	// ProhibitedAAGUIDs, when non-empty, rejects registration from authenticators whose AAGUID is in
	// the list (deny-list). Mutually exclusive with PermittedAAGUIDs.
	ProhibitedAAGUIDs []uuid.UUID
	// ProhibitBackupEligibility, when true, rejects registration from backup-eligible (syncable)
	// authenticators.
	ProhibitBackupEligibility bool
	// MDS is an optional FIDO Metadata Service provider for attestation trust-anchor validation. When
	// set it is passed through to webauthn.Config.MDS. The zero value (nil) disables MDS validation.
	MDS metadata.Provider
}

// isAttestationPolicyError reports whether err is a go-webauthn attestation-filtering rejection.
// ValidateFilteredCredential surfaces a *protocol.Error whose Type is "policy_restriction" (a copy
// of protocol.ErrPolicyRestriction built via WithInfo), so matching on Type rather than pointer
// identity is the stable seam.
func isAttestationPolicyError(err error) bool {
	var protoErr *protocol.Error
	return errors.As(err, &protoErr) && protoErr.Type == "policy_restriction"
}

// findStoredCredential loads the user's stored credential whose ID matches credentialID, scoped to
// the tenant and user (so a caller cannot reach another user's/tenant's credential). It returns nil
// (no error) when the user has no matching credential.
func (s *Service) findStoredCredential(ctx context.Context, tenantID string, userID uuid.UUID, credentialID []byte) (*Credential, error) {
	creds, err := s.store.GetCredentials(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	for _, c := range creds {
		if bytes.Equal(c.ID, credentialID) {
			return c, nil
		}
	}
	return nil, nil
}

// applyLoginMetadata folds a successful login into the stored credential record and persists it.
// Because Store.UpdateCredential is a full-record replace on every backend, the assertion-derived
// record (stored) would otherwise blank the fields the assertion response does not carry. This
// copies forward from the existing record the non-assertion-carried fields (Nickname, Transports,
// CreatedAt, BackupEligible — BE never changes per spec), stamps LastUsedAt, and keeps the
// fresh SignCount and BackupState from the assertion.
func (s *Service) applyLoginMetadata(ctx context.Context, tenantID string, existing, stored *Credential) error {
	if existing != nil {
		stored.Nickname = existing.Nickname
		stored.Transports = existing.Transports
		stored.CreatedAt = existing.CreatedAt
		stored.BackupEligible = existing.BackupEligible
	}
	now := time.Now().UTC()
	stored.LastUsedAt = &now
	return s.store.UpdateCredential(ctx, tenantID, stored)
}

// RenameCredential sets the human-friendly nickname on one of the user's credentials. The lookup is
// tenant- and user-scoped (so a caller cannot rename another user's or tenant's credential); it
// returns ErrCredentialNotFound when no matching credential exists. The full existing record is
// re-supplied to UpdateCredential with only Nickname mutated, so transports/backup-flags/created-at
// are untouched (UpdateCredential is a full-record replace).
func (s *Service) RenameCredential(ctx context.Context, tenantID string, userID uuid.UUID, credentialID []byte, nickname string) error {
	existing, err := s.findStoredCredential(ctx, tenantID, userID, credentialID)
	if err != nil {
		return err
	}
	if existing == nil {
		return ErrCredentialNotFound
	}
	existing.Nickname = nickname
	return s.store.UpdateCredential(ctx, tenantID, existing)
}

// SignalAllAcceptedCredentials builds a WebAuthn L3 signalAllAcceptedCredentials report for the
// user: the full set of credential IDs still valid for (RPID, user handle). After a credential is
// deleted, the integrator relays this to the client so the authenticator prunes any stored
// credential no longer in the list. The user handle (userId) is the account UUID bytes, matching
// waUser.WebAuthnID().
func (s *Service) SignalAllAcceptedCredentials(ctx context.Context, tenantID string, userID uuid.UUID) (*protocol.SignalAllAcceptedCredentials, error) {
	creds, err := s.ListCredentials(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}
	ids := make([]protocol.URLEncodedBase64, 0, len(creds))
	for _, c := range creds {
		ids = append(ids, protocol.URLEncodedBase64(c.ID))
	}
	handle := userID
	return &protocol.SignalAllAcceptedCredentials{
		RPID:                     s.wa.Config.RPID,
		UserID:                   protocol.URLEncodedBase64(handle[:]),
		AllAcceptedCredentialIDs: ids,
	}, nil
}

// SignalUnknownCredential builds a WebAuthn L3 signalUnknownCredential report for a credential the
// RP no longer recognizes (revoked/deleted). The integrator relays it to the client so the
// authenticator removes that one credential.
func (s *Service) SignalUnknownCredential(credentialID []byte) *protocol.SignalUnknownCredential {
	return &protocol.SignalUnknownCredential{
		CredentialID: protocol.URLEncodedBase64(credentialID),
		RPID:         s.wa.Config.RPID,
	}
}
