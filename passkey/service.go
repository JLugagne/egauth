package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// ErrCredentialCloned is returned by FinishLogin when the authenticator's signature counter
// went backwards, which indicates a possibly cloned authenticator. The login is rejected.
var ErrCredentialCloned = errors.New("passkey: authenticator signature counter regressed (possible clone)")

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
}

// Service runs the WebAuthn registration and login ceremonies over a credential Store.
type Service struct {
	wa    *webauthn.WebAuthn
	store Store
}

// ceremonyTimeout bounds how long an in-flight registration/login ceremony stays valid.
const ceremonyTimeout = 5 * time.Minute

// NewService builds a passkey Service for the given relying-party Config. Ceremony timeouts are
// enforced server-side (the challenge expiry is written into the signed ceremony cookie and
// re-checked at Finish), so a captured/forged ceremony cannot be completed late.
func NewService(store Store, cfg Config) (*Service, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTimeout, TimeoutUVD: ceremonyTimeout},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTimeout, TimeoutUVD: ceremonyTimeout},
		},
	})
	if err != nil {
		return nil, err
	}
	return &Service{wa: wa, store: store}, nil
}

// BeginRegistration starts adding a passkey for the user, returning the creation options to
// hand to navigator.credentials.create() and the SessionData to carry to FinishRegistration.
func (s *Service) BeginRegistration(ctx context.Context, userID uuid.UUID, name, displayName string, opts ...Option) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	u, err := s.loadUser(ctx, userID, name, displayName, opts...)
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
func (s *Service) FinishRegistration(ctx context.Context, userID uuid.UUID, name, displayName string, session webauthn.SessionData, r *http.Request, opts ...Option) (*Credential, error) {
	u, err := s.loadUser(ctx, userID, name, displayName, opts...)
	if err != nil {
		return nil, err
	}
	cred, err := s.wa.FinishRegistration(u, session, r)
	if err != nil {
		return nil, err
	}
	stored, err := toStored(userID, cred)
	if err != nil {
		return nil, err
	}
	if err := s.store.SaveCredential(ctx, stored, opts...); err != nil {
		return nil, err
	}
	return stored, nil
}

// BeginLogin starts a login ceremony for a user that has at least one passkey, returning the
// assertion options for navigator.credentials.get() and the SessionData.
func (s *Service) BeginLogin(ctx context.Context, userID uuid.UUID, opts ...Option) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	u, err := s.loadUser(ctx, userID, "", "", opts...)
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
func (s *Service) FinishLogin(ctx context.Context, userID uuid.UUID, session webauthn.SessionData, r *http.Request, opts ...Option) (*Credential, error) {
	u, err := s.loadUser(ctx, userID, "", "", opts...)
	if err != nil {
		return nil, err
	}
	cred, err := s.wa.FinishLogin(u, session, r)
	if err != nil {
		return nil, err
	}
	if cred.Authenticator.CloneWarning {
		return nil, ErrCredentialCloned
	}
	stored, err := toStored(userID, cred)
	if err != nil {
		return nil, err
	}
	if err := s.store.UpdateCredential(ctx, stored, opts...); err != nil {
		return nil, err
	}
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
// tenant-scoped, so pass the tenant (WithTenant) the same way you would for the username-based
// flow — derive it from the request (host/subdomain) before calling.
func (s *Service) FinishDiscoverableLogin(ctx context.Context, session webauthn.SessionData, r *http.Request, opts ...Option) (*Credential, uuid.UUID, error) {
	var resolvedID uuid.UUID
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		uid, err := uuid.FromBytes(userHandle)
		if err != nil {
			return nil, err
		}
		resolvedID = uid
		return s.loadUser(ctx, uid, "", "", opts...)
	}

	cred, err := s.wa.FinishDiscoverableLogin(handler, session, r)
	if err != nil {
		return nil, uuid.Nil, err
	}
	if cred.Authenticator.CloneWarning {
		return nil, uuid.Nil, ErrCredentialCloned
	}
	stored, err := toStored(resolvedID, cred)
	if err != nil {
		return nil, uuid.Nil, err
	}
	if err := s.store.UpdateCredential(ctx, stored, opts...); err != nil {
		return nil, uuid.Nil, err
	}
	return stored, resolvedID, nil
}

// ListCredentials returns the user's registered credentials.
func (s *Service) ListCredentials(ctx context.Context, userID uuid.UUID, opts ...Option) ([]*Credential, error) {
	return s.store.GetCredentials(ctx, userID, opts...)
}

// DeleteCredential removes one of the user's credentials.
func (s *Service) DeleteCredential(ctx context.Context, userID uuid.UUID, credentialID []byte, opts ...Option) error {
	return s.store.DeleteCredential(ctx, userID, credentialID, opts...)
}

// loadUser builds the go-webauthn User adapter from the user's stored credentials.
func (s *Service) loadUser(ctx context.Context, userID uuid.UUID, name, displayName string, opts ...Option) (*waUser, error) {
	stored, err := s.store.GetCredentials(ctx, userID, opts...)
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
	return &Credential{
		UserID:    userID,
		ID:        cred.ID,
		PublicKey: cred.PublicKey,
		SignCount: cred.Authenticator.SignCount,
		Data:      data,
		CreatedAt: time.Now().UTC(),
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
