package passkeysvc

import (
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/passkey"
)

var errNoOrigin = errors.New("passkeysvc: no trusted origin for the tenant")

func (s *Service) relyingParty(t core.TenantID, k ceremony.Kind) (*webauthn.WebAuthn, error) {
	origins := s.origins.For(t)
	if len(origins) == 0 {
		return nil, errNoOrigin
	}
	u, err := url.Parse(origins[0])
	if err != nil || u.Hostname() == "" {
		return nil, errors.Join(errNoOrigin, err)
	}
	ttl := k.TTL()
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: ttl, TimeoutUVD: ttl}
	return webauthn.New(&webauthn.Config{
		RPID:                  strings.ToLower(u.Hostname()),
		RPDisplayName:         s.displayName,
		RPOrigins:             origins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: new(true),
			UserVerification:   protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{Login: timeout, Registration: timeout},
	})
}

type waUser struct {
	sub     core.Subject
	name    string
	display string
	creds   []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return slices.Clone(u.sub.User[:]) }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.display }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func webauthnCredential(c passkey.Credential) (webauthn.Credential, error) {
	var wc webauthn.Credential
	if len(c.Data) > 0 {
		if err := json.Unmarshal(c.Data, &wc); err != nil {
			return webauthn.Credential{}, err
		}
	}
	if len(wc.ID) == 0 {
		wc.ID = slices.Clone(c.ID)
	}
	if len(wc.PublicKey) == 0 {
		wc.PublicKey = slices.Clone(c.PublicKey)
	}
	if !slices.Equal(wc.ID, c.ID) {
		return webauthn.Credential{}, errors.New("passkeysvc: stored credential data names another id")
	}
	wc.Authenticator.SignCount = c.SignCount
	wc.Authenticator.CloneWarning = false
	return wc, nil
}

func sessionPayload(sd *webauthn.SessionData) (ceremonycodec.WebAuthn, error) {
	if sd == nil {
		return ceremonycodec.WebAuthn{}, errors.New("passkeysvc: no session data")
	}
	cp := *sd
	cp.AllowedCredentialIDs = nil
	cp.Expires = cp.Expires.UTC().Truncate(time.Second)
	b, err := json.Marshal(cp)
	if err != nil {
		return ceremonycodec.WebAuthn{}, err
	}
	return ceremonycodec.WebAuthn{Session: b}, nil
}

func sessionOf(w ceremonycodec.WebAuthn) (webauthn.SessionData, error) {
	var sd webauthn.SessionData
	if err := json.Unmarshal(w.Session, &sd); err != nil {
		return webauthn.SessionData{}, err
	}
	return sd, nil
}
