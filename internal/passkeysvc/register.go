package passkeysvc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/passkey"
)

const (
	stateRegistration = "passkey_registration"
	stateRegistered   = "passkey_registered"
)

type challengeBody struct {
	State   string          `json:"state"`
	Options json.RawMessage `json:"options"`
	Handle  string          `json:"handle"`
	Bind    string          `json:"bind,omitempty"`
}

type registeredBody struct {
	State        string         `json:"state"`
	Credential   CredentialView `json:"credential"`
	SessionEnded bool           `json:"session_ended,omitempty"`
}

func (h *handlers) registerBegin(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	a, err := current(r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	sub := a.Subject()
	st, err := h.accounts.AccountState(ctx, sub)
	if err != nil {
		r.Fail(w, unavailable(err))
		return
	}
	if !st.Usable() {
		r.Fail(w, httpx.ErrUnauthenticated)
		return
	}
	p, err := h.issuer.Begin(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	if p, err = p.Bind(sub, st); err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	u, err := h.registrant(ctx, sub)
	if err != nil {
		r.Fail(w, unavailable(err))
		return
	}
	wa, err := h.relyingParty(sub.Tenant, ceremony.PasskeyRegistration)
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrUnauthenticated, err))
		return
	}
	creation, sd, err := wa.BeginRegistration(u,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: new(true),
			UserVerification:   protocol.VerificationRequired,
		}),
		webauthn.WithExtensions(webauthn.WithExtensionCredProps()),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
		webauthn.WithExclusions(webauthn.Credentials(u.creds).CredentialDescriptors()),
	)
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	handle, err := h.putSubjectCeremony(ctx, p, ceremony.PasskeyRegistration, ceremonycodec.PasskeyRegistration(), sd)
	if err != nil {
		r.Fail(w, unavailable(err))
		return
	}
	opts, err := json.Marshal(creation)
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	r.Respond(w, httpx.Response{Body: challengeBody{State: stateRegistration, Options: opts, Handle: handle.Encode()}})
}

func (s *Service) registrant(ctx context.Context, sub core.Subject) (*waUser, error) {
	creds, err := s.passkeys.List(ctx, sub)
	if err != nil {
		return nil, err
	}
	u := &waUser{sub: sub, name: sub.User.String(), display: sub.User.String()}
	for _, c := range creds {
		u.creds = append(u.creds, webauthn.Credential{ID: c.ID})
	}
	usr, err := s.identity.GetUser(ctx, sub)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return nil, err
	case !usr.Email.IsZero():
		u.name, u.display = usr.Email.Value(), usr.Email.Value()
	case !usr.Phone.IsZero():
		u.name, u.display = usr.Phone.Value(), usr.Phone.Value()
	}
	return u, nil
}

func (s *Service) putSubjectCeremony(ctx context.Context, p core.Pending, k ceremony.Kind, c ceremonycodec.Codec[ceremonycodec.WebAuthn], sd *webauthn.SessionData) (ceremonycodec.Handle, error) {
	sub, _ := p.Subject()
	session, err := sessionPayload(sd)
	if err != nil {
		return ceremonycodec.Handle{}, err
	}
	payload, err := c.Encode(session)
	if err != nil {
		return ceremonycodec.Handle{}, err
	}
	sealed, err := core.SealPending(p)
	if err != nil {
		return ceremonycodec.Handle{}, err
	}
	handle, err := ceremonycodec.NewHandle()
	if err != nil {
		return ceremonycodec.Handle{}, err
	}
	rec, err := ceremony.NewRecord(ceremony.Spec{
		Kind: k, HandleHash: handle.Hash(), Scope: ceremony.SubjectScope(sub), Pending: sealed, Payload: payload, Now: s.clock.Now(),
	}, openPending)
	if err != nil {
		return ceremonycodec.Handle{}, err
	}
	if _, err := s.ceremonies.Put(ctx, rec); err != nil {
		return ceremonycodec.Handle{}, err
	}
	return handle, nil
}

func openPending(sealed principal.Sealed) (ceremony.PendingBinding, error) {
	p, err := core.UnsealPending(sealed)
	if err != nil {
		return ceremony.PendingBinding{}, err
	}
	sub, _ := p.Subject()
	return ceremony.PendingBinding{Tenant: p.Tenant(), Subject: sub, ExpiresAt: p.ExpiresAt()}, nil
}

func (s *Service) consumeSubjectCeremony(ctx context.Context, t core.TenantID, k ceremony.Kind, rawHandle string, invalid error) (core.Pending, core.Subject, ceremonycodec.WebAuthn, error) {
	handle, err := ceremonycodec.ParseHandle(rawHandle)
	if err != nil {
		return core.Pending{}, core.Subject{}, ceremonycodec.WebAuthn{}, errors.Join(invalid, err)
	}
	rec, err := s.ceremonies.Consume(ctx, t, k, handle.Hash())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return core.Pending{}, core.Subject{}, ceremonycodec.WebAuthn{}, errors.Join(invalid, err)
	case err != nil:
		return core.Pending{}, core.Subject{}, ceremonycodec.WebAuthn{}, unavailable(err)
	}
	p, err := core.UnsealPending(rec.Pending)
	if err != nil {
		return core.Pending{}, core.Subject{}, ceremonycodec.WebAuthn{}, errors.Join(invalid, err)
	}
	sub, bound := p.Subject()
	if !bound || p.Tenant() != t || rec.Tenant() != t || sub.Tenant != t {
		return core.Pending{}, core.Subject{}, ceremonycodec.WebAuthn{}, invalid
	}
	codec := ceremonycodec.PasskeyRegistration()
	if k == ceremony.MFAPasskey {
		codec = ceremonycodec.MFAPasskey()
	}
	session, err := codec.Decode(rec.Payload())
	if err != nil {
		return core.Pending{}, core.Subject{}, ceremonycodec.WebAuthn{}, errors.Join(invalid, err)
	}
	return p, sub, session, nil
}

func (h *handlers) registerFinish(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	a, err := current(r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	sub := a.Subject()
	nickname, err := parseNickname(r.Field(routes.FieldNickname), true)
	if err != nil {
		r.Fail(w, err)
		return
	}
	c, err := h.verifyRegistration(ctx, r, sub, nickname)
	if err != nil {
		r.Fail(w, err)
		return
	}
	if _, err := h.passkeys.Get(ctx, sub.Tenant, c.ID); err == nil {
		r.Fail(w, ErrAlreadyRegistered)
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		r.Fail(w, unavailable(err))
		return
	}
	if _, err := h.mutations.Apply(ctx, identity.BumpEpoch{Subject: sub, Keep: a.Lineage(), Change: identity.FactorPasskeyAdded}); err != nil {
		r.Fail(w, unavailable(err))
		return
	}
	if err := h.passkeys.Save(ctx, c); err != nil {
		if errors.Is(err, store.ErrConflict) {
			r.Fail(w, errors.Join(ErrAlreadyRegistered, err))
			return
		}
		r.Fail(w, unavailable(err))
		return
	}
	_ = h.audit.Emit(ctx, event.CredentialAdded, scopeOf(sub), audit.Detail{}, nil, audit.A(event.KeyFactor, core.FactorPasskey.Code()))
	ended := h.issuer.Reissue(ctx, w, r, httpx.FactorEnrolledChange(core.FactorPasskeyStepUp)) != nil
	r.Respond(w, httpx.Response{Body: registeredBody{State: stateRegistered, Credential: View(c), SessionEnded: ended}})
}

func (s *Service) verifyRegistration(ctx context.Context, r *httpx.Request, sub core.Subject, nickname string) (passkey.Credential, error) {
	p, bound, session, err := s.consumeSubjectCeremony(ctx, sub.Tenant, ceremony.PasskeyRegistration, r.Field(routes.FieldHandle), ErrRegistrationFailed)
	if err != nil {
		return passkey.Credential{}, err
	}
	if bound != sub {
		return passkey.Credential{}, ErrRegistrationFailed
	}
	st, err := s.accounts.AccountState(ctx, sub)
	if err != nil {
		return passkey.Credential{}, unavailable(err)
	}
	if !st.Usable() || st.Epoch() != p.EpochAtBind() {
		return passkey.Credential{}, ErrRegistrationFailed
	}
	sd, err := sessionOf(session)
	if err != nil {
		return passkey.Credential{}, errors.Join(ErrRegistrationFailed, err)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(r.WebAuthnBody())
	if err != nil {
		return passkey.Credential{}, errors.Join(ErrRegistrationFailed, err)
	}
	wa, err := s.relyingParty(sub.Tenant, ceremony.PasskeyRegistration)
	if err != nil {
		return passkey.Credential{}, errors.Join(httpx.ErrUnauthenticated, err)
	}
	wc, err := wa.CreateCredential(&waUser{sub: sub}, sd, parsed)
	if err != nil {
		return passkey.Credential{}, errors.Join(ErrRegistrationFailed, err)
	}
	state, err := discoverability(parsed)
	if err != nil {
		return passkey.Credential{}, err
	}
	if len(wc.ID) == 0 || len(wc.ID) > passkey.MaxCredentialIDLen {
		return passkey.Credential{}, ErrRegistrationFailed
	}
	data, err := json.Marshal(wc)
	if err != nil {
		return passkey.Credential{}, errors.Join(httpx.ErrInternal, err)
	}
	var transports []string
	for _, t := range wc.Transport {
		transports = append(transports, string(t))
	}
	return passkey.Credential{
		Subject:        sub,
		ID:             wc.ID,
		PublicKey:      wc.PublicKey,
		SignCount:      wc.Authenticator.SignCount,
		Data:           data,
		CreatedAt:      s.clock.Now(),
		Nickname:       nickname,
		Transports:     transports,
		BackupEligible: wc.Flags.BackupEligible,
		BackupState:    wc.Flags.BackupState,
		Discoverable:   state,
	}, nil
}

func discoverability(parsed *protocol.ParsedCredentialCreationData) (passkey.DiscoverableState, error) {
	props := parsed.ClientExtensionResults.CredProps
	if props == nil || props.RK == nil {
		return passkey.Inferred, nil
	}
	if !*props.RK {
		return 0, ErrCannotStorePasskey
	}
	return passkey.Confirmed, nil
}
