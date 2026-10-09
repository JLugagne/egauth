package passkeysvc

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/cookie"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/identitysvc"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/passkey"
)

const (
	stateChallenge = "passkey_challenge"
	decoyIDInfo    = "egauth/passkey-decoy-id/"
	maxDecoys      = 3
	bindBytes      = 32
)

var (
	decoyCounts     = [...]int{1, 1, 1, 1, 2, 2, 2, maxDecoys}
	decoyIDLengths  = [...]int{16, 16, 20, 32, 32, 32, 48, 64}
	decoyTransports = [...][]protocol.AuthenticatorTransport{
		{protocol.Hybrid, protocol.Internal},
		{protocol.Hybrid, protocol.Internal},
		{protocol.Internal},
		{protocol.Hybrid},
		{protocol.NFC, protocol.USB},
		{protocol.USB},
		{protocol.BLE, protocol.NFC, protocol.USB},
		nil,
	}
)

func (h *handlers) loginBegin(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	p, err := h.issuer.Begin(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	hash, minted, err := h.bindFor(r, p)
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	if p, err = p.WithBindHash(hash); err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	var (
		opts   []byte
		issued ceremonycodec.Issued
		kind   ceremony.Kind
	)
	if r.Has(routes.FieldIdentifier) {
		kind = ceremony.UsernameFirstPasskey
		opts, issued, err = h.beginUsernameFirst(ctx, p, r.Field(routes.FieldIdentifier))
	} else {
		kind = ceremony.DiscoverablePasskey
		opts, issued, err = h.beginDiscoverable(p)
	}
	if err != nil {
		r.Fail(w, err)
		return
	}
	body := challengeBody{State: stateChallenge, Options: opts, Handle: issued.Handle}
	switch {
	case p.Transport() == core.TransportBearer:
		body.Bind = minted.Value()
	case minted.Value() != "":
		if err := h.cookies.SetBind(w, minted, kind); err != nil {
			r.Fail(w, errors.Join(httpx.ErrInternal, err))
			return
		}
	}
	r.RespondPending(w, p, httpx.Response{Body: body})
}

func (s *Service) bindFor(r *httpx.Request, p core.Pending) ([]byte, cookie.BindSecret, error) {
	if p.Transport() == core.TransportCookies {
		if v, ok := s.cookies.Read(r.HTTP(), cookie.Bind); ok && mintedShape(v) {
			sum := sha256.Sum256([]byte(v))
			return sum[:], cookie.BindSecret{}, nil
		}
	}
	b, err := cookie.NewBind()
	if err != nil {
		return nil, cookie.BindSecret{}, err
	}
	return b.Hash(), b, nil
}

func mintedShape(v string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(raw) == bindBytes && base64.RawURLEncoding.EncodeToString(raw) == v
}

func (s *Service) beginDiscoverable(p core.Pending) ([]byte, ceremonycodec.Issued, error) {
	wa, err := s.relyingParty(p.Tenant(), ceremony.DiscoverablePasskey)
	if err != nil {
		return nil, ceremonycodec.Issued{}, errors.Join(httpx.ErrUnauthenticated, err)
	}
	assertion, sd, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, ceremonycodec.Issued{}, errors.Join(httpx.ErrInternal, err)
	}
	return seal(ceremonycodec.DiscoverablePasskey(), s.sealer, p, assertion, sd)
}

func seal(c ceremonycodec.Codec[ceremonycodec.WebAuthn], sealer *ceremonycodec.Sealer, p core.Pending, assertion *protocol.CredentialAssertion, sd *webauthn.SessionData) ([]byte, ceremonycodec.Issued, error) {
	session, err := sessionPayload(sd)
	if err != nil {
		return nil, ceremonycodec.Issued{}, errors.Join(httpx.ErrInternal, err)
	}
	issued, err := c.Seal(sealer, p, session)
	if err != nil {
		return nil, ceremonycodec.Issued{}, errors.Join(httpx.ErrInternal, err)
	}
	opts, err := json.Marshal(assertion)
	if err != nil {
		return nil, ceremonycodec.Issued{}, errors.Join(httpx.ErrInternal, err)
	}
	return opts, issued, nil
}

func (s *Service) beginUsernameFirst(ctx context.Context, p core.Pending, raw string) ([]byte, ceremonycodec.Issued, error) {
	id, err := identitysvc.Normalize(raw)
	if err != nil {
		return nil, ceremonycodec.Issued{}, errors.Join(ErrInvalidIdentifier, err)
	}
	u, st, err := s.loginCandidate(ctx, p.Tenant(), id)
	if err != nil {
		return nil, ceremonycodec.Issued{}, unavailable(err)
	}
	if p, err = p.Bind(u.sub, st); err != nil {
		return nil, ceremonycodec.Issued{}, errors.Join(httpx.ErrInternal, err)
	}
	wa, err := s.relyingParty(p.Tenant(), ceremony.UsernameFirstPasskey)
	if err != nil {
		return nil, ceremonycodec.Issued{}, errors.Join(httpx.ErrUnauthenticated, err)
	}
	assertion, sd, err := wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, ceremonycodec.Issued{}, errors.Join(httpx.ErrInternal, err)
	}
	return seal(ceremonycodec.UsernameFirstPasskey(), s.sealer, p, assertion, sd)
}

func (s *Service) loginCandidate(ctx context.Context, t core.TenantID, id identity.Identifier) (*waUser, core.AccountState, error) {
	fake := s.decoy(t, id)
	u, err := s.identity.FindUser(ctx, t, id)
	found := err == nil
	if !found && !errors.Is(err, store.ErrNotFound) {
		return nil, core.AccountState{}, err
	}
	sub := fake.sub
	if found {
		sub = u.Subject
	}
	st, stErr := s.accounts.AccountState(ctx, sub)
	creds, listErr := s.passkeys.List(ctx, sub)
	if err := errors.Join(stErr, listErr); err != nil {
		return nil, core.AccountState{}, err
	}
	if !found || !loginAllowed(u, id) || !st.Usable() || !st.EmailVerified() {
		return fake, core.AccountState{}, nil
	}
	wu := &waUser{sub: u.Subject}
	for _, c := range creds {
		if !c.Active() {
			continue
		}
		wc, err := webauthnCredential(c)
		if err != nil {
			continue
		}
		wu.creds = append(wu.creds, wc)
	}
	if len(wu.creds) == 0 {
		return fake, core.AccountState{}, nil
	}
	return wu, st, nil
}

func loginAllowed(u identity.User, id identity.Identifier) bool {
	if !u.DisabledAt.IsZero() || !u.DeletedAt.IsZero() || u.EmailVerifiedAt.IsZero() {
		return false
	}
	switch id.Kind() {
	case identity.IdentifierEmail:
		return u.Email == id
	case identity.IdentifierPhone:
		return u.Phone == id && !u.PhoneVerifiedAt.IsZero()
	}
	return false
}

func (s *Service) decoy(t core.TenantID, id identity.Identifier) *waUser {
	mac := hmac.New(sha256.New, s.decoyKey)
	tenant := t.String()
	mac.Write([]byte{byte(len(tenant))})
	mac.Write([]byte(tenant))
	mac.Write([]byte{byte(id.Kind())})
	mac.Write([]byte(id.Value()))
	seed := mac.Sum(nil)
	user, _ := uuid.FromBytes(seed[:16])
	user[6] = (user[6] & 0x0f) | 0x40
	user[8] = (user[8] & 0x3f) | 0x80
	u := &waUser{sub: core.Subject{Tenant: t, User: user}}
	n := decoyCounts[int(seed[16])%len(decoyCounts)]
	for i := range n {
		size := decoyIDLengths[int(seed[17+i])%len(decoyIDLengths)]
		cid, err := hkdf.Expand(sha256.New, seed, decoyIDInfo+strconv.Itoa(i), size)
		if err != nil {
			continue
		}
		u.creds = append(u.creds, webauthn.Credential{ID: cid, Transport: decoyTransports[int(seed[17+maxDecoys+i])%len(decoyTransports)]})
	}
	return u
}

type opened struct {
	kind       ceremony.Kind
	pending    core.Pending
	session    webauthn.SessionData
	handleHash []byte
	expiresAt  time.Time
}

func (s *Service) openLogin(t core.TenantID, handle string) (opened, error) {
	kind := ceremony.DiscoverablePasskey
	o, err := ceremonycodec.DiscoverablePasskey().Open(s.sealer, t, handle)
	if errors.Is(err, ceremonycodec.ErrWrongKind) {
		kind = ceremony.UsernameFirstPasskey
		o, err = ceremonycodec.UsernameFirstPasskey().Open(s.sealer, t, handle)
	}
	if err != nil {
		return opened{}, errors.Join(ErrPasskeyRejected, err)
	}
	sd, err := sessionOf(o.Payload)
	if err != nil {
		return opened{}, errors.Join(ErrPasskeyRejected, err)
	}
	return opened{kind: kind, pending: o.Pending, session: sd, handleHash: o.HandleHash, expiresAt: o.ExpiresAt}, nil
}

func (s *Service) presentedBind(r *httpx.Request, p core.Pending) bool {
	var presented string
	if p.Transport() == core.TransportBearer {
		presented = r.Field(routes.FieldBind)
	} else {
		presented, _ = s.cookies.Read(r.HTTP(), cookie.Bind)
	}
	return cookie.VerifyBind(presented, p.BindHash())
}

func (h *handlers) loginFinish(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	t := r.Tenant()
	o, err := h.openLogin(t, r.Field(routes.FieldHandle))
	if err != nil {
		h.loginFailed(ctx, t, err)
		r.Fail(w, err)
		return
	}
	if !h.presentedBind(r, o.pending) {
		r.Fail(w, ErrUnboundCeremony)
		return
	}
	v, err := h.verifyLogin(ctx, t, o, r.WebAuthnBody())
	if err != nil {
		h.loginFailed(ctx, t, err)
		r.Fail(w, err)
		return
	}
	resp, err := h.issuer.Complete(ctx, w, r, o.pending, v)
	if err != nil {
		r.Fail(w, err)
		return
	}
	r.RespondPending(w, o.pending, resp)
}

func (s *Service) loginFailed(ctx context.Context, t core.TenantID, err error) {
	if !errors.Is(err, ErrPasskeyRejected) {
		return
	}
	_ = s.audit.Emit(ctx, event.LoginFailed, audit.Scope{TenantID: t.String()},
		audit.Detail{Reason: ErrPasskeyRejected.Code()}, nil, audit.A(event.KeyMethod, core.FactorPasskey.Code()))
}

func (s *Service) verifyLogin(ctx context.Context, t core.TenantID, o opened, body []byte) (core.Verified, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return core.Verified{}, errors.Join(ErrPasskeyRejected, err)
	}
	cred, wc, err := s.activeCredential(ctx, t, parsed.RawID)
	if err != nil {
		return core.Verified{}, err
	}
	wa, err := s.relyingParty(t, o.kind)
	if err != nil {
		return core.Verified{}, errors.Join(ErrPasskeyRejected, err)
	}
	u := &waUser{sub: cred.Subject, creds: []webauthn.Credential{wc}}
	if o.kind == ceremony.DiscoverablePasskey {
		_, _, err = wa.ValidatePasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
			if !bytes.Equal(rawID, cred.ID) || !bytes.Equal(userHandle, cred.Subject.User[:]) {
				return nil, errors.New("passkeysvc: user handle is not the credential owner")
			}
			return u, nil
		}, o.session, parsed)
	} else {
		if bound, ok := o.pending.Subject(); !ok || bound != cred.Subject {
			return core.Verified{}, ErrPasskeyRejected
		}
		_, err = wa.ValidateLogin(u, o.session, parsed)
	}
	if err != nil {
		return core.Verified{}, errors.Join(ErrPasskeyRejected, err)
	}
	first, err := s.ceremonies.MarkConsumed(ctx, t, o.kind, o.handleHash, o.expiresAt)
	if err != nil {
		return core.Verified{}, unavailable(err)
	}
	if !first {
		return core.Verified{}, ErrPasskeyRejected
	}
	if err := s.recordUse(ctx, cred, parsed); err != nil {
		return core.Verified{}, err
	}
	st, err := s.accounts.AccountState(ctx, cred.Subject)
	if err != nil {
		return core.Verified{}, unavailable(err)
	}
	if !st.Usable() || !st.EmailVerified() {
		return core.Verified{}, ErrPasskeyRejected
	}
	v, err := factors.Passkey(factorCredential(cred), flagsOf(parsed), s.clock.Now())
	if err != nil {
		return core.Verified{}, errors.Join(ErrPasskeyRejected, err)
	}
	return v, nil
}

func (s *Service) activeCredential(ctx context.Context, t core.TenantID, rawID []byte) (passkey.Credential, webauthn.Credential, error) {
	if len(rawID) == 0 || len(rawID) > passkey.MaxCredentialIDLen {
		return passkey.Credential{}, webauthn.Credential{}, ErrPasskeyRejected
	}
	cred, err := s.passkeys.Get(ctx, t, rawID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return passkey.Credential{}, webauthn.Credential{}, errors.Join(ErrPasskeyRejected, err)
	case err != nil:
		return passkey.Credential{}, webauthn.Credential{}, unavailable(err)
	}
	if !cred.Active() || cred.Subject.Tenant != t {
		return passkey.Credential{}, webauthn.Credential{}, ErrPasskeyRejected
	}
	wc, err := webauthnCredential(cred)
	if err != nil {
		return passkey.Credential{}, webauthn.Credential{}, errors.Join(ErrPasskeyRejected, err)
	}
	return cred, wc, nil
}

func (s *Service) recordUse(ctx context.Context, cred passkey.Credential, parsed *protocol.ParsedCredentialAssertionData) error {
	defer s.lockCredential(cred.ID)()
	ok, err := s.passkeys.UpdateSignCount(ctx, cred.Subject, cred.ID, parsed.Response.AuthenticatorData.Counter)
	if err != nil {
		return unavailable(err)
	}
	now := s.clock.Now()
	if !ok {
		if err := s.passkeys.Suspend(ctx, cred.Subject, cred.ID, now); err != nil {
			return unavailable(err)
		}
		_ = s.audit.Emit(ctx, event.AccountBlocked, scopeOf(cred.Subject), audit.Detail{Reason: "passkey_clone_suspected"}, nil,
			audit.A(event.KeyFactor, core.FactorPasskey.Code()))
		return ErrPasskeyRejected
	}
	fresh, err := s.passkeys.Get(ctx, cred.Subject.Tenant, cred.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return errors.Join(ErrPasskeyRejected, err)
	case err != nil:
		return unavailable(err)
	case fresh.Subject != cred.Subject:
		return ErrPasskeyRejected
	}
	fresh.LastUsedAt = &now
	if fresh.BackupEligible {
		fresh.BackupState = parsed.Response.AuthenticatorData.Flags.HasBackupState()
	}
	if err := s.passkeys.Update(ctx, fresh); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errors.Join(ErrPasskeyRejected, err)
		}
		return unavailable(err)
	}
	return nil
}

func factorCredential(c passkey.Credential) factors.PasskeyCredential {
	return factors.PasskeyCredential{Owner: c.Subject, ID: c.ID, Suspended: !c.Active()}
}

func flagsOf(parsed *protocol.ParsedCredentialAssertionData) factors.AuthenticatorFlags {
	f := parsed.Response.AuthenticatorData.Flags
	return factors.AuthenticatorFlags{UserPresent: f.HasUserPresent(), UserVerified: f.HasUserVerified()}
}
