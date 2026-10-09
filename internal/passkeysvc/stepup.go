package passkeysvc

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/factors"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/store/ceremony"
)

// StepUpChallenge is a passkey step-up for the MFA flow: Options for navigator.credentials.get()
// and the 256-bit Handle of the stored MFAPasskey record, which the client sends back with its
// assertion.
type StepUpChallenge struct {
	Options json.RawMessage
	Handle  string
}

// BeginStepUp stores an MFAPasskey record sealing p, scoped to its bound subject, and returns the
// request options for that subject's active credentials with user verification required. The
// record dies with p and lasts at most ceremony.MFAPasskey.TTL(). A login p is finished by
// FinishStepUp, a reauthentication p (core.PendingForReauth) by FinishReauth. It returns
// ErrPasskeyRejected for an unbound p, ErrNoPasskey when the subject has no active credential, and
// a 503 problem on store failure.
func (s *Service) BeginStepUp(ctx context.Context, p core.Pending) (StepUpChallenge, error) {
	sub, ok := p.Subject()
	if !ok {
		return StepUpChallenge{}, ErrPasskeyRejected
	}
	creds, err := s.passkeys.List(ctx, sub)
	if err != nil {
		return StepUpChallenge{}, unavailable(err)
	}
	u := &waUser{sub: sub}
	for _, c := range creds {
		if !c.Active() {
			continue
		}
		if wc, err := webauthnCredential(c); err == nil {
			u.creds = append(u.creds, wc)
		}
	}
	if len(u.creds) == 0 {
		return StepUpChallenge{}, ErrNoPasskey
	}
	wa, err := s.relyingParty(sub.Tenant, ceremony.MFAPasskey)
	if err != nil {
		return StepUpChallenge{}, errors.Join(httpx.ErrUnauthenticated, err)
	}
	assertion, sd, err := wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return StepUpChallenge{}, errors.Join(httpx.ErrInternal, err)
	}
	handle, err := s.putSubjectCeremony(ctx, p, ceremony.MFAPasskey, ceremonycodec.MFAPasskey(), sd)
	if err != nil {
		return StepUpChallenge{}, unavailable(err)
	}
	opts, err := json.Marshal(assertion)
	if err != nil {
		return StepUpChallenge{}, errors.Join(httpx.ErrInternal, err)
	}
	return StepUpChallenge{Options: opts, Handle: handle.Encode()}, nil
}

// FinishStepUp consumes the MFAPasskey record of handle in tenant t, whatever the outcome, and
// verifies assertionJSON against the active credentials of the sealed subject with user
// verification required, the conditional sign-count update and suspension on the clone signal. It
// returns the sealed Pending and a pk_stepup verification of the credential used. Before feeding
// both to Issuer.Complete, whose Pending.Add refuses the credential of a primary passkey of the same
// Pending (C-28), the caller must consume the MFAFlow record the step-up was begun from and refuse
// the result unless that consume succeeds: the MFAPasskey record is independent of it, so skipping
// the consume lets one flow complete twice (once per factor). A record begun for /reauth is
// refused. It returns ErrPasskeyRejected or a 503 problem.
func (s *Service) FinishStepUp(ctx context.Context, t core.TenantID, handle string, assertionJSON []byte) (core.Pending, core.Verified, error) {
	return s.finishSubjectAssertion(ctx, t, handle, assertionJSON, false)
}

func (s *Service) finishSubjectAssertion(ctx context.Context, t core.TenantID, handle string, assertionJSON []byte, reauth bool) (core.Pending, core.Verified, error) {
	f, mint := core.FactorPasskeyStepUp, factors.PasskeyStepUp
	if reauth {
		f, mint = core.FactorPasskey, factors.Passkey
	}
	p, sub, session, err := s.consumeSubjectCeremony(ctx, t, ceremony.MFAPasskey, handle, ErrPasskeyRejected)
	if _, isReauth := p.ReauthOf(); err == nil && isReauth != reauth {
		err = ErrPasskeyRejected
	}
	var v core.Verified
	if err == nil {
		v, err = s.verifySubjectAssertion(ctx, sub, session, assertionJSON, mint)
	}
	if err != nil {
		s.stepUpFailed(ctx, t, f, err)
		return core.Pending{}, core.Verified{}, err
	}
	return p, v, nil
}

func (s *Service) stepUpFailed(ctx context.Context, t core.TenantID, f core.Factor, err error) {
	if !errors.Is(err, ErrPasskeyRejected) {
		return
	}
	_ = s.audit.Emit(ctx, event.MFAVerificationFailed, audit.Scope{TenantID: t.String()},
		audit.Detail{Reason: ErrPasskeyRejected.Code()}, nil, audit.A(event.KeyFactor, f.Code()))
}

type passkeyMint func(factors.PasskeyCredential, factors.AuthenticatorFlags, time.Time) (core.Verified, error)

func (s *Service) verifySubjectAssertion(ctx context.Context, sub core.Subject, session ceremonycodec.WebAuthn, body []byte, mint passkeyMint) (core.Verified, error) {
	sd, err := sessionOf(session)
	if err != nil {
		return core.Verified{}, errors.Join(ErrPasskeyRejected, err)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return core.Verified{}, errors.Join(ErrPasskeyRejected, err)
	}
	cred, wc, err := s.activeCredential(ctx, sub.Tenant, parsed.RawID)
	if err != nil {
		return core.Verified{}, err
	}
	if cred.Subject != sub {
		return core.Verified{}, ErrPasskeyRejected
	}
	wa, err := s.relyingParty(sub.Tenant, ceremony.MFAPasskey)
	if err != nil {
		return core.Verified{}, errors.Join(ErrPasskeyRejected, err)
	}
	if _, err := wa.ValidateLogin(&waUser{sub: sub, creds: []webauthn.Credential{wc}}, sd, parsed); err != nil {
		return core.Verified{}, errors.Join(ErrPasskeyRejected, err)
	}
	if err := s.recordUse(ctx, cred, parsed); err != nil {
		return core.Verified{}, err
	}
	v, err := mint(factorCredential(cred), flagsOf(parsed), s.clock.Now())
	if err != nil {
		return core.Verified{}, errors.Join(ErrPasskeyRejected, err)
	}
	return v, nil
}
