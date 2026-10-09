package mfasvc

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
)

const (
	stateEnrollmentStarted = "totp_enrollment_started"
	stateTOTPEnabled       = "totp_enabled"
	stateTOTPDisabled      = "totp_disabled"
	stateCodesRegenerated  = "recovery_codes_regenerated"
)

type enrollBody struct {
	State  string `json:"state"`
	Secret string `json:"secret"`
	URI    string `json:"otpauth_uri"`
}

type codesBody struct {
	State         string   `json:"state"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
	SessionEnded  bool     `json:"session_ended,omitempty"`
}

func current(r *httpx.Request) (core.SessionAttrs, error) {
	res, ok := r.Session()
	if !ok {
		return core.SessionAttrs{}, httpx.ErrUnauthenticated
	}
	return res.Attrs(), nil
}

func (h *handlers) enroll(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	a, err := current(r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	sub := a.Subject()
	prev, err := h.mfa.GetTOTP(ctx, sub)
	switch {
	case errors.Is(err, store.ErrNotFound):
		prev = mfa.Enrollment{}
	case err != nil:
		r.Fail(w, unavailable(err))
		return
	case prev.Confirmed():
		r.Fail(w, ErrAlreadyEnrolled)
		return
	}
	secret, err := newSecret()
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	ref, err := sealing.TOTPSecret(sub)
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	sealed, err := sealing.Seal(ctx, h.kek, ref, []byte(secret))
	if err != nil {
		r.Fail(w, unavailable(err))
		return
	}
	err = h.mfa.SaveTOTP(ctx, mfa.Enrollment{
		Subject:        sub,
		Sealed:         sealed,
		AADVersion:     mfa.AADVersionCurrent,
		LastUsedStep:   prev.LastUsedStep,
		FailedAttempts: prev.FailedAttempts,
		LastAttemptAt:  prev.LastAttemptAt,
		CreatedAt:      h.clock.Now(),
	})
	if err != nil {
		r.Fail(w, unavailable(err))
		return
	}
	r.Respond(w, httpx.Response{Body: enrollBody{
		State:  stateEnrollmentStarted,
		Secret: secret,
		URI:    provisioningURI(secret, h.totpIssuer, h.accountLabel(ctx, sub)),
	}})
}

func (s *Service) accountLabel(ctx context.Context, sub core.Subject) string {
	u, err := s.identity.GetUser(ctx, sub)
	if err != nil || u.Email.IsZero() {
		return sub.User.String()
	}
	return u.Email.Value()
}

func (h *handlers) confirm(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	a, err := current(r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	sub := a.Subject()
	pending, err := h.mfa.GetTOTP(ctx, sub)
	switch {
	case errors.Is(err, store.ErrNotFound) || (err == nil && pending.Confirmed()):
		r.Fail(w, ErrNoPendingEnrollment)
		return
	case err != nil:
		r.Fail(w, unavailable(err))
		return
	}
	e, step, err := h.verifyTOTP(ctx, sub, r.Field(routes.FieldCode), false)
	if err != nil {
		h.failed(ctx, sub, core.FactorTOTP, err)
		r.Fail(w, err)
		return
	}
	plain, hashes, err := newRecoveryCodes()
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	if _, err := h.mutations.Apply(ctx, identity.BumpEpoch{Subject: sub, Keep: a.Lineage(), Change: identity.FactorTOTPEnrolled}); err != nil {
		r.Fail(w, unavailable(err))
		return
	}
	now := h.clock.Now()
	e.ConfirmedAt = &now
	e.LastUsedStep = max(e.LastUsedStep, step)
	e.FailedAttempts = 0
	if err := h.mfa.ConfirmEnrollment(ctx, e, hashes); err != nil {
		r.Fail(w, unavailable(err))
		return
	}
	_ = h.audit.Emit(ctx, event.CredentialAdded, scopeOf(sub), audit.Detail{}, nil, audit.A(event.KeyFactor, core.FactorTOTP.Code()))
	ended := h.issuer.Reissue(ctx, w, r, httpx.FactorEnrolledChange(core.FactorTOTP)) != nil
	r.Respond(w, httpx.Response{Body: codesBody{State: stateTOTPEnabled, RecoveryCodes: plain, SessionEnded: ended}})
}

func (h *handlers) disable(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	a, err := current(r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	sub := a.Subject()
	f, err := ParseFactor(r.Field(routes.FieldFactor))
	if err != nil {
		r.Fail(w, err)
		return
	}
	confirmed, err := h.mfa.HasConfirmedTOTP(ctx, sub)
	switch {
	case err != nil:
		r.Fail(w, unavailable(err))
		return
	case !confirmed:
		r.Fail(w, ErrNotEnrolled)
		return
	}
	if _, err := h.Verify(ctx, sub, f, r.Field(routes.FieldCode)); err != nil {
		r.Fail(w, err)
		return
	}
	passkey, err := h.passkeys.HasActive(ctx, sub)
	if err != nil {
		r.Fail(w, unavailable(err))
		return
	}
	if err := h.removeTOTP(ctx, sub, !passkey); err != nil {
		r.Fail(w, unavailable(err))
		return
	}
	_ = h.audit.Emit(ctx, event.CredentialRemoved, scopeOf(sub), audit.Detail{}, nil, audit.A(event.KeyFactor, core.FactorTOTP.Code()))
	r.Respond(w, httpx.Response{Body: codesBody{State: stateTOTPDisabled, SessionEnded: true}})
}

func (s *Service) removeTOTP(ctx context.Context, sub core.Subject, codes bool) error {
	if _, err := s.mutations.Apply(ctx, identity.BumpEpoch{Subject: sub, Keep: uuid.Nil, Change: identity.FactorTOTPRemoved}); err != nil {
		return err
	}
	if err := s.mfa.DeleteTOTP(ctx, sub); err != nil {
		return err
	}
	if !codes {
		return nil
	}
	return s.mfa.DeleteRecoveryCodes(ctx, sub)
}

func (h *handlers) regenerate(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	a, err := current(r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	sub := a.Subject()
	has, err := h.hasSecondFactor(ctx, sub)
	switch {
	case err != nil:
		r.Fail(w, unavailable(err))
		return
	case !has:
		r.Fail(w, ErrNoSecondFactor)
		return
	}
	plain, hashes, err := newRecoveryCodes()
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrInternal, err))
		return
	}
	if _, err := h.mutations.Apply(ctx, identity.BumpEpoch{Subject: sub, Keep: uuid.Nil, Change: identity.FactorRecoveryCodesRegenerated}); err != nil {
		r.Fail(w, unavailable(err))
		return
	}
	if err := h.mfa.ReplaceRecoveryCodes(ctx, sub, hashes); err != nil {
		r.Fail(w, unavailable(err))
		return
	}
	_ = h.audit.Emit(ctx, event.CredentialAdded, scopeOf(sub), audit.Detail{}, nil, audit.A(event.KeyFactor, core.FactorRecoveryCode.Code()))
	r.Respond(w, httpx.Response{Body: codesBody{State: stateCodesRegenerated, RecoveryCodes: plain, SessionEnded: true}})
}
