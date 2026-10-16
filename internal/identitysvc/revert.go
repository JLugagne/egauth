package identitysvc

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/ceremonycodec"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/ceremony"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/mfa"
	"github.com/JLugagne/egauth/store/passkey"
)

const (
	revertSlack           = time.Minute
	stateSecurityReverted = "security_reverted"
	stateAccountDisabled  = "account_disabled"
	reasonSecurityRevert  = "security_revert"
)

var noticeNamespace = uuid.MustParse("6f1d5a52-3c39-4f43-9b0e-7d1c2b9e4a10")

// SecurityNotice runs the security-notice cell of one lifecycle outbox row (DESIGN §7.2); the
// ComponentNotices subscriber calls it and it ignores rows of other components. It sends:
//   - for CredentialRotated, except the rotation a revert itself applies, and for FactorsChanged: a
//     notice to the verified email the account had when the row was written;
//   - for IdentifierChanged of the email: a notice to the previous address, none for a first
//     verification, which has no previous address; of the phone or recovery email: a notice to the
//     verified email the account had when the row was written;
//   - nothing for disable, enable and delete, nor for a deleted or unknown account.
//
// A row delivered after a later email change goes to the address of its time, read from the email
// history identitysvc keeps for seven days, so a late notice never reaches, nor arms, the address
// that replaced it. When that history is missing, the notice goes to the current address without a
// revert link.
//
// A notice carries a SecurityRevert link bound to the address it is sent to, dated at the change
// (item.CreatedAt) and usable for seven days from it; past that, or once a revert already covered
// the change, it has no link. The link is not tied to the epoch: a later security change by the
// hijacker must not disarm it (C-45). Its handle is derived from the row under the deployment data
// key, so a retried row re-sends the same link instead of adding one. Client is zero: the outbox
// row does not record the client. It sends synchronously and returns the store, PendingSource,
// Links and mailer errors, so that the outbox retries; the DeliveryID is derived from the row, so a
// retry carries the same id.
func (a *Accounts) SecurityNotice(ctx context.Context, item identity.OutboxItem) error {
	if item.Component != identity.ComponentNotices {
		return nil
	}
	u, err := a.identity.GetUser(ctx, item.Subject)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case err != nil:
		return err
	case !u.DeletedAt.IsZero():
		return nil
	}
	n, ok := noticeOf(item, u)
	if !ok {
		return nil
	}
	at := item.CreatedAt
	if at.IsZero() {
		at = a.clock.Now()
	}
	linked := true
	if n.current && u.EmailVerifiedAt.After(at) {
		addr, found, err := a.emailAt(ctx, u.Subject, at)
		if err != nil {
			return err
		}
		if found {
			n.to = addr
		}
		linked = found
	}
	msg := SecurityNoticeMessage{
		DeliveryID: noticeDeliveryID(item),
		Tenant:     item.Subject.Tenant,
		To:         n.to.Value(),
		Event:      n.event,
		Summary:    n.summary,
		OccurredAt: at,
	}
	if linked && a.clock.Now().Before(at.Add(ceremony.SecurityRevert.TTL())) {
		link, err := a.putRevert(ctx, u, n.to, n.event, at, item)
		if err != nil {
			return err
		}
		msg.RevertLink = link
	}
	return a.mailer.SecurityNotice(ctx, msg)
}

type notice struct {
	event   SecurityEvent
	to      identity.Identifier
	summary string
	current bool
}

func noticeOf(item identity.OutboxItem, u identity.User) (notice, bool) {
	verified := !u.EmailVerifiedAt.IsZero() && !u.Email.IsZero()
	switch item.Event {
	case identity.EventCredentialRotated:
		if item.Rotation == identity.RotationSecurityRevert || !verified {
			return notice{}, false
		}
		return notice{SecurityCredentialRotated, u.Email, "The password of your account was changed.", true}, true
	case identity.EventFactorsChanged:
		if !verified {
			return notice{}, false
		}
		return notice{SecurityFactorsChanged, u.Email, "A sign-in method of your account was changed (" + item.Change.String() + ").", true}, true
	case identity.EventIdentifierChanged:
		return identifierNotice(item, u, verified)
	}
	return notice{}, false
}

func identifierNotice(item identity.OutboxItem, u identity.User, verified bool) (notice, bool) {
	switch item.Identifier {
	case identity.IdentifierEmail:
		if item.Old.Kind() != identity.IdentifierEmail {
			return notice{}, false
		}
		return notice{SecurityIdentifierChanged, item.Old, "The email address of your account was changed.", false}, true
	case identity.IdentifierPhone:
		if verified {
			return notice{SecurityIdentifierChanged, u.Email, "The phone number of your account was changed.", true}, true
		}
	case identity.IdentifierRecoveryEmail:
		if verified {
			return notice{SecurityIdentifierChanged, u.Email, "The recovery email of your account was changed.", true}, true
		}
	}
	return notice{}, false
}

func noticeDeliveryID(item identity.OutboxItem) uuid.UUID {
	key := item.Subject.Tenant.String() + "/" + item.Subject.User.String() + "/" + strconv.FormatInt(item.ID, 10) + "/" + item.Component.String()
	return uuid.NewSHA1(noticeNamespace, []byte(key))
}

func (a *Accounts) putRevert(ctx context.Context, u identity.User, to identity.Identifier, ev SecurityEvent, at time.Time, item identity.OutboxItem) (string, error) {
	t := u.Subject.Tenant
	dead, err := a.superseded(ctx, u.Subject, at)
	if err != nil || dead {
		return "", err
	}
	scope, err := a.scopes.Scope(to)
	if err != nil {
		return "", err
	}
	handle, err := a.revertHandle(item)
	if err != nil {
		return "", err
	}
	if err := a.holdAnchor(ctx, u, to, at); err != nil {
		return "", err
	}
	rec, err := a.revertRecord(ctx, u, scope, handle.Hash(), ceremonycodec.Revert{Address: to.Value(), Event: uint16(ev)}, at)
	if err != nil {
		return "", err
	}
	if _, err := a.ceremonies.Put(ctx, rec); err != nil && !errors.Is(err, store.ErrConflict) {
		return "", err
	}
	return a.links.Link(ctx, t, ceremony.SecurityRevert, handle.Encode())
}

type revertPlan struct {
	user    identity.User
	address identity.Identifier
	restore bool
	since   time.Time
	until   time.Time
}

func (p revertPlan) covers(at time.Time) bool {
	return !at.Before(p.since.Add(-revertSlack)) && (p.until.IsZero() || !at.After(p.until.Add(revertSlack)))
}

func (p revertPlan) spans(start, end time.Time) []interval {
	if p.until.IsZero() {
		return []interval{{p.since, end}}
	}
	hi := p.until.Add(revertSlack)
	if !hi.Before(start) {
		return []interval{{p.since, maxTime(hi, end)}}
	}
	return []interval{{p.since, hi}, {start, end}}
}

type interval struct {
	from, to time.Time
}

func (h *acctHandlers) revert(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	handle, err := ceremonycodec.ParseHandle(r.Field(routes.FieldToken))
	if err != nil {
		r.Fail(w, errors.Join(ErrInvalidToken, err))
		return
	}
	p, err := h.issuer.Begin(ctx, r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	plan, out, err := h.revertOnce(ctx, r.Tenant(), handle.Hash())
	if err != nil {
		r.Fail(w, err)
		return
	}
	sub := plan.user.Subject
	_ = h.audit.Emit(ctx, event.AccountLocked, scopeOf(sub), audit.Detail{Reason: reasonSecurityRevert}, nil)
	if out.disabled {
		_ = h.audit.Emit(ctx, event.AccountDisabled, scopeOf(sub), audit.Detail{Reason: reasonSecurityRevert}, nil)
	}
	if out.taken {
		r.Fail(w, ErrAccountExists)
		return
	}
	if plan.restore {
		_ = h.audit.Emit(ctx, event.EmailChanged, scopeOf(sub), audit.Detail{Reason: reasonSecurityRevert}, nil,
			audit.A(event.KeyIdentifierKind, identity.IdentifierEmail.String()))
	}
	u, err := h.identity.GetUser(ctx, sub)
	if err != nil {
		r.Fail(w, errors.Join(httpx.ErrServiceUnavailable, err))
		return
	}
	state := stateAccountDisabled
	if st := stateOf(u); st.Usable() {
		state = stateSecurityReverted
		if st.EmailVerified() && u.Email == plan.address {
			h.sendReset(ctx, p, u, st)
		}
	}
	r.RespondPending(w, p, httpx.Response{Body: journeyBody{State: state}})
}

func (a *Accounts) revertOnce(ctx context.Context, t core.TenantID, hash []byte) (revertPlan, revertOutcome, error) {
	rec, err := a.ceremonies.Peek(ctx, t, ceremony.SecurityRevert, hash)
	if err != nil {
		return revertPlan{}, revertOutcome{}, ceremonyProblem(err)
	}
	_, sub, err := openReset(rec, t)
	if err != nil {
		return revertPlan{}, revertOutcome{}, err
	}
	u, err := a.identity.GetUser(ctx, sub)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return revertPlan{}, revertOutcome{}, errors.Join(ErrInvalidToken, err)
	case err != nil:
		return revertPlan{}, revertOutcome{}, errors.Join(httpx.ErrServiceUnavailable, err)
	}
	release, err := a.lockReverts(ctx, u)
	if err != nil {
		return revertPlan{}, revertOutcome{}, err
	}
	defer release()
	if rec, err = a.ceremonies.Peek(ctx, t, ceremony.SecurityRevert, hash); err != nil {
		return revertPlan{}, revertOutcome{}, ceremonyProblem(err)
	}
	plan, out, err := a.runRevert(ctx, rec, t)
	if err != nil {
		return revertPlan{}, revertOutcome{}, err
	}
	_, _ = a.ceremonies.Consume(context.WithoutCancel(ctx), t, ceremony.SecurityRevert, hash)
	return plan, out, nil
}

func (a *Accounts) runRevert(ctx context.Context, rec ceremony.Record, t core.TenantID) (revertPlan, revertOutcome, error) {
	plan, err := a.planRevert(ctx, rec, t)
	if err != nil {
		return revertPlan{}, revertOutcome{}, err
	}
	run := &revertRun{Accounts: a}
	out, err := run.apply(ctx, plan)
	return plan, out, err
}

func (a *Accounts) planRevert(ctx context.Context, rec ceremony.Record, t core.TenantID) (revertPlan, error) {
	_, sub, err := openReset(rec, t)
	if err != nil {
		return revertPlan{}, err
	}
	rv, err := ceremonycodec.SecurityRevert().Decode(rec.Payload())
	if err != nil {
		return revertPlan{}, errors.Join(ErrInvalidToken, err)
	}
	ev := SecurityEvent(rv.Event)
	if uint16(ev) != rv.Event || ev < SecurityCredentialRotated || ev > SecurityIdentifierChanged {
		return revertPlan{}, ErrInvalidToken
	}
	addr, err := identity.NewIdentifier(identity.IdentifierEmail, rv.Address)
	if err != nil {
		return revertPlan{}, errors.Join(ErrInvalidToken, err)
	}
	u, err := a.identity.GetUser(ctx, sub)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return revertPlan{}, errors.Join(ErrInvalidToken, err)
	case err != nil:
		return revertPlan{}, errors.Join(httpx.ErrServiceUnavailable, err)
	}
	if !stateOf(u).Usable() {
		return revertPlan{}, ErrInvalidToken
	}
	restore := u.Email != addr
	if restore && ev != SecurityIdentifierChanged {
		return revertPlan{}, ErrInvalidToken
	}
	changedAt := rec.CreatedAt()
	dead, err := a.superseded(ctx, sub, changedAt)
	switch {
	case err != nil:
		return revertPlan{}, errors.Join(httpx.ErrServiceUnavailable, err)
	case dead:
		return revertPlan{}, ErrInvalidToken
	}
	since := changedAt
	first, _, _, err := a.anchor(ctx, sub, addr)
	switch {
	case err != nil:
		return revertPlan{}, errors.Join(httpx.ErrServiceUnavailable, err)
	case !first.IsZero() && first.Before(since):
		since = first
	}
	until := changedAt
	if restore {
		until = time.Time{}
	}
	return revertPlan{user: u, address: addr, restore: restore, since: since, until: until}, nil
}

type revertOutcome struct {
	taken, disabled bool
}

type revertRun struct {
	*Accounts
	first, last time.Time
}

func (r *revertRun) Apply(ctx context.Context, m identity.Mutation) (identity.Applied, error) {
	ap, err := r.Accounts.Apply(ctx, m)
	for _, it := range ap.Outbox {
		if it.CreatedAt.IsZero() {
			continue
		}
		if r.first.IsZero() || it.CreatedAt.Before(r.first) {
			r.first = it.CreatedAt
		}
		if it.CreatedAt.After(r.last) {
			r.last = it.CreatedAt
		}
	}
	return ap, err
}

func (r *revertRun) start(began time.Time) time.Time {
	if r.first.IsZero() || began.Before(r.first) {
		return began
	}
	return r.first
}

func (r *revertRun) end() time.Time {
	if r.last.IsZero() {
		return r.clock.Now()
	}
	return r.last.Add(time.Microsecond)
}

func (r *revertRun) apply(ctx context.Context, plan revertPlan) (revertOutcome, error) {
	sub := plan.user.Subject
	began := r.clock.Now()
	if err := r.lockDown(ctx, sub); err != nil {
		return revertOutcome{}, err
	}
	var out revertOutcome
	if plan.restore {
		_, err := r.changeEmail(ctx, plan.user, plan.address, r.Apply)
		switch {
		case errors.Is(err, identity.ErrIdentifierTaken):
			out.taken = true
		case err != nil:
			return revertOutcome{}, mutationProblem(err)
		}
	}
	stripped, err := r.removeFactors(ctx, sub, plan)
	if err != nil {
		return revertOutcome{}, mutationProblem(err)
	}
	if err := r.removeIdentifiers(ctx, plan); err != nil {
		return revertOutcome{}, mutationProblem(err)
	}
	spans := plan.spans(r.start(began), r.end())
	widens, err := r.spanWidens(ctx, sub, spans)
	if err != nil {
		return revertOutcome{}, errors.Join(httpx.ErrServiceUnavailable, err)
	}
	if out.disabled = out.taken || widens || stripped; out.disabled && !stripped {
		if _, err := r.Apply(ctx, identity.SetDisabledState{Subject: sub, Disable: true}); err != nil {
			return revertOutcome{}, mutationProblem(err)
		}
	}
	for _, s := range spans {
		if err := r.recordSpan(ctx, plan.user, s.from, s.to); err != nil {
			return revertOutcome{}, errors.Join(httpx.ErrServiceUnavailable, err)
		}
	}
	r.dropAnchor(ctx, sub, plan.address)
	if plan.restore && !out.taken {
		r.dropAnchor(ctx, sub, plan.user.Email)
		r.dropReverts(ctx, sub.Tenant, plan.user.Email)
	}
	return out, nil
}

func (a *Accounts) dropReverts(ctx context.Context, t core.TenantID, addr identity.Identifier) {
	scope, err := a.scopes.Scope(addr)
	if err != nil {
		return
	}
	_, _ = a.ceremonies.DeleteForScope(ctx, t, scope.Hash(), ceremony.SecurityRevert)
}

func (a *revertRun) removeFactors(ctx context.Context, sub core.Subject, plan revertPlan) (bool, error) {
	e, err := a.mfa.GetTOTP(ctx, sub)
	hasTOTP := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	creds, err := a.passkeys.List(ctx, sub)
	if err != nil {
		return false, err
	}
	dropTOTP := hasTOTP && plan.covers(totpChangedAt(e))
	had := hasTOTP && e.Confirmed()
	kept := had && !dropTOTP
	var drop []passkey.CredentialID
	for _, c := range creds {
		had = had || c.Active()
		if plan.covers(c.CreatedAt) {
			drop = append(drop, c.ID)
			continue
		}
		kept = kept || c.Active()
	}
	stripped := had && !kept
	if stripped {
		if _, err := a.Apply(ctx, identity.SetDisabledState{Subject: sub, Disable: true}); err != nil {
			return false, err
		}
	}
	if dropTOTP {
		if _, err := a.Apply(ctx, identity.BumpEpoch{Subject: sub, Change: identity.FactorTOTPRemoved}); err != nil {
			return stripped, err
		}
		if err := a.mfa.DeleteForSubject(ctx, sub); err != nil {
			return stripped, err
		}
	}
	if err := a.removePasskeys(ctx, sub, drop); err != nil {
		return stripped, err
	}
	return stripped, a.removeLinks(ctx, sub, plan)
}

func totpChangedAt(e mfa.Enrollment) time.Time {
	if e.ConfirmedAt != nil {
		return *e.ConfirmedAt
	}
	return e.CreatedAt
}

func (a *revertRun) removePasskeys(ctx context.Context, sub core.Subject, ids []passkey.CredentialID) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := a.Apply(ctx, identity.BumpEpoch{Subject: sub, Change: identity.FactorPasskeyRemoved}); err != nil {
		return err
	}
	for _, id := range ids {
		if err := a.passkeys.Delete(ctx, sub, id); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}

func (a *revertRun) removeLinks(ctx context.Context, sub core.Subject, plan revertPlan) error {
	links, err := a.identity.ListFederated(ctx, sub)
	if err != nil {
		return err
	}
	for _, l := range links {
		if !plan.covers(l.LinkedAt) {
			continue
		}
		m := identity.UnlinkFederated{Subject: sub, Provider: l.Identity.Provider, ProviderSubject: l.Identity.ProviderSubject}
		if _, err := a.Apply(ctx, m); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}

func (a *revertRun) removeIdentifiers(ctx context.Context, plan revertPlan) error {
	u := plan.user
	if !u.PhoneVerifiedAt.IsZero() && plan.covers(u.PhoneVerifiedAt) {
		if _, err := a.Apply(ctx, identity.SetPhone{Subject: u.Subject}); err != nil {
			return err
		}
	}
	if !u.RecoveryEmailVerifiedAt.IsZero() && plan.covers(u.RecoveryEmailVerifiedAt) {
		if _, err := a.Apply(ctx, identity.SetRecoveryEmail{Subject: u.Subject}); err != nil {
			return err
		}
	}
	return nil
}

func (a *revertRun) lockDown(ctx context.Context, sub core.Subject) error {
	phc, err := decoyHash(ctx, a.hasher)
	if err != nil {
		return errors.Join(httpx.ErrInternal, err)
	}
	if _, err := a.Apply(ctx, identity.SetPassword{Subject: sub, PHC: identity.NewPasswordHash(phc), Reason: identity.RotationSecurityRevert}); err != nil {
		return mutationProblem(err)
	}
	if _, err := a.Apply(ctx, identity.SetMustChange{Subject: sub, MustChange: true}); err != nil {
		return mutationProblem(err)
	}
	return nil
}
