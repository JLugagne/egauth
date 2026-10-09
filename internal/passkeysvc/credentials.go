package passkeysvc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/httpx"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/store"
	"github.com/JLugagne/egauth/store/identity"
	"github.com/JLugagne/egauth/store/passkey"
)

// MaxNicknameRunes bounds a credential nickname.
const MaxNicknameRunes = 64

const (
	stateRenamed = "passkey_renamed"
	stateDeleted = "passkey_deleted"
)

// CredentialView is the §8 listing of one credential: what GET /passkey/credentials answers and
// what rename and delete accept back through CredentialID, unpadded base64url end to end (P-05). It
// never carries the subject, the public key, the counter or the authenticator data.
// NeedsReregistration is true only for a Legacy credential, registered before residency was
// required.
type CredentialView struct {
	CredentialID        passkey.CredentialID `json:"credential_id"`
	Nickname            string               `json:"nickname"`
	Transports          []string             `json:"transports"`
	BackupEligible      bool                 `json:"backup_eligible"`
	BackupState         bool                 `json:"backup_state"`
	Discoverable        string               `json:"discoverable"`
	Suspended           bool                 `json:"suspended"`
	NeedsReregistration bool                 `json:"needs_reregistration"`
	CreatedAt           time.Time            `json:"created_at"`
	LastUsedAt          *time.Time           `json:"last_used_at"`
}

func View(c passkey.Credential) CredentialView {
	transports := slices.Clone(c.Transports)
	if transports == nil {
		transports = []string{}
	}
	return CredentialView{
		CredentialID:        slices.Clone(c.ID),
		Nickname:            c.Nickname,
		Transports:          transports,
		BackupEligible:      c.BackupEligible,
		BackupState:         c.BackupState,
		Discoverable:        c.Discoverable.String(),
		Suspended:           !c.Active(),
		NeedsReregistration: c.Discoverable.NeedsReregistration(),
		CreatedAt:           c.CreatedAt,
		LastUsedAt:          c.LastUsedAt,
	}
}

type listBody struct {
	Credentials []CredentialView `json:"credentials"`
}

type renamedBody struct {
	State      string         `json:"state"`
	Credential CredentialView `json:"credential"`
}

type deletedBody struct {
	State        string `json:"state"`
	SessionEnded bool   `json:"session_ended"`
}

func (h *handlers) list(w http.ResponseWriter, r *httpx.Request) {
	a, err := current(r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	creds, err := h.passkeys.List(r.Context(), a.Subject())
	if err != nil {
		r.Fail(w, unavailable(err))
		return
	}
	slices.SortStableFunc(creds, func(x, y passkey.Credential) int { return x.CreatedAt.Compare(y.CreatedAt) })
	out := listBody{Credentials: make([]CredentialView, 0, len(creds))}
	for _, c := range creds {
		out.Credentials = append(out.Credentials, View(c))
	}
	r.Respond(w, httpx.Response{Body: out})
}

func parseCredentialID(raw string) (passkey.CredentialID, error) {
	quoted, err := json.Marshal(raw)
	if err != nil {
		return nil, errors.Join(ErrInvalidCredentialID, err)
	}
	var id passkey.CredentialID
	if err := id.UnmarshalJSON(quoted); err != nil {
		return nil, errors.Join(ErrInvalidCredentialID, err)
	}
	return id, nil
}

func parseNickname(raw string, optional bool) (string, error) {
	n := strings.TrimSpace(raw)
	if n == "" && optional {
		return "", nil
	}
	if n == "" || !utf8.ValidString(n) || utf8.RuneCountInString(n) > MaxNicknameRunes {
		return "", ErrInvalidNickname
	}
	if strings.ContainsFunc(n, func(c rune) bool { return unicode.IsControl(c) || unicode.Is(unicode.Cf, c) }) {
		return "", ErrInvalidNickname
	}
	return n, nil
}

func (s *Service) owned(ctx context.Context, sub core.Subject, raw string) (passkey.Credential, error) {
	id, err := parseCredentialID(raw)
	if err != nil {
		return passkey.Credential{}, err
	}
	return s.ownedID(ctx, sub, id)
}

func (s *Service) ownedID(ctx context.Context, sub core.Subject, id passkey.CredentialID) (passkey.Credential, error) {
	c, err := s.passkeys.Get(ctx, sub.Tenant, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return passkey.Credential{}, errors.Join(ErrCredentialNotFound, err)
	case err != nil:
		return passkey.Credential{}, unavailable(err)
	case c.Subject != sub:
		return passkey.Credential{}, ErrCredentialNotFound
	}
	return c, nil
}

func (h *handlers) rename(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	a, err := current(r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	id, err := parseCredentialID(r.Field(routes.FieldCredentialID))
	if err != nil {
		r.Fail(w, err)
		return
	}
	nickname, err := parseNickname(r.Field(routes.FieldNickname), false)
	if err != nil {
		r.Fail(w, err)
		return
	}
	c, err := h.renameCredential(ctx, a.Subject(), id, nickname)
	if err != nil {
		r.Fail(w, err)
		return
	}
	r.Respond(w, httpx.Response{Body: renamedBody{State: stateRenamed, Credential: View(c)}})
}

func (s *Service) renameCredential(ctx context.Context, sub core.Subject, id passkey.CredentialID, nickname string) (passkey.Credential, error) {
	defer s.lockCredential(id)()
	c, err := s.ownedID(ctx, sub, id)
	if err != nil {
		return passkey.Credential{}, err
	}
	c.Nickname = nickname
	if err := s.passkeys.Update(ctx, c); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return passkey.Credential{}, errors.Join(ErrCredentialNotFound, err)
		}
		return passkey.Credential{}, unavailable(err)
	}
	return c, nil
}

func (h *handlers) remove(w http.ResponseWriter, r *httpx.Request) {
	ctx := r.Context()
	a, err := current(r)
	if err != nil {
		r.Fail(w, err)
		return
	}
	sub := a.Subject()
	c, err := h.owned(ctx, sub, r.Field(routes.FieldCredentialID))
	if err != nil {
		r.Fail(w, err)
		return
	}
	if err := h.removeCredential(ctx, sub, c.ID); err != nil {
		r.Fail(w, err)
		return
	}
	_ = h.audit.Emit(ctx, event.CredentialRemoved, scopeOf(sub), audit.Detail{}, nil, audit.A(event.KeyFactor, core.FactorPasskey.Code()))
	r.Respond(w, httpx.Response{Body: deletedBody{State: stateDeleted, SessionEnded: true}})
}

func (s *Service) removeCredential(ctx context.Context, sub core.Subject, id passkey.CredentialID) error {
	if _, err := s.mutations.Apply(ctx, identity.BumpEpoch{Subject: sub, Keep: uuid.Nil, Change: identity.FactorPasskeyRemoved}); err != nil {
		return unavailable(err)
	}
	if err := s.passkeys.Delete(ctx, sub, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errors.Join(ErrCredentialNotFound, err)
		}
		return unavailable(err)
	}
	totp, err := s.mfa.HasConfirmedTOTP(ctx, sub)
	if err != nil {
		return unavailable(err)
	}
	pk, err := s.passkeys.HasActive(ctx, sub)
	if err != nil {
		return unavailable(err)
	}
	if totp || pk {
		return nil
	}
	if err := s.mfa.DeleteRecoveryCodes(ctx, sub); err != nil {
		return unavailable(err)
	}
	return nil
}
