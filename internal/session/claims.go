package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
)

// MaxAppClaimsBytes caps the compact JSON encoding of application claims, in bytes. It mirrors
// egauth.MaxAppClaimsBytes, which internal packages cannot import.
const MaxAppClaimsBytes = 2048

var (
	// ErrUnknownSubject is returned by a ClaimsSource that no longer knows the subject; the session
	// is revoked instead of keeping stale claims. The composition maps egauth.ErrUnknownSubject to
	// it.
	ErrUnknownSubject = errors.New("session: claims source does not know the subject")
	// ErrMalformedClaims reports application claims that are not one JSON object. It is treated as
	// a failure of the claims source.
	ErrMalformedClaims = errors.New("session: application claims are not a JSON object")
)

// ClaimsSource returns the JSON object of the application claims of a subject. It is the single
// claims source, read at admission, at Reissue and at every renewal, and must be safe for
// concurrent use. It never names the subject: the session's sealed subject is the only one (T-02).
type ClaimsSource interface {
	ClaimsFor(ctx context.Context, s core.Subject) ([]byte, error)
}

// FetchClaims applies the admission rows of DESIGN §4.4. ErrUnknownSubject returns
// core.ErrClaimsSubjectUnknown, a refusal (401) on which a caller holding a session must revoke it;
// any other source error, ErrMalformedClaims included, returns core.ErrClaimsUnavailable and emits
// ClaimsUnavailable; claims over MaxAppClaimsBytes return core.ErrClaimsTooLarge and emit
// ClaimsTooLarge. Claims are never truncated; the result is their compact encoding.
func (r *Renewer) FetchClaims(ctx context.Context, s core.Subject) (core.SealedClaims, error) {
	raw, err := r.claims.ClaimsFor(ctx, s)
	if errors.Is(err, ErrUnknownSubject) {
		return core.SealedClaims{}, errors.Join(core.ErrClaimsSubjectUnknown, err)
	}
	if err == nil {
		var c core.SealedClaims
		c, err = CompactClaims(raw)
		if err == nil {
			return c, nil
		}
		if errors.Is(err, core.ErrClaimsTooLarge) {
			r.emit(ctx, event.ClaimsTooLarge, s, "admission", err)
			return core.SealedClaims{}, err
		}
	}
	r.emit(ctx, event.ClaimsUnavailable, s, "admission", err)
	return core.SealedClaims{}, errors.Join(core.ErrClaimsUnavailable, err)
}

// CompactClaims validates raw as one JSON object and returns its compact encoding. It returns
// ErrMalformedClaims for anything else, and core.ErrClaimsTooLarge, never a truncated value, when
// the compact encoding exceeds MaxAppClaimsBytes.
func CompactClaims(raw []byte) (core.SealedClaims, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return core.SealedClaims{}, ErrMalformedClaims
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, trimmed); err != nil {
		return core.SealedClaims{}, errors.Join(ErrMalformedClaims, err)
	}
	if buf.Len() > MaxAppClaimsBytes {
		return core.SealedClaims{}, errors.Join(core.ErrClaimsTooLarge, errors.New("session: "+strconv.Itoa(buf.Len())+" bytes of application claims"))
	}
	return core.NewSealedClaims(buf.Bytes()), nil
}

func (r *Renewer) renewalClaims(ctx context.Context, a core.SessionAttrs, current core.SealedClaims, now time.Time) (core.ClaimsOutcome, core.SealedClaims, error) {
	raw, err := r.claims.ClaimsFor(ctx, a.Subject())
	if errors.Is(err, ErrUnknownSubject) {
		return core.ClaimsSubjectUnknown, core.SealedClaims{}, err
	}
	if err == nil {
		var c core.SealedClaims
		c, err = CompactClaims(raw)
		if err == nil {
			return core.ClaimsRefreshed, c, nil
		}
		if errors.Is(err, core.ErrClaimsTooLarge) {
			return core.ClaimsTooLarge, core.SealedClaims{}, err
		}
	}
	if now.Sub(a.ClaimsFetchedAt()) <= r.life.RecheckEvery {
		return core.ClaimsKeptStale, current, err
	}
	return core.ClaimsUnavailable, core.SealedClaims{}, err
}

func (r *Renewer) emit(ctx context.Context, t event.Type, s core.Subject, reason string, cause error) {
	_ = audit.Emit(ctx, r.events, t, audit.Scope{TenantID: s.Tenant.String(), UserID: s.User.String()}, audit.Detail{Reason: reason}, cause)
}
