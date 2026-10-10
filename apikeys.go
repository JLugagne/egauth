package egauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/JLugagne/egauth/event"
	"github.com/JLugagne/egauth/internal/audit"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/principal"
	"github.com/JLugagne/egauth/store/keys"
	"github.com/JLugagne/egauth/store/tokens"
)

// DefaultAPIKeyLifetime is what keys.DefaultExpiry() resolves to for APIKeyRequest.Lifetime.
const DefaultAPIKeyLifetime = 90 * 24 * time.Hour

// APIKeys issues and revokes the API keys of the calling user. Only a session caller has keys: a
// System caller gets ErrForbidden and an API-key caller ErrAPIKeyCaller. Every method needs a
// session fresh within SessionPolicy.ReauthWindow and multi-factor when its subject enrolled a
// second factor. It returns ErrFacadeUnavailable when Modules.APIKeys is nil.
type APIKeys struct {
	f *facade
}

// APIKeys returns the API-key facade.
func (a *Auth[C]) APIKeys() *APIKeys {
	return &APIKeys{f: a.facade()}
}

// APIKeyRequest describes a key to issue. Kind is one of APIKeyModule.Kinds and Name a printable label of
// at most 128 bytes. Roles, Scopes and Groups must each be a subset of the caller's current
// AppClaims; a key never carries Custom, which comes from its owner at every use. The zero Lifetime
// is invalid: pass keys.ExpireAfter, keys.NeverExpire or keys.DefaultExpiry.
type APIKeyRequest struct {
	Kind                  string
	Name                  string
	Roles, Scopes, Groups []string
	Lifetime              keys.Expiry
}

// APIKeySecret is a newly issued key: its description and its secret, which is shown once and
// never stored. It renders the secret as REDACTED under fmt, slog and JSON; only Reveal returns it.
type APIKeySecret struct {
	Info   APIKeyInfo
	secret *string
}

// Reveal returns the key to hand to its client; never log or persist it.
func (s APIKeySecret) Reveal() string {
	if s.secret == nil {
		return ""
	}
	return *s.secret
}

func (s APIKeySecret) String() string {
	return "egauth.APIKeySecret{ID: " + s.Info.ID.String() + ", Kind: " + s.Info.Kind + ", Secret: REDACTED}"
}

func (s APIKeySecret) GoString() string { return s.String() }

func (s APIKeySecret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

func (s APIKeySecret) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", s.Info.ID.String()), slog.String("kind", s.Info.Kind), slog.String("secret", "REDACTED"))
}

func (s APIKeySecret) MarshalJSON() ([]byte, error) {
	return []byte(`{"id":"` + s.Info.ID.String() + `","secret":"REDACTED"}`), nil
}

// Create issues a key owned by the caller. It returns ErrClaimsNotSubset when a requested role,
// scope or group is not among the caller's current claims, and ErrInvalidRequest for an unknown
// kind, an over-long name or one that is not printable UTF-8 (controls, format and bidi characters
// are refused), a blank claim, or a Lifetime that is zero or already over.
func (k *APIKeys) Create(ctx context.Context, by principal.Caller, req APIKeyRequest) (APIKeySecret, error) {
	g, err := k.authorize(ctx, by, "APIKeys.Create")
	if err != nil {
		return APIKeySecret{}, err
	}
	if err := k.check(req); err != nil {
		return APIKeySecret{}, err
	}
	if !subset(req.Roles, g.claims.roles) || !subset(req.Scopes, g.claims.scopes) || !subset(req.Groups, g.claims.groups) {
		return APIKeySecret{}, ErrClaimsNotSubset
	}
	now := k.f.o.clock.Now().UTC()
	expires, err := req.Lifetime.At(now, DefaultAPIKeyLifetime)
	switch {
	case err != nil:
		return APIKeySecret{}, errors.Join(ErrInvalidRequest, err)
	case !expires.IsZero() && !expires.After(now):
		return APIKeySecret{}, errors.Join(ErrInvalidRequest, errors.New("egauth: the API key lifetime must be positive"))
	}
	roles, scopes, groups := dedupe(req.Roles), dedupe(req.Scopes), dedupe(req.Groups)
	claims, err := encodeAPIKeyGrant(roles, scopes, groups)
	if err != nil {
		return APIKeySecret{}, err
	}
	if len(claims) > tokens.MaxAppClaimsLen {
		return APIKeySecret{}, errors.Join(ErrInvalidRequest, errors.New("egauth: the requested claims are too large"))
	}
	secret, hash, err := newAPIKeySecret(k.f.apiKeys.Prefix)
	if err != nil {
		return APIKeySecret{}, errors.Join(errors.New("egauth: generating an API key"), err)
	}
	rec := tokens.APIKey{
		ID: uuid.New(), Owner: g.subject, Kind: req.Kind, Name: req.Name, KeyHash: hash, AppClaims: claims,
		CreatedEpoch: g.epoch, CreatedAt: now, ExpiresAt: expires,
	}
	if err := k.f.storage.Tokens.CreateAPIKey(ctx, rec); err != nil {
		return APIKeySecret{}, err
	}
	emitFor(ctx, k.f, event.APIKeyCreated, g.subject, "", audit.A(event.KeyKeyType, rec.Kind), audit.A(event.KeyKeyID, rec.ID.String()))
	return APIKeySecret{Info: infoOf(rec, roles, scopes, groups), secret: &secret}, nil
}

// Revoke revokes the caller's key id at once. It returns store.ErrNotFound when the caller owns
// no such key, and nil for a key already revoked.
func (k *APIKeys) Revoke(ctx context.Context, by principal.Caller, id uuid.UUID) error {
	g, err := k.authorize(ctx, by, "APIKeys.Revoke")
	if err != nil {
		return err
	}
	if err := k.f.storage.Tokens.RevokeAPIKey(ctx, g.subject, id); err != nil {
		return err
	}
	emitFor(ctx, k.f, event.APIKeyRevoked, g.subject, "", audit.A(event.KeyKeyID, id.String()))
	return nil
}

// List returns the caller's keys that are neither revoked nor expired.
func (k *APIKeys) List(ctx context.Context, by principal.Caller) ([]APIKeyInfo, error) {
	g, err := k.authorize(ctx, by, "APIKeys.List")
	if err != nil {
		return nil, err
	}
	all, err := k.f.storage.Tokens.ListAPIKeys(ctx, g.subject)
	if err != nil {
		return nil, err
	}
	now := k.f.o.clock.Now()
	out := make([]APIKeyInfo, 0, len(all))
	for _, rec := range all {
		if !rec.RevokedAt.IsZero() || (!rec.ExpiresAt.IsZero() && !now.Before(rec.ExpiresAt)) || rec.Owner != g.subject {
			continue
		}
		grant, err := decodeAPIKeyGrant(rec.AppClaims)
		if err != nil {
			continue
		}
		out = append(out, infoOf(rec, grant.Roles, grant.Scopes, grant.Groups))
	}
	return out, nil
}

func (k *APIKeys) authorize(ctx context.Context, by principal.Caller, method string) (grant, error) {
	g, err := k.f.authorize(ctx, by, method, by.Tenant(), core.Subject{}, scopeSelf)
	if err != nil {
		return grant{}, err
	}
	if k.f.apiKeys == nil || !present(k.f.storage.Tokens) {
		return grant{}, errors.Join(ErrFacadeUnavailable, errors.New("egauth: Modules.APIKeys is nil"))
	}
	return g, nil
}

func (k *APIKeys) check(req APIKeyRequest) error {
	switch {
	case !slices.Contains(k.f.apiKeys.Kinds, req.Kind):
		return errors.Join(ErrInvalidRequest, errors.New("egauth: the API key kind is not in Modules.APIKeys.Kinds"))
	case len(req.Name) > tokens.MaxAPIKeyLabelLen || !printable(req.Name):
		return errors.Join(ErrInvalidRequest, errors.New("egauth: the API key name must be at most 128 bytes of printable UTF-8"))
	case !req.Lifetime.Valid():
		return errors.Join(ErrInvalidRequest, keys.ErrInvalidExpiry)
	}
	for _, list := range [][]string{req.Roles, req.Scopes, req.Groups} {
		if slices.Contains(list, "") {
			return errors.Join(ErrInvalidRequest, errors.New("egauth: a requested claim is empty"))
		}
	}
	return nil
}

func subset(requested, held []string) bool {
	for _, v := range requested {
		if !slices.Contains(held, v) {
			return false
		}
	}
	return true
}

func dedupe(in []string) []string {
	out := []string{}
	for _, v := range in {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func infoOf(rec tokens.APIKey, roles, scopes, groups []string) APIKeyInfo {
	return APIKeyInfo{
		ID: rec.ID, Kind: rec.Kind, Name: rec.Name, Owner: rec.Owner, Roles: slices.Clone(roles), Scopes: slices.Clone(scopes),
		Groups: slices.Clone(groups), CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt,
	}
}
