package federationsvc

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/JLugagne/egauth/federation"
	"github.com/JLugagne/egauth/internal/core"
	"github.com/JLugagne/egauth/internal/routes"
	"github.com/JLugagne/egauth/internal/sealing"
	"github.com/JLugagne/egauth/store"
	storefed "github.com/JLugagne/egauth/store/federation"
)

type resolved struct {
	spec      federation.Provider
	client    doer
	scope     string
	authority string
}

func (s *Service) provider(ctx context.Context, t core.TenantID, name string) (resolved, error) {
	if p, ok := s.static[name]; ok {
		return resolved{spec: p, client: s.http.static, scope: storefed.StaticAuthority, authority: storefed.StaticAuthority}, nil
	}
	if !s.perTenant || name == "" {
		return resolved{}, ErrUnknownProvider
	}
	spec, err := s.federation.GetProvider(ctx, t, name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return resolved{}, ErrUnknownProvider
	case err != nil:
		return resolved{}, unavailable(err)
	case spec.Tenant != t || spec.Name != name || spec.AADVersion != storefed.AADVersionCurrent:
		return resolved{}, unavailable(errors.New("federationsvc: provider row of another tenant or format"))
	}
	secret, err := s.openSecret(ctx, spec)
	if err != nil {
		return resolved{}, unavailable(err)
	}
	p, err := federation.FromStore(spec, federation.NewSecret(secret))
	if err != nil {
		return resolved{}, unavailable(err)
	}
	if err := p.Complete(); err != nil {
		return resolved{}, unavailable(err)
	}
	return resolved{spec: p, client: s.http.tenant, scope: "tenant:" + t.String(), authority: storefed.RuntimeAuthority(spec)}, nil
}

func (s *Service) openSecret(ctx context.Context, spec storefed.ProviderSpec) (string, error) {
	if len(spec.SealedSecret) == 0 {
		return "", nil
	}
	ref, err := sealing.OAuthClientSecret(spec.Tenant, spec.Name)
	if err != nil {
		return "", err
	}
	opened, err := sealing.Open(ctx, s.kek, ref, spec.SealedSecret)
	if err != nil {
		return "", err
	}
	if opened.Stale {
		if resealed, err := sealing.Seal(ctx, s.kek, ref, opened.Plaintext); err == nil {
			_, _ = s.federation.ReplaceSealed(ctx, storefed.Reseal{
				Ref: storefed.SealedRef{Tenant: spec.Tenant, Provider: spec.Name}, Old: spec.SealedSecret, New: resealed,
			})
		}
	}
	return string(opened.Plaintext), nil
}

func (s *Service) redirectURI(t core.TenantID, provider string) (string, error) {
	raw, err := s.origins.PublicOrigin(t)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", errors.Join(errors.New("federationsvc: public origin is not an origin"), err)
	}
	return u.Scheme + "://" + u.Host + s.basePath + strings.Replace(routes.OAuthCallback, "{provider}", url.PathEscape(provider), 1), nil
}
