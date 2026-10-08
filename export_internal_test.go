package egauth

import (
	"github.com/JLugagne/egauth/internal/configcheck"
	"github.com/JLugagne/egauth/principal"
)

func ConfigOptions[C any](cfg Config[C]) configcheck.Options {
	cfg = snapshot(cfg)
	return configOptions(&cfg)
}

func Resolve[C any](cfg Config[C]) (*configcheck.Resolved, []*configcheck.Error) {
	cfg = snapshot(cfg)
	return configcheck.Validate(&cfg, configOptions(&cfg))
}

func NewSessionPrincipal[C any](a principal.SessionAttrs, claims AppClaims[C]) (Principal[C], error) {
	return sessionPrincipal(a, claims)
}

func NewAPIKeyPrincipal[C any](info APIKeyInfo, claims AppClaims[C]) (Principal[C], error) {
	return apiKeyPrincipal(info, claims)
}

const LongSessionsMax = longSessionsMax

func ConfigOf[C any](a *Auth[C]) Config[C] {
	return a.cfg
}
