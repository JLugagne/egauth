package webapp

import (
	"fmt"
	"log/slog"
)

// redacted is the placeholder substituted for secret material in log/print output.
const redacted = "REDACTED"

// Config carries the HS256 SigningKey in an exported string field, and is exactly the value a
// consumer assembles and dumps at startup (log.Printf("%+v", cfg), structured logging). The
// methods below keep the accidental-leak paths safe by default: fmt verbs (%v/%s/%+v/%#v) and
// slog (via slog.LogValuer) render the signing key as a placeholder while the non-secret
// identifying fields (Issuer, Tenant, TTLs, routes) stay visible to aid debugging.
//
// NOTE: like the tokens/jwt redaction, JSON marshalling is intentionally NOT redacted (Config has
// no json tags and is never serialized by egauth). Treat the signing key as a credential: load it
// from a secret store and never log or serialize Config. See SECURITY.md.

// String renders the Config with the SigningKey redacted and no dependency object dumps.
func (cfg Config) String() string {
	signingKey := redacted
	if cfg.SigningKey == "" {
		signingKey = "" // distinguish "unset" from "set-but-hidden" without leaking
	}
	return fmt.Sprintf(
		"Config{Issuer:%s Tenant:%s SigningKey:%s AccessTTL:%s RefreshTTL:%s CookieDomain:%s "+
			"TrustedOrigins:%v InsecureNoOriginCheck:%t InsecureNoRateLimit:%t RateLimiterSet:%t "+
			"IdentitySet:%t TokenStoreSet:%t EventSinkSet:%t Routes:%v}",
		cfg.Issuer, cfg.Tenant, signingKey, cfg.AccessTTL, cfg.RefreshTTL, cfg.CookieDomain,
		cfg.TrustedOrigins, cfg.InsecureNoOriginCheck, cfg.InsecureNoRateLimit, cfg.RateLimiter != nil,
		cfg.Identity != nil, cfg.TokenStore != nil, cfg.EventSink != nil, cfg.Routes,
	)
}

// GoString redacts the %#v representation.
func (cfg Config) GoString() string { return cfg.String() }

// LogValue redacts the Config for structured (slog) logging.
func (cfg Config) LogValue() slog.Value {
	signingKey := redacted
	if cfg.SigningKey == "" {
		signingKey = ""
	}
	return slog.GroupValue(
		slog.String("issuer", cfg.Issuer),
		slog.String("tenant", cfg.Tenant),
		slog.String("signing_key", signingKey),
		slog.Duration("access_ttl", cfg.AccessTTL),
		slog.Duration("refresh_ttl", cfg.RefreshTTL),
		slog.String("cookie_domain", cfg.CookieDomain),
		slog.Any("trusted_origins", cfg.TrustedOrigins),
		slog.Bool("insecure_no_origin_check", cfg.InsecureNoOriginCheck),
		slog.Bool("insecure_no_rate_limit", cfg.InsecureNoRateLimit),
		slog.Bool("rate_limiter_set", cfg.RateLimiter != nil),
	)
}
