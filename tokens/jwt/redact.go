package jwt

import (
	"fmt"
	"log/slog"
	"sort"
)

// Config and SigningKey carry the HS256 signing secret(s) in exported string fields, and
// Config is the value a consumer assembles and passes to New — exactly the kind of struct that
// gets dumped at startup (log.Printf("%+v", cfg), structured logging, JSON). The methods below
// make the common accidental-leak paths safe by default: fmt verbs (%v/%s/%+v/%#v) and slog
// (via slog.LogValuer) render the signing secrets as a placeholder, never in clear, while the
// non-secret identifying fields (Issuer, key IDs, TTLs) stay visible to aid debugging.
//
// NOTE: like tokens.TokenPair/APIKey, JSON marshalling is intentionally NOT redacted — Config is
// never serialized by egauth, and a redacting MarshalJSON would silently corrupt a consumer who
// (ill-advisedly) round-trips it. Treat the signing secret as a credential: never log or
// serialize Config; load the key from your secret store. See SECURITY.md.

const redactedKey = "REDACTED"

// String renders the signing key with its secret redacted (the KeyID is not secret and is kept
// to aid identification).
func (k SigningKey) String() string {
	return fmt.Sprintf("SigningKey{KeyID:%s Secret:%s}", k.KeyID, redactedKey)
}

// GoString redacts the %#v representation.
func (k SigningKey) GoString() string { return k.String() }

// LogValue redacts the signing key for structured (slog) logging.
func (k SigningKey) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("key_id", k.KeyID),
		slog.String("secret", redactedKey),
	)
}

// String renders the Config with every HS256 signing secret redacted. The single-mode SecretKey
// and each rotation SigningKey.Secret are masked; non-secret fields (Issuer, ActiveKeyID, the
// key IDs, TTLs and tuning) are shown.
func (cfg Config[C]) String() string {
	secretKey := redactedKey
	if cfg.SecretKey == "" {
		secretKey = "" // distinguish "unset" from "set-but-hidden" without leaking length
	}
	keyIDs := make([]string, len(cfg.SigningKeys))
	for i, k := range cfg.SigningKeys {
		keyIDs[i] = k.KeyID
	}
	return fmt.Sprintf(
		"Config{Issuer:%s SecretKey:%s SigningKeys:%v ActiveKeyID:%s AccessTTL:%s RefreshTTL:%s "+
			"RefreshLength:%d APIKeyLength:%d ReuseGracePeriod:%s StoreSet:%t ClaimsProviderSet:%t "+
			"EventSinkSet:%t ClockSet:%t}",
		cfg.Issuer, secretKey, keyIDs, cfg.ActiveKeyID, cfg.AccessTTL, cfg.RefreshTTL,
		cfg.RefreshLength, cfg.APIKeyLength, cfg.ReuseGracePeriod,
		cfg.Store != nil, cfg.ClaimsProvider != nil, cfg.EventSink != nil, cfg.Clock != nil,
	)
}

// GoString redacts the %#v representation.
func (cfg Config[C]) GoString() string { return cfg.String() }

// LogValue redacts the Config for structured (slog) logging.
func (cfg Config[C]) LogValue() slog.Value {
	secretKey := redactedKey
	if cfg.SecretKey == "" {
		secretKey = ""
	}
	keys := make([]slog.Value, len(cfg.SigningKeys))
	for i, k := range cfg.SigningKeys {
		keys[i] = k.LogValue()
	}
	return slog.GroupValue(
		slog.String("issuer", cfg.Issuer),
		slog.String("secret_key", secretKey),
		slog.Any("signing_keys", keys),
		slog.String("active_key_id", cfg.ActiveKeyID),
		slog.Duration("access_ttl", cfg.AccessTTL),
		slog.Duration("refresh_ttl", cfg.RefreshTTL),
	)
}

// String renders the running Service with all key material redacted. The Service holds the
// resolved HS256 key bytes in unexported fields, which fmt would otherwise dump verbatim (as a
// byte slice) for %v/%+v/%#v; this keeps those paths safe.
func (s *Service[C]) String() string {
	keyIDs := make([]string, 0, len(s.verifySigners))
	for kid := range s.verifySigners {
		keyIDs = append(keyIDs, kid)
	}
	sort.Strings(keyIDs)
	return fmt.Sprintf(
		"jwt.Service{Issuer:%s SigningKeyID:%s VerifyKeyIDs:%v SigningKey:%s LegacyKey:%s "+
			"AccessTTL:%s RefreshTTL:%s}",
		s.issuer, s.signingKeyID, keyIDs, redactedKey, redactedKey, s.accessTTL, s.refreshTTL,
	)
}

// GoString redacts the %#v representation.
func (s *Service[C]) GoString() string { return s.String() }

// LogValue redacts the Service for structured (slog) logging.
func (s *Service[C]) LogValue() slog.Value {
	keyIDs := make([]string, 0, len(s.verifySigners))
	for kid := range s.verifySigners {
		keyIDs = append(keyIDs, kid)
	}
	sort.Strings(keyIDs)
	return slog.GroupValue(
		slog.String("issuer", s.issuer),
		slog.String("signing_key_id", s.signingKeyID),
		slog.Any("verify_key_ids", keyIDs),
		slog.String("signing_key", redactedKey),
		slog.String("legacy_key", redactedKey),
	)
}
