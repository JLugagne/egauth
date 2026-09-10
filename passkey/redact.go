package passkey

import (
	"fmt"
	"log/slog"
)

// redacted is the placeholder substituted for secret material in log/print output.
const redacted = "REDACTED"

// Config carries the ceremony-cookie HMAC key in an exported []byte field. Dumping the config
// (log.Printf("%+v", cfg), slog.Any) would print the key and let anyone forge ceremony cookies.
// The methods below make the common accidental-leak paths safe by default: fmt verbs
// (%v/%s/%+v/%#v) and slog (via slog.LogValuer) render CookieKey as a placeholder, while the
// non-secret relying-party settings stay visible to aid debugging.
//
// NOTE: like the other key-bearing types, JSON marshalling is intentionally NOT redacted (Config
// has no json tags and is never serialized by egauth). Load CookieKey from a secret store and
// never log or serialize Config. See SECURITY.md.

// String renders the Config with CookieKey redacted and no dependency object dumps.
func (cfg Config) String() string {
	return fmt.Sprintf(
		"Config{RPID:%s RPDisplayName:%s RPOrigins:%v UserVerification:%s CookieKey:%s "+
			"ChallengeStoreSet:%t InsecureNoChallengeStore:%t EventsSet:%t AccountGateSet:%t "+
			"Attestation:%s}",
		cfg.RPID, cfg.RPDisplayName, cfg.RPOrigins, cfg.UserVerification, redacted,
		cfg.ChallengeStore != nil, cfg.InsecureNoChallengeStore, cfg.Events != nil, cfg.AccountGate != nil,
		cfg.Attestation,
	)
}

// GoString redacts the %#v representation.
func (cfg Config) GoString() string { return cfg.String() }

// LogValue redacts the Config for structured (slog) logging.
func (cfg Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("rp_id", cfg.RPID),
		slog.String("rp_display_name", cfg.RPDisplayName),
		slog.Any("rp_origins", cfg.RPOrigins),
		slog.String("user_verification", string(cfg.UserVerification)),
		slog.String("cookie_key", redacted),
		slog.Bool("challenge_store_set", cfg.ChallengeStore != nil),
		slog.Bool("insecure_no_challenge_store", cfg.InsecureNoChallengeStore),
	)
}

// String renders the attestation policy without dumping the optional MDS provider. It contains no
// secret material, so its identifying fields stay visible.
func (a AttestationConfig) String() string {
	return fmt.Sprintf(
		"AttestationConfig{ConveyancePreference:%s PermittedAAGUIDs:%v ProhibitedAAGUIDs:%v "+
			"ProhibitBackupEligibility:%t MDSSet:%t}",
		a.ConveyancePreference, a.PermittedAAGUIDs, a.ProhibitedAAGUIDs, a.ProhibitBackupEligibility,
		a.MDS != nil,
	)
}
