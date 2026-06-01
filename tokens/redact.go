package tokens

import (
	"fmt"
	"log/slog"
)

// redacted is the placeholder substituted for secret material in log/print output.
const redacted = "REDACTED"

// TokenPair, APIKey carry live credentials in exported string fields. The methods below make
// the common accidental-leak paths safe by default: fmt verbs (%v/%s/%#v), and slog (via
// slog.LogValuer) never render the plaintext access/refresh token or API key.
//
// NOTE: JSON marshalling is intentionally NOT redacted — returning the freshly issued tokens
// to the client in a response body is a legitimate use. If you log or persist these structs,
// rely on the redaction here; if you serialize them, send them only to the authenticated
// owner over TLS (see SECURITY.md).

// String renders the pair with its access and refresh tokens redacted.
func (tp TokenPair[C]) String() string {
	return fmt.Sprintf("TokenPair{AccessToken:%s RefreshToken:%s RefreshTokenHash:%s AccessTokenExpiresAt:%s RefreshTokenExpiresAt:%s}",
		redacted, redacted, tp.RefreshTokenHash, tp.AccessTokenExpiresAt, tp.RefreshTokenExpiresAt)
}

// GoString redacts the %#v representation.
func (tp TokenPair[C]) GoString() string { return tp.String() }

// LogValue redacts the token pair for structured (slog) logging.
func (tp TokenPair[C]) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("access_token", redacted),
		slog.String("refresh_token", redacted),
		slog.Time("access_token_expires_at", tp.AccessTokenExpiresAt),
		slog.Time("refresh_token_expires_at", tp.RefreshTokenExpiresAt),
	)
}

// String renders the API key with its clear-text token redacted (the prefix and hash are not
// secret and are kept to aid identification).
func (k APIKey[C]) String() string {
	return fmt.Sprintf("APIKey{ID:%s TenantID:%s Prefix:%s Token:%s Hash:%s}",
		k.ID, k.TenantID, k.Prefix, redacted, k.Hash)
}

// GoString redacts the %#v representation.
func (k APIKey[C]) GoString() string { return k.String() }

// LogValue redacts the API key for structured (slog) logging.
func (k APIKey[C]) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", k.ID.String()),
		slog.String("prefix", k.Prefix),
		slog.String("token", redacted),
		slog.String("hash", k.Hash),
	)
}
