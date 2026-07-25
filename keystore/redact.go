package keystore

import (
	"fmt"
	"log/slog"
)

// redacted is the placeholder substituted for secret material in log/print output. It matches the
// placeholder used by tokens/redact.go so a deployment greps for one token.
const redacted = "REDACTED"

// SigningKey.Secret holds LIVE key material once the Manager has opened it: the raw HMAC secret for
// HS256, or the PKCS#8 DER of the private key for an asymmetric alg. The methods below make the
// common accidental-leak paths safe by default — fmt verbs (%v/%+v/%s/%#v) and slog (via
// slog.LogValuer) render a placeholder instead of the material. Everything else about the key (its
// id, tenant, alg and lifecycle timestamps) is not secret and stays visible so logs remain useful.
//
// NOTE: like tokens/redact.go this deliberately does NOT touch JSON marshalling; a Store backend
// that persists the SEALED form is a legitimate serializer.

// String renders the key with its material redacted.
func (k SigningKey) String() string {
	retired := "<nil>"
	if k.RetiredAt != nil {
		retired = k.RetiredAt.String()
	}
	return fmt.Sprintf("SigningKey{KeyID:%s TenantID:%s Alg:%s Secret:%s CreatedAt:%s NotAfter:%s RetiredAt:%s}",
		k.KeyID, k.TenantID, k.Alg, redacted, k.CreatedAt, k.NotAfter, retired)
}

// GoString redacts the %#v representation.
func (k SigningKey) GoString() string { return k.String() }

// LogValue redacts the key material for structured (slog) logging.
func (k SigningKey) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("key_id", k.KeyID),
		slog.String("tenant_id", k.TenantID),
		slog.String("alg", k.Alg),
		slog.String("secret", redacted),
		slog.Time("created_at", k.CreatedAt),
		slog.Time("not_after", k.NotAfter),
	)
}
