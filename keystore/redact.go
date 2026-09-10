package keystore

import (
	"fmt"
	"log/slog"
	"sort"
)

// redacted is the placeholder substituted for secret material in log/print output.
const redacted = "REDACTED"

// SigningKey carries the raw key material in the exported Secret field (a KEK-opened HMAC secret
// or the PKCS#8 DER of an asymmetric private key). A dumped key — log.Printf("%+v", key),
// slog.Any, or an accidental %v in an error path — would print the credential verbatim. The
// methods below make the common accidental-leak paths safe by default: fmt verbs
// (%v/%s/%+v/%#v) and slog (via slog.LogValuer) render Secret as a placeholder, while the
// non-secret metadata (KeyID, TenantID, Alg, timestamps) stays visible to aid debugging.
//
// NOTE: like the other key-bearing types, JSON marshalling is intentionally NOT redacted — the
// keystore backends write Secret explicitly through their own SQL/encoding paths. Treat Secret as
// a credential and never log or serialize a SigningKey.
func (k SigningKey) String() string {
	secret := redacted
	if len(k.Secret) == 0 {
		secret = "" // distinguish "unset" from "set-but-hidden" without leaking
	}
	return fmt.Sprintf(
		"SigningKey{KeyID:%s TenantID:%s Alg:%s Secret:%s CreatedAt:%s NotAfter:%s RetiredAt:%v}",
		k.KeyID, k.TenantID, k.Alg, secret, k.CreatedAt, k.NotAfter, k.RetiredAt,
	)
}

// GoString redacts the %#v representation.
func (k SigningKey) GoString() string { return k.String() }

// LogValue redacts the SigningKey for structured (slog) logging.
func (k SigningKey) LogValue() slog.Value {
	secret := redacted
	if len(k.Secret) == 0 {
		secret = ""
	}
	return slog.GroupValue(
		slog.String("key_id", k.KeyID),
		slog.String("tenant_id", k.TenantID),
		slog.String("alg", k.Alg),
		slog.String("secret", secret),
		slog.Time("created_at", k.CreatedAt),
		slog.Time("not_after", k.NotAfter),
	)
}

// String renders the Keyset with every SigningKey redacted (its Active key and Verify map values
// carry the same Secret field).
func (ks Keyset) String() string {
	ids := make([]string, 0, len(ks.Verify))
	for id := range ks.Verify {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return fmt.Sprintf("Keyset{TenantID:%s Active:%s VerifyKeyIDs:%v}", ks.TenantID, ks.Active, ids)
}

// GoString redacts the %#v representation.
func (ks Keyset) GoString() string { return ks.String() }

// LogValue redacts the Keyset for structured (slog) logging.
func (ks Keyset) LogValue() slog.Value {
	ids := make([]string, 0, len(ks.Verify))
	for id := range ks.Verify {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return slog.GroupValue(
		slog.String("tenant_id", ks.TenantID),
		slog.Any("active", ks.Active.LogValue()),
		slog.Any("verify_key_ids", ids),
	)
}
