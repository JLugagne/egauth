package passkey

import "context"

// CookieKeyResolver returns the ceremony-cookie HMAC key to use for a given tenant. It is the seam
// that makes the passkey ceremony cookie tenant-scoped: see WithTenantCookieKeys. tenantID is the
// empty string for the single-tenant partition. Implementations must return a stable, random secret
// of at least MinCookieKeyLength bytes; returning an error fails the request closed rather than
// falling back to a shared key.
type CookieKeyResolver func(ctx context.Context, tenantID string) ([]byte, error)
