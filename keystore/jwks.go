package keystore

import "context"

// JWK is a single entry in a tenant's JSON Web Key Set. egauth signs with HS256 (a SYMMETRIC
// algorithm), so a JWK here is deliberately metadata-only: it carries the key id, algorithm and
// intended use, but NEVER the secret ("k") value.
//
// Publishing the symmetric secret in a public /.well-known/jwks.json would hand every verifier
// the power to MINT tokens — a critical vulnerability. So this JWKS is for internal introspection
// and operational tooling (which kids are live for a tenant), not for public distribution. A
// truly publishable JWKS requires asymmetric signing (RS256/EdDSA), which is deferred to a
// future task (see the Discussion in TASK-003 / road-to-v1 §1b). The shape is forward-compatible:
// asymmetric public-key fields can be added without breaking this contract.
type JWK struct {
	// Kty is the key type. For HS256 keys this is "oct" (symmetric octet sequence).
	Kty string `json:"kty"`
	// Use is the intended use: "sig" (signature).
	Use string `json:"use"`
	// Alg is the algorithm, "HS256".
	Alg string `json:"alg"`
	// Kid is the key id (the JWT "kid" header value).
	Kid string `json:"kid"`
	// Note: the symmetric secret ("k") is intentionally omitted — see the type doc.
}

// JWKSet is a tenant's JSON Web Key Set (metadata only — see JWK).
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKS returns the metadata-only JWK set for a tenant: one entry per currently-verifiable key
// (active plus retired-but-unexpired), describing kid/alg/use but NOT the secret. It is safe to
// expose to internal operators; it is NOT safe to publish publicly while signing is symmetric
// (see the JWK doc). tenantID "" is the single-tenant partition.
func (m *Manager) JWKS(ctx context.Context, tenantID string) (JWKSet, error) {
	keys, err := m.store.VerificationKeys(ctx, tenantID)
	if err != nil {
		return JWKSet{}, err
	}
	set := JWKSet{Keys: make([]JWK, 0, len(keys))}
	for kid := range keys {
		set.Keys = append(set.Keys, JWK{
			Kty: "oct",
			Use: "sig",
			Alg: "HS256",
			Kid: kid,
		})
	}
	return set, nil
}
