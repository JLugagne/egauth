// Package tokens is egauth's stateless-token module: JWT access tokens plus single-use refresh
// tokens with rotation, family-based reuse/theft detection, and long-lived API keys. It defines
// the seams (Issuer, Verifier, Rotator, Store) that the credential modules issue against; the
// JWT reference implementation lives in tokens/jwt.
//
// # Composable by design
//
// Like the rest of egauth (see the database/sql-style note in package identity), tokens is an
// independent module you wire by dependency injection. identity.LoginHandler and friends take a
// tokens.Issuer, so the same login flow works against any token backend. Choose this module for
// stateless, horizontally-scalable auth (no session lookup on every request); choose the sessions
// module instead — or alongside — when you want server-side revocable sessions. The generic
// parameter C is your application's custom claims type (use struct{} when you need none).
//
// # Wiring
//
//	issuer := jwt.New[struct{}](jwt.Config[struct{}]{
//	    Store:          memory.NewStore[struct{}](),   // tokens/memory; or tokens/pgx.NewStore(pool)
//	    Issuer:         "my-app",
//	    SecretKey:      hs256SecretFromYourSecretStore, // >= 32 bytes
//	    AccessTTL:      15 * time.Minute,
//	    RefreshTTL:     720 * time.Hour,
//	    ClaimsProvider: claimsProvider,                 // required for Rotate (refresh)
//	})
//	pair, err := issuer.IssueTokenPair(ctx, tokens.Claims[struct{}]{Subject: userID, TenantID: tenantID})
//	// ... later, refresh:
//	next, err := issuer.Rotate(ctx, tenantID, pair.RefreshToken)
//
// jwt.New panics on an unusable signing key (fail-fast at startup): an empty key, a key shorter
// than jwt.MinSecretKeyLength (32 bytes), or a malformed keyset. See the package examples for a
// full login + refresh wiring.
//
// # HTTP handlers and middleware
//
// RefreshHandler and LogoutHandler are mountable http.HandlerFunc factories; RequireAuth is the
// access-token-verifying middleware (with optional WithRequiredAMR / WithMaxAuthAge step-up gates).
//
// # Security posture
//
// Refresh rotation within a family with reuse/theft detection (a replayed consumed token revokes
// the whole family), HS256 alg-pinning (rejects "none"/alg-confusion), kid-tagged signing-key
// rotation with overlapping validity, and secret-at-rest as SHA-256 hashes only. Credential-bearing
// types (TokenPair, APIKey) and the signing config (jwt.Config, SigningKey, Service) redact their
// secrets on fmt/slog. See SECURITY.md.
package tokens
