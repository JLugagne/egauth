// Package egauth is a composable authentication toolkit for Go: a set of independent modules you
// import à la carte and wire together yourself, in the style of the standard library's
// database/sql — rather than a framework that owns your HTTP router, your database access, or your
// conventions. The root package itself is deliberately tiny: it exports only Actor, the explicit
// authenticated-principal value passed to handlers (never smuggled through context.Context). All
// behavior lives in the sub-packages below.
//
// # Modules
//
//	identity   Accounts & credentials: register, login (Authenticate), password reset, email
//	           verification, magic-link login, change-password / change-email, phone verification,
//	           an independent recovery channel, account deletion, and OAuth identity linking.
//	tokens     Stateless JWT access tokens + single-use refresh tokens with rotation and theft
//	           detection, plus API keys. Reference implementation in tokens/jwt.
//	sessions   Server-side, revocable sessions with idle-timeout (Touch) and fixation defense
//	           (Rotate).
//	passwords  Hashing / policy / breach-check seams plus references: passwords/argon2,
//	           passwords/policy, passwords/breach/hibp, passwords/breach/offline.
//	mfa        TOTP (RFC 6238) with recovery codes. (SMS is intentionally excluded as a factor.)
//	otp        One-time codes (email/SMS), with enumeration-safe HTTP handlers.
//	passkey    WebAuthn / passkeys, including discoverable (usernameless) login.
//	oauth      OAuth2 / OIDC with PKCE-S256 and id_token/nonce/JWKS; ready-made providers
//	           (Google, GitHub, Microsoft, Apple, Okta, Auth0, ...) live in oauth/providers.
//	delivery   Optional reference SMTP mailer, template renderer, OTP sender and SMS phone-verifier.
//	ratelimit  Pluggable rate-limiting Limiter + token-bucket reference + middleware.
//	event      Dependency-free security-event Sink seam (audit logging, slog adapter).
//	health     Optional Store Ping/readiness seam.
//
// # Composable by design
//
// There is no top-level constructor that bundles everything, and that is intentional: each module
// has its own Service interface, its own Store contract (with in-memory and pgx backends behind a
// shared cross-backend conformance suite), and functional-option dependency injection. You compose
// exactly the stack you need. A typical password-login deployment wires identity (verifies
// credentials and manages the account lifecycle) with tokens (issues the access/refresh pair) —
// identity never issues tokens or sessions itself, so you pick the token backend that fits.
//
//	idStore := identitymem.NewStore()                          // or identity/pgx.NewStore(pool)
//	idSvc := identity.NewService(idStore, argon2.NewHasher(), policy.NewDefaultPolicy())
//
//	tkStore := tokensmem.NewStore()                            // or tokens/pgx.NewStore(pool)
//	issuer := jwt.New(jwt.Config{SecretKey: secret}, tkStore)  // tokens/jwt reference issuer
//
//	user, _ := idSvc.Register(ctx, tenantID, email, password)
//	pair, _ := issuer.Issue(ctx, tenantID, tokens.Claims[MyClaims]{Subject: user.ID.String()})
//
// The complete, runnable login + refresh wiring (including the HTTP handlers) lives in the
// identity package's example tests — see Example, ExampleNewSingleTenant and ExampleLoginHandler.
//
// # Multi-tenancy
//
// Multi-tenancy is explicit and pervasive: every Store and Service operation takes a tenantID
// string. The empty string is the valid single-tenant default partition, so a single-tenant
// application simply passes "" — or wraps a Service in that module's SingleTenant facade
// (e.g. identity.NewSingleTenant) to drop the argument from every call.
//
// # Security and stability
//
// egauth is security-literate by default (Argon2id, enumeration-resistant auth paths, refresh
// rotation with theft detection, alg-pinned JWTs, secure-by-default cookies, pre-auth body caps).
// The full threat model is in SECURITY.md; the module overview and a copy-pasteable quickstart are
// in README.md. The API is pre-1.0 and still settling; pin a commit or tag in go.mod for
// reproducible builds (see the Stability section of README.md).
package egauth
