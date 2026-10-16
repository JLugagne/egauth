// Package egauth is a misuse-resistant authentication library for Go. A deployment is one validated
// composition object, built by New from one Config, and the application's own routes are declared
// through Auth.Routes, a deny-by-default builder. No handler, cookie, issuer, limiter or gate is
// wired by hand, so no two of them can disagree.
//
// # Composition
//
// New checks the whole configuration at once and returns every problem joined: required fields,
// bounds, module dependencies, origins, store durability, the key-encryption key against existing
// data, the limiter, and any v0.16 secret that has not been upgraded. It never answers "misconfigured"
// at request time. The returned Auth owns every policy object, store handle and background worker
// until Close.
//
// Config.Modules enables features: Password, MagicLink, LoginCode, Passkey, OAuth, External, MFA,
// Verification, SelfDelete and APIKeys. A nil module is off, and at least one primary module is
// required. Config.Storage comes from memstore.New for tests and development, or from
// pgxstore.New in the adapters/pgx module for production.
//
// # Routes
//
// Auth.Routes returns a builder. Protect serves an established human session, Optional serves
// everyone and presents a caller that fails a Protect gate as anonymous, ProtectAPI serves API keys
// of declared kinds, and Public serves everyone. Build returns the handler to serve at the server
// root: it mounts the auth endpoints under Config.BasePath and answers 404 to every request that is
// not declared. Handlers receive a Principal as an argument; it is never read from context.
//
// # Sessions
//
// What a login proved is minted once, sealed, stored on every artefact and replayed: later steps
// can add a factor, never re-derive one. Multi-factor enrollment is read from stored state, so
// configuration cannot lower the floor. Revocation is derived from a per-subject security epoch,
// which the stores bump atomically with every security mutation.
//
// # Opting out
//
// Every weakening of a default lives in InsecureOptOuts, needs a written reason, and is listed by
// Auth.Posture. Nothing else loosens a gate.
//
// # Packages
//
//	memstore    in-memory Storage for tests and single-instance development
//	kek         key-encryption keys that seal secrets at rest, with mandatory associated data
//	signing     JWT signers and verifiers, and JWKS encoding
//	principal   the Subject, Caller, TenantID and Factor values shared with applications
//	event       the security-event Sink seam (slog and OpenTelemetry adapters)
//	passwords   password hashing, policy and breach-check seams, with Argon2id references
//	federation  identity-provider specs, with 12 built-in providers in federation/providers
//	store       store contracts, each with memory and pgx implementations and a contract suite
//	egauthtest  test doubles: clock, mailbox, identity provider, principals
//	webauthntest a software WebAuthn authenticator for passkey tests
//
// # Security and stability
//
// The threat model, the secret-handling model and the consumer responsibilities are in SECURITY.md;
// the quick start is in README.md. The API is pre-1.0 and still settling; pin a tag in go.mod for
// reproducible builds.
//
// Audit status: egauth's security review to date is an AI-driven audit only; it has not had an
// independent third-party human security audit, and that risk is accepted for v1.0 — pin a
// reviewed commit, commission your own audit, or wait if that trade-off is unacceptable.
// "AI-audited" is not a synonym for "audited". See AUDIT.md for the full review scope and the
// cautious-user escape hatch.
package egauth
