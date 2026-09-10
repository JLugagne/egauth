// Package passwords defines egauth's password seams — Hasher (hash and constant-time compare),
// Policy (validate a candidate password), and BreachChecker (k-anonymity breach lookup) — plus
// the shared error sentinels and the MaxPasswordLength pre-hash DoS cap. The interfaces live
// here; the implementations live in subpackages so you depend only on what you use.
//
// # Composable by design
//
// Like the rest of egauth (see the database/sql-style note in package identity), passwords is a
// seam, not a framework. identity.NewService takes a passwords.Hasher and passwords.Policy, so you
// plug in the shipped references or your own:
//
//   - passwords/argon2 — Argon2id Hasher (PHC string, crypto/rand salt, constant-time compare).
//     The recommended default.
//   - passwords/policy — DefaultPolicy (character-class rules) and PassphrasePolicy (length-first,
//     with a denylist and an optional BreachChecker).
//   - passwords/breach — BreachChecker implementations: hibp (HaveIBeenPwned range API,
//     k-anonymity — only a 5-char hash prefix leaves the process) and offline (a local blocklist).
//
// # Wiring
//
//	hasher := argon2.NewHasher()
//	pol := policy.NewDefaultPolicy()                    // or policy.NewPassphrasePolicy(...)
//	svc := identity.NewService(store, hasher, pol)
//
// # Security posture
//
// Hash and Compare reject input longer than MaxPasswordLength before the KDF runs, so an attacker
// cannot amplify a login into a multi-megabyte argon2 computation. Length is measured in runes by
// the policies, so a multibyte password is neither under-counted nor over-restricted. See
// SECURITY.md.
//
// # Stability
//
// Stability class: frozen-v1 candidate. The exported API is intended to remain
// backward-compatible for the life of v1; breaking changes require a new major version. Until v1
// is tagged the API remains pre-1.0. See docs/adr/0001-v1-scope-and-stability-classes.md.
package passwords
