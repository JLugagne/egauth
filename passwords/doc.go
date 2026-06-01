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
package passwords
