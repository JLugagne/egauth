package identity_test

import (
	"context"
	"testing"

	"github.com/JLugagne/egauth/identity"
	identitymemory "github.com/JLugagne/egauth/identity/memory"
	argon2hasher "github.com/JLugagne/egauth/passwords/argon2"
)

// Timing-evidence benchmarks for the constant-time authentication claim
// (SECURITY.md "Constant-time authentication paths").
//
// These benchmarks are EVIDENCE to run and cite manually, NOT pass/fail gates.
// They contain no timing-threshold assertions: a wall-clock delta on a noisy
// runner is not a sound oracle test. The real guarantee is structural — every
// enumeration-safe failure path in Authenticate (unknown user, unknown identity,
// identity with no password hash, non-password provider, malformed email) calls
// decoyHash, which runs a full Argon2id pass via hasher.Hash, mirroring the cost
// of the real Compare on the success/wrong-password path.
//
// Run them with, e.g.:
//
//	go test -run=^$ -bench=BenchmarkAuthenticate -benchmem ./identity
//	go test -run=^$ -bench=BenchmarkAuthenticate -benchmem -count=10 ./identity | tee old.txt
//	# then, after a change:  benchstat old.txt new.txt
//
// What to expect: BenchmarkAuthenticate_ValidUser_WrongPassword (real Compare),
// BenchmarkAuthenticate_UnknownUser (decoy hash) and
// BenchmarkAuthenticate_IdentityNoPasswordHash (decoy hash) should all land
// within benchstat noise of one another — each spends one full Argon2id pass.
// A benchstat-significant gap between the unknown-user path and the wrong-
// password path would indicate the decoy defence has regressed (e.g. a path that
// skips decoyHash), reopening a user-enumeration timing oracle.

// benchAuthService wires the real Argon2id hasher (so the decoy and the real
// compare cost the same) at a low-but-valid cost for benchmark speed, seeds one
// registered account, and returns the service plus that account's email.
func benchAuthService(b *testing.B) (identity.Service, string) {
	b.Helper()
	ctx := context.Background()
	hasher := argon2hasher.NewHasher(
		argon2hasher.WithMemory(argon2hasher.MinMemoryKiB),
		argon2hasher.WithTime(1),
		argon2hasher.WithThreads(1),
	)
	policy := &mockPolicy{VerifyFunc: func(context.Context, string) error { return nil }}
	// WithNoLockout: the valid-user benchmark replays the same wrong password
	// thousands of times against one account. With the default lockout
	// (DefaultLockThreshold=5) the account would lock after the 5th iteration and
	// every later iteration would return ErrAccountLocked BEFORE hasher.Compare
	// runs — skipping the Argon2id pass entirely and making the benchmark measure
	// the lockout short-circuit (~0.5 MB / sub-millisecond) instead of the verify
	// path. Disabling lockout keeps every iteration on the real Compare path so
	// the number is comparable to the decoy-hash (unknown-user) path. This is a
	// benchmark-fixture concern only; lockout stays ON by default in production.
	svc := identity.NewService(identitymemory.NewStore(), hasher, policy, identity.WithNoLockout())

	const email = "registered@example.com"
	const password = "correct-horse-battery-staple"
	if _, err := svc.Register(ctx, "t1", email, password); err != nil {
		b.Fatalf("Register: %v", err)
	}
	return svc, email
}

// BenchmarkAuthenticate_ValidUser_WrongPassword measures the real verify path:
// the account exists, so Authenticate runs hasher.Compare (a full Argon2id pass
// plus a constant-time comparison) and rejects the wrong password.
func BenchmarkAuthenticate_ValidUser_WrongPassword(b *testing.B) {
	ctx := context.Background()
	svc, email := benchAuthService(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.Authenticate(ctx, "t1", "password", email, "wrong-password")
	}
}

// BenchmarkAuthenticate_UnknownUser measures the enumeration-safe path for an
// account that does not exist: FindUserByEmail fails, decoyHash runs a full
// Argon2id pass, and the response is the same uniform ErrInvalidCredentials.
// Compare against BenchmarkAuthenticate_ValidUser_WrongPassword: the gap is the
// residual enumeration signal, which should be within benchstat noise.
func BenchmarkAuthenticate_UnknownUser(b *testing.B) {
	ctx := context.Background()
	svc, _ := benchAuthService(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.Authenticate(ctx, "t1", "password", "ghost@example.com", "wrong-password")
	}
}

// BenchmarkAuthenticate_NonPasswordProvider measures the other decoy path:
// credential login attempted against a non-"password" provider. It must also
// spend a decoy hash so it is indistinguishable by timing from a wrong-password
// failure on the password path.
func BenchmarkAuthenticate_NonPasswordProvider(b *testing.B) {
	ctx := context.Background()
	svc, _ := benchAuthService(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = svc.Authenticate(ctx, "t1", "google", "someone@example.com", "wrong-password")
	}
}
