package argon2_test

import (
	"context"
	"testing"

	argon2hasher "github.com/JLugagne/egauth/passwords/argon2"
)

// Timing-evidence benchmarks for the constant-time password-comparison claim
// (SECURITY.md "Constant-time password comparison").
//
// These benchmarks are EVIDENCE to be run and cited manually, NOT pass/fail
// gates. They deliberately contain no timing-threshold assertions: a wall-clock
// delta on a shared/noisy CI runner is not a sound oracle test and would be
// flaky. The real guarantee is structural (see the package source): Compare
// always reaches subtle.ConstantTimeCompare for any candidate whose stored hash
// is well-formed, and it never branches on the byte-wise outcome of the secret
// comparison.
//
// Run them with, e.g.:
//
//	go test -run=^$ -bench=BenchmarkCompare -benchmem ./passwords/argon2
//	go test -run=^$ -bench=BenchmarkCompare -benchmem -count=10 ./passwords/argon2 | tee old.txt
//	# ...then, after a change, compare with:
//	#   benchstat old.txt new.txt
//
// What to expect: BenchmarkCompare_CorrectPassword and
// BenchmarkCompare_WrongPassword should land within benchstat noise of each
// other — both run a full Argon2id pass and then a constant-time compare, so the
// wrong-password path costs the same as the correct one (no early-out on the
// comparison). BenchmarkCompare_MalformedHash is expected to be FASTER on
// purpose: a corrupt/forged stored hash is rejected before the KDF, and that is
// not a secret-dependent branch (it depends only on the stored hash's shape, not
// on the candidate password). The decoy-cost benchmarks document the one known
// residual: the decoy hashes at the CURRENT cost while a not-yet-rehashed
// account verifies at its OLD (stored) cost — see SECURITY.md
// "Residual enumeration timing after raising Argon2id cost".

// benchHasher builds a hasher at a fixed, low-but-valid cost so the benchmarks
// run quickly while still exercising the real KDF and constant-time compare.
func benchHasher() *argon2hasher.Hasher {
	return argon2hasher.NewHasher(
		argon2hasher.WithMemory(argon2hasher.MinMemoryKiB),
		argon2hasher.WithTime(1),
		argon2hasher.WithThreads(1),
	)
}

// BenchmarkCompare_CorrectPassword measures the success path: a full Argon2id
// pass followed by a matching constant-time comparison.
func BenchmarkCompare_CorrectPassword(b *testing.B) {
	ctx := context.Background()
	h := benchHasher()
	const password = "correct-horse-battery-staple"
	stored, err := h.Hash(ctx, password)
	if err != nil {
		b.Fatalf("Hash: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.Compare(ctx, stored, password)
	}
}

// BenchmarkCompare_WrongPassword measures the wrong-password path. It must be
// indistinguishable from the correct path: the same full Argon2id pass runs and
// the comparison is constant-time, so no byte-wise early-out shortens it. A
// benchstat-significant gap between this and BenchmarkCompare_CorrectPassword
// would indicate a regression in the constant-time guarantee.
func BenchmarkCompare_WrongPassword(b *testing.B) {
	ctx := context.Background()
	h := benchHasher()
	stored, err := h.Hash(ctx, "correct-horse-battery-staple")
	if err != nil {
		b.Fatalf("Hash: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.Compare(ctx, stored, "wrong-horse-battery-staple")
	}
}

// BenchmarkCompare_MalformedHash measures the corrupt/forged-stored-hash path.
// This is EXPECTED to be much faster than the two above: a malformed PHC string
// is rejected before the KDF. This is not a secret-dependent branch — it depends
// only on the shape of the STORED hash (untrusted DB input), never on the
// candidate password — so it does not leak anything about the password and is
// not part of the constant-time claim. It is benchmarked to make that asymmetry
// explicit and measurable rather than asserted.
func BenchmarkCompare_MalformedHash(b *testing.B) {
	ctx := context.Background()
	h := benchHasher()
	const malformed = "$argon2id$v=19$not-a-cost$bad$bad"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.Compare(ctx, malformed, "correct-horse-battery-staple")
	}
}

// BenchmarkDecoyGap_VerifyOldCost and BenchmarkDecoyGap_DecoyNewCost together
// quantify the documented residual enumeration channel: after an operator raises
// Argon2id cost, a not-yet-rehashed account verifies at the OLD (cheaper) stored
// cost, while an unknown account is decoy-hashed at the NEW (more expensive)
// current cost. The delta between these two benchmarks is the size of that
// residual oracle. It is evidence, not a gate; the mitigation is to rehash the
// fleet (see SECURITY.md). To keep the benchmark fast the "new" cost here is only
// modestly higher than the "old" cost; production deltas will be larger.
func BenchmarkDecoyGap_VerifyOldCost(b *testing.B) {
	ctx := context.Background()
	old := argon2hasher.NewHasher(
		argon2hasher.WithMemory(argon2hasher.MinMemoryKiB),
		argon2hasher.WithTime(1),
		argon2hasher.WithThreads(1),
	)
	const password = "correct-horse-battery-staple"
	oldHash, err := old.Hash(ctx, password)
	if err != nil {
		b.Fatalf("Hash: %v", err)
	}
	// The operator has since raised the configured cost; Compare still honours
	// the stored (old, cheaper) cost for this not-yet-rehashed account.
	target := argon2hasher.NewHasher(
		argon2hasher.WithMemory(2*argon2hasher.MinMemoryKiB),
		argon2hasher.WithTime(3),
		argon2hasher.WithThreads(2),
	)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = target.Compare(ctx, oldHash, password)
	}
}

// BenchmarkDecoyGap_DecoyNewCost measures the decoy path an unknown account
// would take under the raised cost: Hash at the current (new, more expensive)
// parameters. Compare against BenchmarkDecoyGap_VerifyOldCost to size the
// residual timing gap.
func BenchmarkDecoyGap_DecoyNewCost(b *testing.B) {
	ctx := context.Background()
	target := argon2hasher.NewHasher(
		argon2hasher.WithMemory(2*argon2hasher.MinMemoryKiB),
		argon2hasher.WithTime(3),
		argon2hasher.WithThreads(2),
	)
	const password = "correct-horse-battery-staple"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = target.Hash(ctx, password)
	}
}
