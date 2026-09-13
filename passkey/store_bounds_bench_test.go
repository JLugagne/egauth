package passkey_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/JLugagne/egauth/passkey"
	passkeymemory "github.com/JLugagne/egauth/passkey/memory"
	"github.com/google/uuid"
)

// The credential ID check used to scan every credential of the tenant on every save, so one
// account's registrations made every other account's ceremonies more expensive. These benchmarks
// pin the per-save cost to the indexed lookup: the two sizes must stay in the same order of
// magnitude, rather than the larger tenant costing proportionally more.
func BenchmarkSaveCredential(b *testing.B) {
	for _, preload := range []int{1_000, 20_000} {
		b.Run(fmt.Sprintf("tenant_credentials_%d", preload), func(b *testing.B) {
			ctx := context.Background()
			store := passkeymemory.NewStore(
				passkeymemory.WithMaxCredentialsPerUser(1_000_000),
				passkeymemory.WithMaxCredentialsPerTenant(1_000_000),
			)
			owner := uuid.Must(uuid.NewV7())
			for i := 0; i < preload; i++ {
				_ = store.SaveCredential(ctx, "t", &passkey.Credential{
					ID: []byte(fmt.Sprintf("preload-%d", i)), UserID: owner,
				})
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = store.SaveCredential(ctx, "t", &passkey.Credential{
					ID: []byte(fmt.Sprintf("bench-%d", i)), UserID: owner,
				})
			}
		})
	}
}

// A single-user lookup must not depend on how many other credentials the tenant holds.
func BenchmarkGetCredentials(b *testing.B) {
	for _, preload := range []int{100, 10_000} {
		b.Run(fmt.Sprintf("tenant_credentials_%d", preload), func(b *testing.B) {
			ctx := context.Background()
			store := passkeymemory.NewStore(
				passkeymemory.WithMaxCredentialsPerUser(1_000_000),
				passkeymemory.WithMaxCredentialsPerTenant(1_000_000),
			)
			target := uuid.Must(uuid.NewV7())
			for i := 0; i < 3; i++ {
				_ = store.SaveCredential(ctx, "t", &passkey.Credential{
					ID: []byte(fmt.Sprintf("target-%d", i)), UserID: target,
				})
			}
			other := uuid.Must(uuid.NewV7())
			for i := 0; i < preload; i++ {
				_ = store.SaveCredential(ctx, "t", &passkey.Credential{
					ID: []byte(fmt.Sprintf("other-%d", i)), UserID: other,
				})
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := store.GetCredentials(ctx, "t", target); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
