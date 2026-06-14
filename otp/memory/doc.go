package memory

// Package memory provides an in-memory otp.Store, primarily for tests and
// single-process use.
//
// # Bounding memory growth
//
// Two complementary strategies prevent unbounded map growth:
//
//  1. [NewBoundedStore](maxSize) — hard cap, self-evicting: when a SaveOTP call
//     would exceed maxSize the store first removes already-expired codes;
//     if the cap is still reached it evicts the code with the soonest ExpiresAt.
//     No external scheduler needed.
//
//  2. [NewStore] + periodic [Store.DeleteExpired] via
//     [github.com/JLugagne/egauth/janitor]:
//
//		store := memory.NewStore()
//		j := janitor.Start(ctx, 5*time.Minute, func() {
//		    store.DeleteExpired(context.Background(), tenantID)
//		})
//		defer j.Stop()
//
// Both approaches are safe for concurrent use. NewBoundedStore is recommended
// for long-running processes where the OTP count is not otherwise capped.
// For persistent or horizontally-scaled deployments, use the otp/pgx backend
// instead.
