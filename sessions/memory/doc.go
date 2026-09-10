package memory

// Package memory provides an in-memory sessions.Store, primarily for tests and
// single-process use.
//
// # Bounding memory growth
//
// [NewStore] is bounded by default: a hard cap of [DefaultMaxEntries] sessions.
// When a new session would exceed the cap the store first removes already-expired
// sessions; if the cap is still reached with active live sessions, CreateSession
// returns [sessions.ErrStoreCapacityExceeded] to protect active sessions from
// eviction. No external scheduler is needed.
//
// Two alternative constructors cover the other deployment shapes:
//
//   - [NewBoundedStore](maxSize) picks a different hard cap with the same policy.
//
//   - [NewUnboundedStore] preserves the unbounded model, where growth is
//     controlled by periodic [Store.DeleteExpired] calls via
//     [github.com/JLugagne/egauth/janitor]:
//
//		store := memory.NewUnboundedStore()
//		j := janitor.Start(ctx, 5*time.Minute, func() {
//		    store.DeleteExpired(context.Background(), tenantID)
//		})
//		defer j.Stop()
//
// All constructors are safe for concurrent use. For persistent or
// horizontally-scaled deployments, use the sessions/pgx backend instead.
