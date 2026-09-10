package memory

// Package memory provides an in-memory otp.Store, primarily for tests and
// single-process use.
//
// # Bounding memory growth
//
// [NewStore] is bounded by default: a hard cap of [DefaultMaxEntries] codes that
// self-evicts expired rows first and then the soonest-expiring code. No external
// scheduler is needed.
//
// [NewBoundedStore](maxSize) picks a different hard cap with the same policy.
// [NewUnboundedStore] preserves the unbounded model, where growth is controlled
// by periodic [Store.DeleteExpired] calls via
// [github.com/JLugagne/egauth/janitor]:
//
//	store := memory.NewUnboundedStore()
//	j := janitor.Start(ctx, 5*time.Minute, func() {
//	    store.DeleteExpired(context.Background(), tenantID)
//	})
//	defer j.Stop()
//
// All constructors are safe for concurrent use. For persistent or
// horizontally-scaled deployments, use the otp/pgx backend instead.
