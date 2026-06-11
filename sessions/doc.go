// Package sessions is egauth's server-side session module: opaque session tokens backed by a
// store, with sliding idle-timeout (Touch), rotation against session fixation (Rotate), and
// revocation. It is the stateful alternative — or complement — to the stateless tokens module.
//
// # Composable by design
//
// Like the rest of egauth (see the database/sql-style note in package identity), sessions is an
// independent module wired by dependency injection. Use it when you want revocable, server-side
// sessions (a logout or admin action invalidates immediately, with no token still valid until
// expiry); use the tokens module when you want stateless JWTs with no per-request store lookup.
// Many applications combine them (a session cookie for the browser, JWT access tokens for APIs).
//
// Multi-tenancy is explicit: every Service method takes a tenantID string (empty string is the
// single-tenant default partition). Wrap the Service in SingleTenant (NewSingleTenant) to drop
// the argument in a single-tenant app.
//
// # Wiring
//
//	store := memory.NewStore()                          // sessions/memory; or sessions/pgx.NewStore(pool)
//	svc := sessions.NewService(store)
//	sess, token, err := svc.CreateSession(ctx, tenantID, userID, userAgent, ip, 24*time.Hour)
//	// on activity: svc.Touch(ctx, tenantID, token, 24*time.Hour)        // slide idle timeout
//	// after a privilege change (same identity): svc.Rotate(ctx, tenantID, token, 24*time.Hour) // defeat fixation
//	// login over an anonymous session (change identity): svc.BindUser(ctx, tenantID, token, userID, 24*time.Hour)
//
// NewService panics on a nil Store (fail-fast at startup).
//
// # HTTP middleware
//
// RequireSession validates the session cookie and hands the authenticated egauth.Actor and Session
// to your handler.
//
// # Security posture
//
// Only the SHA-256 hash of the opaque token is stored (the plaintext is returned once, at
// creation/rotation); rotation is a compare-and-set on the token hash so two requests racing to
// rotate cannot both succeed. See SECURITY.md.
package sessions
