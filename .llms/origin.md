# origin — exported same-origin / CSRF primitive

`origin` exposes the exact CSRF same-origin check egauth's built-in handlers apply, so an
application can protect its **own** cookie-authenticated routes with the same semantics instead
of hand-rolling a weaker check. The classic hand-rolled hole is suffix matching, which admits
`app.example.com.evil.com`; `origin` is exact-match by construction.

Import: `github.com/JLugagne/egauth/origin`.

## Why it exists

egauth's handler families (`identity`, `tokens`, `otp`, `mfa`, `passkey`, `authflow`,
`sessions`) enforce strict same-origin by default, but `tokens.RequireAuth` /
`ContextMiddleware` only authenticate a credential — they do not gate the routes you wrap.
`tokens.WithGate` cannot fill the gap (its predicate receives `(Actor, C)` and no
`*http.Request`), so apps own the check. `origin.Middleware` is the supported way to do that.

## API

```go
// The predicate the handlers use internally: r's Origin (or Referer) host must be r.Host
// or a key in trusted. Exact match; missing header and cross-scheme fail closed.
func Allowed(r *http.Request, trusted map[string]bool) bool

// Normalize trusted entries: full origins and bare hosts both reduce to a lowercased bare
// host (host or host:port). Errors on the first entry that is neither.
func NormalizeHosts(entries []string) ([]string, error)

// Best-effort allowlist builder (invalid entries ignored) — used by WithTrustedOrigins.
func TrustedSet(entries ...string) map[string]bool

// Middleware wraps next, checking every unsafe method (anything but GET/HEAD/OPTIONS).
func Middleware(next http.Handler, opts ...Option) http.Handler

type Option func(*Config)
func WithTrustedOrigins(origins ...string) Option // bare hosts or full origins
func WithInsecureNoOriginCheck() Option           // loud opt-out
```

## Semantics (identical to the built-in handlers)

- Exact host match against `r.Host` or an allowlisted host — no substring, suffix or
  parent-domain matching.
- Missing `Origin` and `Referer` on an unsafe method → rejected (fail-closed).
- `Origin` (or `Referer` fallback) with scheme `http` on an HTTPS request → rejected.
- `Origin: null` (opaque) → rejected, with no Referer fallback.
- Allowlist entries are normalized first, so `https://app.example.com` and `app.example.com`
  are equivalent.
- Rejection is `403` with body `cross_site_blocked`.

## Wiring

```go
import "github.com/JLugagne/egauth/origin"

mux.Handle("/api/widgets", origin.Middleware(widgetHandler,
    origin.WithTrustedOrigins("https://app.example.com")))
```

Pair it with `tokens.RequireAuth(...)` on the same route: `RequireAuth` proves *who* the caller
is, `origin.Middleware` proves the request came from an allowed origin.

## Gotchas

- `Middleware` only blocks unsafe methods; reads (`GET`/`HEAD`/`OPTIONS`) pass. Apply it to
  state-changing routes, exactly as the built-in handlers do.
- `WithInsecureNoOriginCheck` is a real CSRF hole unless another layer handles CSRF; prefer
  `WithTrustedOrigins`.
- `Allowed` expects a **normalized** map. If you build it yourself, run `NormalizeHosts` /
  `TrustedSet` first, or full-origin keys will never match.
