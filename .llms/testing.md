# Testing applications

- `egauthtest.Config[C]()` returns a loopback development configuration with a fresh random KEK and every opt-out acknowledged by `egauthtest.TestOptOutReason`, which `New` refuses once an origin or audience is not loopback; `egauthtest.New(cfg, clock, idp)` builds an `egauth.Auth` on a controllable `egauthtest.Clock`.
- `egauthtest.NewPrincipal[C](spec)` builds an `egauth.Principal` to call a handler directly.
- `egauthtest.Mailbox` records deliveries so a test can read emailed links and codes.
- `egauthtest.NewIdP(t, clock)` is an in-process OIDC provider for OAuth journeys.
- `webauthntest.New(origin)` is a software authenticator for passkey registration and login, including discoverable credentials.
- `memstore.NewWithClock` makes expiry follow the test clock.

`egauthtest` is for tests only; production code that imports it fails a repository guard.

## Contract suites

Backends and implementations of the seams run the shared suites: `store/<name>/storetest` for each store, `kek.CheckConformance` for a KEK, `federation/providertest` for providers. Run them against a custom implementation before trusting it.

## Journeys

`ExampleNew` in the root package is the end-to-end shape: register, confirm the emailed link, log in, call a protected route, refresh, log out. The same flow is exercised for every primary factor, second factor, backend, transport and tenancy by `internal/journeytest`.
