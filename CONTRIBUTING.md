# Contributing to egauth

Thank you for your interest in contributing to `egauth`.

egauth is a misuse-resistant library: a mistake that an integrator could make should not compile,
should make `egauth.New` return an error, or should be caught by a CI guard. Contributions are
reviewed against that bar. This document lists the invariants the code base keeps and, for each,
the guard that fails the build when a change breaks it.

## Invariants

Each invariant names its guard. Guards are numbered `G1` to `G29`. Static guards live in
`tools/archtest`, behavioural guards in `internal/journeytest` and `internal/session/backendtest`,
documentation guards in `tools/doclint`.

1. **Seal and replay.** Every fact a later step needs (factors, assurance time, must-change,
   remember-me, return target) is minted once by issuance, sealed, persisted on the artefact that
   step consumes and replayed from there. A later step may add a factor, never re-derive or upgrade
   one. Guards: G8 (store records carry a sealed field and no loose copies of these facts), G6
   (only the owner may produce, transition or unseal them), G21 (the backend suite asserts replay
   across renewal).
2. **One owner per policy.** `egauth.Auth` owns the cookies, issuer, claims source, tenant resolver,
   origins, event sink, MFA policy, limiter and revocation. Nothing outside `internal/` returns an
   HTTP handler or takes a functional option. Guards: G1 (no exported handler constructors), G2 (no
   option types), G6 (single-owner table for cookies, client addresses, form parsing, outbound HTTP,
   clocks and events).
3. **Issuance inputs come from verified facts.** Methods, factors, tenant and remember-me come from
   the ceremony result, never from a caller callback. Guards: G6 (verified-factor constructors are
   owned by `internal/factors`, issuance steps by `internal/issuance`), G23 (the journey matrix
   compares the resulting session with the expected value for every primary factor).
4. **Producers and consumers share a type.** Identifiers that cross a boundary have one type, and a
   capability a consumer relies on is checked when it is constructed. Guards: G3 (no two adjacent
   parameters or results of the same primitive type), G11 (every store implementation runs the
   shared contract suite), G24 (the software authenticator honours resident-key requests), G25
   (every built-in provider declares its email verification and issuer).
5. **Deny by default, one opt-out per policy.** A weakening of a default is a field of
   `egauth.InsecureOptOuts` or `egauth.ResourceInsecure` with a written reason, listed by
   `Auth.Posture`, and identical on every sibling path. Guards: G7a (identifier names that suggest
   a weakening are refused outside those structs), G7b (a semantic search of every `Config` field
   for a variant that loosens a probe), G22 (the probe battery over all routes).
6. **Construction validates the whole wiring.** `egauth.New` and `egauth.NewResourceServer` return
   every problem, joined, and no request-time "not configured" path exists. An option a constructor
   does not consume is an error. Guards: G4 (no such literals, no `Must*`, no panics in exported
   functions), G5 (every tag is enforced and every default has a registry entry).
7. **Resolvers return structs.** No exported function or interface method takes or returns two
   adjacent values of the same primitive type. Guard: G3.
8. **Lifecycle effects are keyed by event.** "Revoke sessions" and "destroy factors" are bound to
   lifecycle events in one table, not to modules. Guards: G18 (the subscriber wiring is compared
   with the golden matrix), G9 (every event type has an emitter or a typed reservation).
9. **Journeys, not route tests.** Every supported journey runs end to end over HTTP and asserts the
   resulting session. Guards: G23 (primary factor, second factor, backend, transport and tenancy
   matrix), G28 (enumeration uniformity), G29 (the v0.16 upgrade on a real dump).

Supporting guards:

| Guard | What it keeps |
|---|---|
| G10 | every event attribute declares its sensitivity |
| G12 | every store embeds the base contract, reaps expiring rows and erases per subject |
| G13, G14 | no context accessors outside `internal/`, no type assertions to interfaces |
| G15 | the import layering, and no adapter import of core `internal/` |
| G16 | migrations are expand-only and idempotent, and each embedded set is registered once |
| G17 | module versions never drift from `VERSION` |
| G19 | the route table and the served routes are the same set |
| G20 | exemptions resolve, and none relies on a symbol that exists |
| G26, G27 | documentation: no burden sentences, every symbol reference resolves, every Go block is embedded from a compiled example |

An exemption is a typed entry that names the symbol and the work that removes it. Free text is
never accepted, and the lists only shrink.

## Documentation rules

Documentation states how something behaves. A sentence that tells the reader to also do something
elsewhere is a defect in the design, so fix the code until the sentence is unnecessary. `make
doclint` fails on such sentences, on references to symbols that do not exist, and on Go code that is
not embedded from a compiled `Example`. Run `cd tools && go run ./doclint -write` after changing an
example to regenerate the blocks.

## Project philosophy

1. **A library, not a framework.** egauth does not take over your router or dictate a response
   envelope. It mounts its endpoints under one base path and serves your declared routes.
2. **Infrastructure agnostic.** Storage is behind store contracts. A backend lives in its own module
   under `adapters/`, such as `adapters/pgx` (`github.com/JLugagne/egauth/adapters/pgx`), and
   certifies against the exported contract suites. Core never changes for a database.
3. **Security first.** Do not change hashing, token entropy or constant-time comparisons without an
   issue to discuss it first.

## Scope of contributions

Welcome: bug fixes, new store adapters, documentation improvements, and new guards.

Discuss first: new authentication mechanics, which need a design in an issue, and new dependencies.
The dependency tree is deliberately small.

## Development setup

This is a multi-module repository: the core module, `adapters/pgx`, `adapters/otel` and the
unpublished `tools` module that holds the guards. A committed `go.work` resolves them locally. The
maintainer drops it, and any `replace` directive, at release (see RELEASING.md).

1. **Go version.** The latest stable release.
2. **Tests.** `GOWORK=off go test -timeout 40m ./...` runs the core suite without a daemon (the full journey
   matrix exceeds go test's 10 minute default; add `-short` for the quick pass). `adapters/pgx` uses
   `testcontainers-go`, so `cd adapters/pgx && go test ./...` needs Docker; add `-short` to skip the
   database tests.
3. **Checks.** `make check` runs vet, vulnerability scan, lint, version sync, the static guards
   (`make archtest`), the documentation guards (`make doclint`), the short journey matrix
   (`make journey`) and the unit tests. `make ci` adds the full matrix and the pgx suites.

## Submitting a pull request

1. Fork the repository and branch from `main`.
2. Write tests first. A fix starts with a test that fails for the reported reason.
3. Run `make check` and keep it green.
4. By submitting a pull request you agree to license your contribution under the MIT License.
