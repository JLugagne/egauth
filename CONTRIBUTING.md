# Contributing to egauth

Thank you for your interest in contributing to `egauth`! 

To ensure the project remains stable, secure, and true to its original vision, please review the following guidelines before submitting issues or pull requests.

## Project Philosophy

Before writing any code, it is critical to understand what `egauth` is (and what it isn't). 

1. **It is a library, not a framework.** We provide core authentication primitives and unopinionated `http.HandlerFunc` factories. We do **not** take over routing, and we do **not** dictate the API payload structure. PRs that attempt to introduce global state, web frameworks, or opinionated JSON response envelopes will be rejected.
2. **Infrastructure Agnostic.** `egauth` relies entirely on interfaces for storage (e.g., `identity.Store`). 
3. **Security First.** Cryptographic code is notoriously difficult to get right. Do not submit PRs changing the hashing algorithms, token entropy, or constant-time comparison logic without opening a discussion issue first.

## Scope of Contributions

### What we love to see:
- **Bug Fixes:** Especially around edge cases in OAuth flows, Passkeys, or database constraint handling.
- **New Store Adapters:** Storage backends live in **their own module per backend technology**, under `adapters/` — e.g. the bundled `adapters/pgx` (`github.com/JLugagne/egauth/adapters/pgx`) holds every PostgreSQL store. This keeps each driver's dependencies out of a consumer who doesn't use that backend. To add MySQL/SQLite/Redis support, create a new module `adapters/<backend>` whose packages implement the core `Store` interfaces (`identity.Store`, `tokens.Store`, …) and certify against the exported conformance suites (the per-domain `*storetest` packages, e.g. `storetest.StoreContractTesting(t, myStore)`). Do **not** modify the core domain logic to accommodate a specific database, and do **not** add a per-domain module — all stores of one backend share the same driver, so per-domain modules add tagging overhead for no dependency win. A third-party backend (e.g. an out-of-tree `egauth-mongo`) certifies against the **same** exported contract, with no change to core required.
- **Documentation Improvements:** Typo fixes, better examples, and clearer explanations are always welcome.

### What requires discussion first:
- **New Features:** Adding completely new authentication mechanics. Please open an Issue to discuss the architecture before writing code.
- **New Dependencies:** `egauth` prides itself on a minimal dependency tree. We use `jackc/pgx/v5` for PostgreSQL and standard libraries for almost everything else. Adding heavy external dependencies will require strong justification.

## Development Setup

This is a **multi-module monorepo**: the core flagship module (`github.com/JLugagne/egauth`) and a
nested pgx adapter module (`github.com/JLugagne/egauth/adapters/pgx`). The adapter's `go.mod` carries
a relative `replace github.com/JLugagne/egauth => ../..` (alongside a committed `go.work`) so it
resolves the local core module without a published tag — clone and everything builds offline. The
maintainer drops the replace at release (see RELEASING.md). `go.work.sum` is a derived lock file and
is not tracked.

1. **Go Version:** We target the latest stable Go releases.
2. **Testing:** The **core** module is Docker-free — `GOWORK=off go test ./...` runs its full suite
   with no daemon. The **`adapters/pgx`** module relies on `testcontainers-go`, so you need Docker
   installed locally to run `cd adapters/pgx && go test ./...`. `make check` runs the full suite for
   both modules. **No Docker?** Run `make test-unit` (or `go test -short ./...` in each module) — the
   `-short` flag skips every testcontainers test, so all non-database unit tests still run and pass.
3. **Running Checks:** Use the provided `Makefile` to ensure your code meets our standards:
   ```bash
   make check
   ```
   This will run `go vet`, `govulncheck`, `golangci-lint`, and `go test -race`.

## Submitting a Pull Request

1. **Fork the repository** and create your branch from `main`.
2. **Write Tests:** If you are adding a new store adapter, ensure you run it against the provided `ContractTesting` suites (e.g., `storetest.StoreContractTesting(t, myNewStore)`).
3. **Pass the Linter:** Ensure `make lint` runs cleanly.
4. **Sign Off:** By submitting a PR, you agree to license your contribution under the MIT License.

We look forward to reviewing your PRs!
