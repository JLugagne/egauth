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
- **New Store Adapters:** If you want to add support for MySQL, SQLite, or Redis, please create a new subpackage (e.g., `identity/mysql`) that implements the `Store` interface. Do not modify the core domain logic to accommodate a specific database.
- **Documentation Improvements:** Typo fixes, better examples, and clearer explanations are always welcome.

### What requires discussion first:
- **New Features:** Adding completely new authentication mechanics. Please open an Issue to discuss the architecture before writing code.
- **New Dependencies:** `egauth` prides itself on a minimal dependency tree. We use `jackc/pgx/v5` for PostgreSQL and standard libraries for almost everything else. Adding heavy external dependencies will require strong justification.

## Development Setup

1. **Go Version:** We target the latest stable Go releases.
2. **Testing:** We rely heavily on `testcontainers-go` for database testing. You will need Docker installed locally to run the full test suite.
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
