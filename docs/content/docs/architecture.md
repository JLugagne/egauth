---
title: "Architecture"
weight: 10
---

# Architecture

`egauth` is designed with modularity in mind.

## Design Principles

- **State Isolation:** Database access is encapsulated in respective modules via `Store` interfaces:
  - `identity` (PostgreSQL): Long-term persistence for users, identities (Password, OAuth), and hashes.
  - `sessions` and `tokens` (Redis, Postgres, Memory): Ephemeral or revocable states.
  - `passwords`: Pure business logic (stateless).
- **Decentralized HTTP:** There is no monolithic `http` package. Each module exposes its own handler constructors (e.g., `identity.LoginHandler(svc)`). You mount only what you need, where you need it.
- **Security by Default:** Opaque tokens (Refresh Tokens, Sessions, API Keys) are **never stored in plaintext** in the database. Only a hash (e.g., SHA-256) is kept to prevent impersonation in case of a DB leak.
- **Type Safety via Generics:** Custom token claims are generically typed `[C any]`.
- **Silent by Default:** No forced internal logging. Systematic propagation of `context.Context` for future tracing (OpenTelemetry).
- **Explicit Errors:** Each module exposes its own sentinel errors (e.g., `ErrUserNotFound`, `ErrTokenExpired`).

## Project Structure

```text
egauth/
├── identity/                 # Main stateful module
│   ├── store.go              # Store interface (CRUD) + Options (WithTenant)
│   ├── service.go            # Service interface (orchestrates Identity + Passwords)
│   └── handlers.go           # Builder funcs: LoginHandler, RegisterHandler...
├── sessions/                 # Stateful (separated from tokens for Redis, etc.)
│   ├── store.go              # Store interface (stores session HASH)
│   └── middleware.go         # Session validation
├── tokens/                   # Hybrid (JWT + Store API Keys/Refresh)
│   ├── token.go              # Generic types TokenPair[C any], Claims[C any]
│   └── store.go              # Store interface (stores Refresh/APIKeys HASH)
├── passwords/                # PURE LOGIC (Stateless)
│   ├── hasher.go             # Hasher interface
│   └── policy.go             # Policy interface
└── oauth/                    # PURE LOGIC (Stateless orchestration)
```

## Advanced Features

### Multi-tenancy
All stateful models include a `TenantID` field of type `string`.
Isolation is managed via the **Options pattern** in Store calls (e.g., `store.FindUserByEmail(ctx, email, identity.WithTenant("t1"))`).

### Multi-provider Identities
Authentication is separated from the user account.
`User` represents the account (ID, primary Email).
`Identity` represents an authentication method linked to the user (e.g., "password", "google", "github").

### Soft Delete & Anonymization
When a user is deleted via `identity.Store.DeleteUser`, the `DeletedAt` field is set, and the **Email** is anonymized to allow re-registration while maintaining referential integrity (GDPR compliant).
