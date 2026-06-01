---
title: "Architecture"
weight: 10
---

# Architecture & Design Philosophy

`egauth` is designed specifically for Go engineers who want the security of an enterprise Identity Provider (like Keycloak or Auth0) without the operational overhead of managing a separate microservice, and without surrendering architectural control to a heavy framework.

## 1. Composable by Design

It operates similarly to the Go standard library's `database/sql` package: you only import the domains you need, and you wire them together explicitly. 

If you just need JWT tokens, import `tokens`. If you need user management, import `identity`. They do not strictly depend on each other, preventing bloated binaries.

## 2. Infrastructure Agnostic

Rather than coupling to a specific ORM (like GORM or Ent), every module defines its own minimal `Store` interface.
- **`pgx`**: Robust PostgreSQL adapters are provided out of the box using `jackc/pgx/v5`. SQL migrations are co-located and embedded via `//go:embed`.
- **`memory`**: Every module ships with a concurrency-safe, zero-dependency in-memory store. This allows you to write blazing fast unit tests for your HTTP handlers without mocking the database.

## 3. Security Hardened

Security is structurally enforced:
- **Opaque Tokens**: Refresh tokens, session tokens, and API keys are high-entropy strings. Only their SHA-256 hashes are persisted. Database leaks do not expose usable credentials.
- **Timing Defense**: Enumeration attacks (testing if an email exists by measuring response time) are neutralized through "decoy hashing."
- **Data Redaction**: Sensitive structures implement `slog.LogValuer` to render as `REDACTED` in application logs, preventing accidental leaks.

## 4. Bring Your Own Routing

`egauth` exposes `http.HandlerFunc` factories instead of a monolithic router. This ensures it integrates seamlessly whether you use `gorilla/mux`, `chi`, `gin`, or the standard library `http.ServeMux`. You maintain total control over your middleware stack (CORS, Request IDs, Tracing).
