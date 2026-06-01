---
title: "Philosophy & Architecture"
weight: 10
---

# Philosophy & Architecture

`egauth` aims to provide robust authentication primitives directly within your Go application. It's built for developers who want to embed secure identity management without needing to deploy a separate authentication service or adopt a heavy, opinionated web framework.

Understanding the philosophy behind `egauth` will make integrating it into your application much easier.

---

## 1. A Library, Not a Framework or Service

Most authentication solutions fall into two categories:
1. **SaaS / Microservices**: You deploy a separate server, and your application talks to it over the network via OAuth/OIDC. This introduces network latency, complex deployment topologies, and vendor lock-in.
2. **Heavyweight Frameworks**: These generate massive amounts of boilerplate into your codebase, dictating what ORM you use, how your API is routed, and what your user schema looks like.

**`egauth` takes a third path:** It is a pure, embeddable SDK. It acts identically to the Go standard library's `database/sql` package. You import only the modules you need (`identity`, `tokens`, `mfa`), and you explicitly wire them together in your application's `main.go` (your Composition Root).

**Integration Impact:** You own the `main` function. `egauth` never starts a server, never opens a port, and never reads environment variables automatically. You must explicitly construct the services and pass them your database connection pool.

---

## 2. Ports and Adapters (Hexagonal Architecture)

`egauth` is internally structured using clean, hexagonal architecture principles to ensure it remains completely decoupled from your infrastructure choices.

### The "Core" (Domain & Services)
The core logic (e.g., hashing passwords, rotating refresh tokens, decoy hashing) lives in the root of each module (e.g., `identity.Service`). The Service defines *Interfaces* (Ports) for anything that requires reaching the outside world.

### The "Outbound" (Storage & Delivery)
`egauth` does not use an ORM. Instead, each module defines a strict `Store` interface.
- **Provided Adapters:** We provide robust PostgreSQL adapters (`jackc/pgx/v5`) natively. SQL migrations are co-located and embedded via `//go:embed`.
- **In-Memory Adapters:** Every module ships with a concurrency-safe, zero-dependency in-memory store. 
- **Delivery Interfaces:** Operations like sending an email or SMS are delegated to you via interfaces like `identity.Mailer`. `egauth` doesn't care if you use AWS SES, SendGrid, or log to standard output.

**Integration Impact:** You can easily write blazing fast unit tests for your own HTTP handlers by injecting the `egauth` in-memory stores, completely bypassing the need to mock the database or the auth service.

---

## 3. Bring Your Own Routing (BYOR)

Because `egauth` is an embeddable library, it does not provide a monolithic router or a running server. 

Instead, `egauth` exposes `http.HandlerFunc` factories (e.g., `identity.LoginHandler(service)`). 

**Integration Impact:** You attach these handlers directly to your preferred multiplexer (`gorilla/mux`, `chi`, `gin`, or `http.ServeMux`). This guarantees that your existing middleware stack (CORS, Request IDs, OpenTelemetry Tracing, Rate Limiting) wraps the authentication endpoints natively.

### Bypassing the Handlers
If our provided HTTP handlers don't match your required JSON payload structures, you can completely ignore them! You are encouraged to write your own HTTP handlers that parse your custom JSON, and then directly call the underlying `identity.Service` methods. 

---

## 4. Error Handling Philosophy

`egauth` does not return HTTP status codes from its core services. It returns domain-specific sentinel errors (e.g., `identity.ErrInvalidCredentials`, `tokens.ErrTokenTheftDetected`).

**Integration Impact:** When using the SDK programmatically, you can `errors.Is(err, identity.ErrInvalidCredentials)` to gracefully handle failures, wrap them in your own application's custom error formats, and translate them to whatever HTTP/gRPC status codes your API contract dictates.

---

## 5. Explicit Multi-Tenancy

Multi-tenancy is not an afterthought in `egauth`; it is structurally enforced. **Every stateful operation across all modules requires a `tenantID` argument.**

This ensures physical data isolation at the service boundary, completely neutralizing Cross-Tenant Insecure Direct Object Reference (IDOR) vulnerabilities.

**Integration Impact:**
- **SaaS Applications:** Extract the tenant from the incoming request (e.g., via a subdomain or header) and pass it directly into the service methods.
- **Single-Tenant Applications:** Use the `NewSingleTenant` wrappers provided by each module. This wraps the core service and automatically injects an empty string `""` partition into every call, hiding the tenant complexity from your daily development entirely.

---

## 6. Security by Default

We handle the cryptographic heavy lifting so you can focus on your product.
- **Opaque Tokens:** Refresh tokens, session tokens, and API keys are high-entropy strings. Only their SHA-256 hashes are persisted. Database leaks do not expose usable credentials.
- **Timing Defense:** Enumeration attacks (testing if an email exists by measuring response time) are neutralized through "decoy hashing."
- **Data Redaction:** Sensitive structures implement `slog.LogValuer` to render as `REDACTED` in application logs, preventing accidental leaks when using structured logging.
