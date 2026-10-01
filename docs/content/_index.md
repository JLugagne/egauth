---
title: "egauth"
layout: hextra-home
---

<div class="hx:mt-8 hx:mb-6">
{{< hextra/hero-headline >}}
  Composable, Secure Authentication&nbsp;<br class="hx:sm:block hx:hidden" />Toolkit for Go
{{< /hextra/hero-headline >}}
</div>

<div class="hx:mb-10">
{{< hextra/hero-subtitle >}}
  Independent modules in the <code>database/sql</code> style. No framework, no vendor lock-in. Secure-by-default primitives for Passwords, Passkeys, MFA, JWT, and Sessions.
{{< /hextra/hero-subtitle >}}
</div>

<div class="hx:mb-12 hx:flex hx:gap-4">
{{< hextra/hero-button text="Get Started" link="docs/sdk/getting-started" >}}
{{< hextra/hero-button text="Architecture" link="docs/architecture" >}}
</div>

{{< hextra/feature-grid >}}
  {{< hextra/feature-card
    title="Extreme Composability"
    subtitle="Import only what you need (identity, tokens, sessions, mfa, passkey). Wire with standard dependency injection."
  >}}
  {{< hextra/feature-card
    title="Secure by Default"
    subtitle="Decoy hashing, Argon2id, constant-time comparisons, single-use refresh token rotation, and strict CSRF protection."
  >}}
  {{< hextra/feature-card
    title="Passkeys & WebAuthn"
    subtitle="Built-in WebAuthn ceremony handlers with server-side challenge verification and tamper-proof ceremony cookies."
  >}}
  {{< hextra/feature-card
    title="Bring Your Own Router"
    subtitle="Standard net/http handlers compatible with standard library http.ServeMux, gorilla/mux, chi, gin, or echo."
  >}}
  {{< hextra/feature-card
    title="Multi-Tenancy Enforced"
    subtitle="Native tenant isolation across all stateful methods, eliminating cross-tenant data leaks and IDOR vulnerabilities."
  >}}
  {{< hextra/feature-card
    title="PostgreSQL & In-Memory Stores"
    subtitle="Production-ready jackc/pgx/v5 adapters with embedded migrations, and zero-dependency in-memory stores for testing."
  >}}
{{< /hextra/feature-grid >}}
