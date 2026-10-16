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
  One validated composition object and a deny-by-default route builder. Secure-by-default Passwords, Passkeys, MFA, OAuth and Sessions, with CI guards that keep it that way.
{{< /hextra/hero-subtitle >}}
</div>

<div class="hx:mb-12 hx:flex hx:gap-4">
{{< hextra/hero-button text="Get Started" link="docs/sdk/getting-started" >}}
{{< hextra/hero-button text="Architecture" link="docs/architecture" >}}
</div>

{{< hextra/feature-grid >}}
  {{< hextra/feature-card
    title="One Composition Object"
    subtitle="egauth.New validates the whole configuration and returns every problem at once. No cookie, issuer, limiter or gate is wired by hand."
  >}}
  {{< hextra/feature-card
    title="Deny by Default"
    subtitle="Routes are declared through Protect, Optional, ProtectAPI and Public. Every other request is a 404, and each gate set is fixed by the library."
  >}}
  {{< hextra/feature-card
    title="Sealed Session State"
    subtitle="What a login proved is minted once, sealed and replayed. Renewal can add a factor, never upgrade one."
  >}}
  {{< hextra/feature-card
    title="Passkeys and MFA"
    subtitle="Discoverable WebAuthn credentials, TOTP and recovery codes. Enrollment is read from stored state, never from configuration."
  >}}
  {{< hextra/feature-card
    title="Multi-Tenancy Enforced"
    subtitle="Tenant resolution fails closed, and every credential and ceremony handle is bound to its tenant."
  >}}
  {{< hextra/feature-card
    title="PostgreSQL and In-Memory Stores"
    subtitle="pgx stores with embedded, expand-only migrations, and in-memory stores for tests, both behind shared contract suites."
  >}}
{{< /hextra/feature-grid >}}
