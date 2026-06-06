---
title: "Developer Manual"
weight: 20
bookCollapseSection: false
---

# `egauth` Developer Manual

Welcome to the `egauth` Developer Manual. `egauth` is a completely modular, composable, and unopinionated authentication SDK for Go. It is designed to act as the authentication backbone for your applications, providing you with high-security primitives (NIST SP 800-63B compliant) while leaving the architectural decisions—like HTTP routing, API design, and DTOs—up to you.

## Modules Overview
- **Getting Started**: Initializing stores and basic wiring.
- **Identity & Passwords**: Managing users, registration, authentication, and secure password hashing.
- **Tokens & HTTP**: Issuing stateless JWTs, managing stateful refresh token families, and protecting HTTP handlers.
- **Sessions**: Managing stateful server-side sessions and idle timeouts.
- **OAuth & OIDC**: Social logins (Google, GitHub) and OIDC integration.
- **MFA & Passkeys**: Implementing Multi-Factor Authentication via TOTP and WebAuthn (biometrics/hardware keys).
- **Tenancy**: Data isolation across all operations.
- **Delivery seams**: `identity.Mailer` and `identity.SMSSender` are bring-your-own-delivery callbacks — wire your SMTP/SMS provider; egauth never sends mail or SMS itself. **Events**: pluggable audit-event `event.Sink` seam.
- **Security Hardening**: The checklist of opt-in controls — cost ceilings, absolute timeouts, UV enforcement, SSRF defence, and rate limiting — to set before production.
