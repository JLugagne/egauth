---
title: "Security Hardening"
weight: 8
---

# Security Hardening

## The posture

`Auth.Posture` reports the set opt-outs, the durability level and the live instance count. A production configuration has no opt-outs. Assert that in a test:

- `Posture().OptOuts` is empty.
- `Posture().Durability` is the persistent level.

## Checklist

1. **Durable, shared storage.** Use `pgxstore.New`. Ephemeral stores are accepted only on a loopback origin.
2. **Keys in a secret store.** Load the KEK and signing seeds from one. `egauth.New` refuses weak, repeated and published keys, and a KEK that cannot open existing data.
3. **Truthful proxy policy.** `egauth.DirectClients()` or `egauth.TrustedProxies(prefix)`. It decides which client address is rate limited.
4. **HTTPS public origin.** Cookies are `Secure` except on loopback.
5. **A real event sink.** Send `Config.Events` to your audit pipeline. Personal attributes are dropped unless you export them on purpose.
6. **Protect delivery.** Messages hold working links and codes. Keep them out of logs and queues that outlive their expiry.
7. **Keep the claims source current.** It is the authority for roles and scopes at every recheck.
8. **Readiness.** Serve `Auth.Ready` from a public route and fail the deployment when it fails.

## Defaults you cannot weaken by accident

CSRF checks, rate limits, body caps, the reauthentication window, `__Host-` cookies, outbound network restrictions and the session lifetime cap are on by default. Each has at most one opt-out, in `egauth.InsecureOptOuts`, with a written reason. See the secure defaults matrix in `.llms/secure-defaults-matrix.md`.

## Deliverers

Implement every `egauth.EmailDeliverer` method. A message kind added in a later release is a compile error in your code, not a dropped message.
