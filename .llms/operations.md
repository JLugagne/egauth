# Operations

## Readiness and posture

- `Auth.Ready(ctx)` pings every store; serve it from a `Public` route as the readiness probe.
- `Auth.Posture()` returns `egauth.Posture`: the set opt-outs, the durability level and the live instance count. A production configuration has no opt-outs.
- `Auth.Close()` stops the background workers; call it on shutdown.

## Events

`Config.Events` is an `event.Sink`: `event.NewSlogSink(logger)`, `event.MultiSink(...)`, `event.SinkFunc`, `event.Discard`, or `adapters/otel`. Every event has a severity and every attribute a sensitivity; sinks drop personal attributes (IP address, user agent, previous email) unless explicitly told to export them. Types include `event.LoginSucceeded`, `event.LoginFailed`, `event.SessionIssued`, `event.RefreshReuseDetected`, `event.TokenFamilyRevoked`, `event.MFAVerified`, `event.AccountDisabled`, `event.PasswordChanged` and `event.APIKeyCreated`; `event.V17Types` lists the full set.

## Delivery

`egauth.EmailDeliverer` and `egauth.SMSDeliverer` have one method per message kind. Every method must be idempotent on `DeliveryID`, which is stable across retries. Messages hold working credentials:

- `egauth.LinkMessage.Link`, `egauth.CodeMessage.Code` and `egauth.SecurityNoticeMessage.RevertLink` render as `REDACTED` in `fmt` and `slog`.
- JSON encoding of a message is not redacted; a deliverer that queues messages as JSON stores the credential in the queue, so protect that queue as a secret store.

Security notices carry a revert link that undoes a credential or identifier change for several days.

## Rate limiting

Library budgets are keyed by class (`store/limiter`: login identifier, code request, and others), by client address and by tenant. The limiter comes from `Storage.Limiter`, so replicas share it on durable storage. With an ephemeral limiter on shared stores, each instance's budget is the library budget divided by the live instance count. `Config.RateLimit` can only tighten the library budgets. Client addresses come from `Config.Proxy`: behind a proxy, `egauth.TrustedProxies` names the peers whose forwarding headers are believed.

## Enumeration

Endpoints that take an identifier answer identically for existing and unknown accounts: same status, same body, same delivery count, comparable time. `POST /register` always answers 202; an existing address receives an account-exists notice instead of a link. Password hashing spends a decoy hash on every branch that skips the real one.

## Tenancy administration

`Auth.Tenants()` erases a tenant (every store's tenant data), imports, renews and revokes tenant signing keys, and sets runtime OAuth providers. `Auth.System(tenant, reason)` mints the caller for background work, one per tenant.
