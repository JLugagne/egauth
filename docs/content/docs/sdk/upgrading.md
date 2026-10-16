---
title: "Upgrading from v0.16"
weight: 9
---

# Upgrading from v0.16

v0.17 is a breaking redesign and a session cutover. Every user logs in again, and outstanding emailed links stop working. Passwords, TOTP, passkeys, OAuth links, API keys and signing keys carry over.

## Steps

1. Run `pgxstore.Migrate`. It is expand-only and idempotent.
2. Re-seal legacy secrets once. `egauth.New` refuses to start until this is done.

<!-- embed: example_test.go#ExampleUpgradeSecretsV016 -->
```go
ctx := context.Background()
var storage egauth.Storage
var oldKey, newKey []byte

legacy, err := kek.LegacyLocalV016(oldKey)
if err != nil {
	return
}
current, err := kek.NewLocal(newKey)
if err != nil {
	return
}
report, err := egauth.UpgradeSecretsV016(ctx, storage, legacy, current)
if err != nil {
	return
}
fmt.Println(report)
```

3. Deploy. Passkeys report `needs_reregistration` only when they are legacy.
4. Replace the v0.16 wiring with `egauth.New` and `Auth.Routes`. The reference is `examples/fullstack`, and the minimal configuration is `ExampleNew`.
5. In v0.18 the contract migrations drop the legacy tables.

## What changed for the application

- Registration creates no account until the email is verified, and always answers `202`.
- Federated identities are never linked automatically.
- Handlers take an `egauth.Principal` as an argument instead of reading a context value.
- Deliverers have one method per message kind.
- Every `With*` option and every module constructor is gone. The full list is in the changelog.
