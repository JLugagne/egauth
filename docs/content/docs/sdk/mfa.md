---
title: "Multi-Factor Authentication"
weight: 5
---

# Multi-Factor Authentication

## One handshake

There is exactly one multi-factor flow. A primary login by a subject with a second factor returns a flow handle, which is not a session, and a session is issued only after the second factor. No interim access token exists.

## Enrollment is stored state

A subject is enrolled when it has a confirmed TOTP or an active passkey. That fact is read from storage at every primary login, whatever the modules, so configuration cannot lower the floor. A deployment that starts without `Modules.MFA` while TOTP enrollments exist fails `New`. Recovery codes exist only while a factor does, and removing the last factor deletes them.

## TOTP and recovery codes

`Modules.MFA` enables TOTP enrollment, confirmation, disabling and recovery-code regeneration. A code is single use within its time step, and failures lock the factor after a bounded number of attempts. `Auth.Accounts().UnlockMFA` clears a lock.

## Passkeys

`Modules.Passkey` enables WebAuthn registration and login. Credentials are discoverable and user verification is required, so usernameless login works. A client that rewrites the request is refused. A falling signature counter suspends the credential. A passkey that logged a user in cannot also serve as that login's second factor.

## Requiring a second factor on a route

`egauth.RequireMFA` on a `Protect` route refuses a session that did not complete a second factor. The facades apply the rule themselves for enrolled subjects.

## Testing

`webauthntest.New(origin)` is a software authenticator for passkey ceremonies, and `egauthtest` provides the clock and mailbox for flows with codes and links.
