---
title: "Identity and Passwords"
weight: 3
---

# Identity and Passwords

Enable the `Password` module to register and log in with a password.

## Registration

`POST /register` always answers `202`. No account exists until the emailed link is confirmed, so an address cannot be claimed by someone who does not control it, and the answer does not reveal whether the address already has an account. An address that already has one receives an account-exists notice instead of a link. `egauth.PasswordModule.Registration` selects open sign-up or invite-only.

## Login

`POST /login` verifies the identifier and password. Unknown, locked, disabled and unverified accounts answer exactly like a wrong password, and each spends the same hashing cost. A successful login either establishes a session or, for a user with a second factor, returns a flow handle that is not a session.

## Passwords

- Argon2id hashing with a recorded cost; a hash recorded at an older cost is replaced after a successful login.
- A floor of 8 to 1024 characters, NFKC normalised, applied before any policy.
- `passwords.Policy` and `passwords.BreachChecker` are seams. References are in `passwords/policy` and `passwords/breach/hibp`.

## Reset and change

A reset starts with `POST /password/forgot`, which answers uniformly, and finishes with the emailed link. A reset ends no session by itself but bumps the security epoch, so every other session dies at its next recheck, while factors survive. A change requires the current password and a fresh session, and keeps the current session.

## Account administration

`Auth.Accounts` creates accounts, sets temporary passwords (which force a change at the next login), disables and enables accounts, revokes sessions, unlocks a locked second factor and deletes accounts. A deletion runs through the lifecycle outbox, so `Hooks.AccountDeleted` is retried until it succeeds.

## Delivery

Messages are sent by your `egauth.EmailDeliverer` and `egauth.SMSDeliverer`. Link and code fields render as `REDACTED` under every `fmt` verb and in `slog` (JSON marshalling prints the real value); the deliverer reads them directly.
