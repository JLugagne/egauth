# Security model — handling secrets and passwords

This document describes how `libauth` handles sensitive values (passwords, opaque
tokens, hashes) and what the **consumer** of the library is responsible for.

## What libauth guarantees

- **Hashing at rest.** Opaque tokens (refresh tokens, API keys, session tokens) are
  never persisted in clear text. Only their SHA-256 hash is stored (`tokens.HashToken`),
  so a database leak does not expose usable credentials. Lookups are performed on the
  hash, which is what makes a plain index/equality lookup safe for high-entropy tokens.
- **Constant-time password comparison.** Password verification uses
  `crypto/subtle.ConstantTimeCompare` (`passwords/argon2`), so a wrong password cannot
  be recovered byte-by-byte through timing.
- **Constant-time authentication paths.** The password authentication path applies an
  equivalent hashing cost even when the user, identity, or password hash is absent, so
  account existence cannot be inferred from response timing (user-enumeration defence).
- **No internal logging.** libauth performs no logging of its own ("silent by default").
  It never writes passwords, plaintext tokens, or hashes to stdout/stderr or any logger.
  `context.Context` is propagated so consumers can attach their own tracing.
- **Errors do not echo secrets.** Wrapped errors carry the underlying cause
  (`%w`) or non-sensitive metadata (e.g. a JWT `alg` header), never the plaintext
  password or token bytes.

## What the consumer must NOT do

Some values are returned to the caller in **plaintext exactly once** and must be treated
as credentials:

- `tokens.APIKey.Token` — the raw API key (only `APIKey.Hash` is stored).
- `tokens.TokenPair.AccessToken` and `tokens.TokenPair.RefreshToken`.
- Session tokens returned by the `sessions` service.
- Any password passed into `Register` / `Authenticate`.

These are plain `string` fields with **no redaction**. Therefore the consumer must:

- **Never log them** (no `log`, `slog`, `fmt.Printf`, request/response dumps, etc.).
- **Never serialize them by accident.** The structs above carry no `json` tags and are
  not marshaled by libauth, but a consumer that JSON-encodes them will emit the
  plaintext. Send a token to the client deliberately (cookie/body) and nowhere else.
- **Transmit only over TLS** and store client-side tokens in `HttpOnly`, `Secure`
  cookies (the HTTP handlers set these flags by default).

## Reporting a vulnerability

Report security issues privately to the maintainer rather than opening a public issue.
