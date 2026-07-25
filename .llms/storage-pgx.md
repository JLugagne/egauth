# storage-pgx — PostgreSQL Store backends (separate module)

module: `github.com/JLugagne/egauth/adapters/pgx`  (install: `go get github.com/JLugagne/egauth/adapters/pgx`)
why separate: keeps the pgx/testcontainers/Docker chain out of core consumers' dependency graph
driver: jackc/pgx — `DBQuerier` interface satisfied by `*pgxpool.Pool` or `pgx.Tx`
source: `adapters/pgx/<module>/store.go` + `adapters/pgx/<module>/migrations/*.sql`

## Common pattern (every subpackage)

```go
import identitypgx "github.com/JLugagne/egauth/adapters/pgx/identity"
pool, _ := pgxpool.New(ctx, dsn)
_ = identitypgx.Migrate(ctx, pool)   // forward-only, versioned via schema_migrations; re-run = no-op
store := identitypgx.NewStore(pool)  // implements identity.Store
```

### Shared exported symbols (identical in every subpackage)

```go
var MigrationsFS embed.FS

func Migrate(ctx context.Context, db DBQuerier) error

type DBQuerier interface {
    Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
    Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
    QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
```

`DBQuerier` is satisfied by both `*pgxpool.Pool` and `pgx.Tx`, so stores can participate in a caller-managed transaction.

Every `Store` exposes `Ping(ctx context.Context) error` — satisfies the optional `health.Pinger` seam for liveness checks.

---

## Per-module reference

### identity

import: `github.com/JLugagne/egauth/adapters/pgx/identity`
implements: `identity.Store`
constructor: `func NewStore(db DBQuerier) *Store`

Methods:
- `CreateUser`, `FindUserByID`, `FindUserByEmail`, `FindUserByPhone`, `UpdateUser`, `MarkEmailVerified` (narrow `email_verified_at` write behind `VerifyEmail`), `DeleteUser` (soft-delete + anonymise the user row AND every identity `provider_id`, releasing the provider keys for re-registration), `DisableUser`, `EnableUser`
- `UpdateUserEmail`, `UpdateUserPhone`, `UpdateUserRecoveryEmail`
- `AddIdentity`, `FindIdentityByProvider`, `FindIdentitiesByUserID`, `UpdateIdentityPassword` (single statement gated on the owner being LIVE: `ErrUserNotFound` for a soft-deleted account, `ErrIdentityNotFound` when a live user has no password identity)
- `IncrementFailedAttempts(ctx, tenantID, identityID, lockThreshold int, lockDuration time.Duration) (justLocked bool, err error)` — atomic single-statement `UPDATE`; `justLocked` derived via `RETURNING` (pre-increment < threshold ≤ post-increment), so concurrent failed logins yield `justLocked=true` to exactly one caller. Drives the once-per-lock `account.locked` event.
- `ResetFailedAttempts(ctx, tenantID, identityID) error`
- `CreateVerificationToken(ctx, tenantID, userID, kind string, ttl time.Duration, metadata []byte) (string, error)`
- `ConsumeVerificationToken(ctx, tenantID, token, kind string) (uuid.UUID, []byte, error)` — atomic single-use
- `DeleteExpiredVerificationTokens(ctx, tenantID) (int64, error)`
- `DeleteVerificationTokensForUser(ctx, tenantID, userID, kinds ...string) error` — per-user purge in a single `DELETE`; an empty `kinds` list purges every kind. Covered by `idx_verification_tokens_user (tenant_id, user_id, kind)`, so no new migration is needed. The credential-rotating flows (`ResetPassword`, `ChangePassword`, `SetTemporaryPassword`, `DisableUser`) call it, so a purge failure must be returned, never swallowed.

Migrations (schema evolution):
```
001_create_tables.sql
002_add_account_lockout.sql
003_create_verification_tokens.sql
004_add_phone.sql
005_add_recovery_email.sql
006_add_disabled_at.sql
007_add_expires_at_index.sql
008_add_password_change_columns.sql
```

Migration `008_add_password_change_columns.sql` adds two columns to the `identities` table:
- `password_changed_at TIMESTAMP WITH TIME ZONE` — **informational** audit metadata recording when
  the password hash was last set; stamped on every `UpdateIdentityPassword` write. `NULL` is simply
  an unknown last-changed time (e.g. legacy rows) and drives no behavior — egauth has no age-based
  rotation policy.
- `must_change_password BOOLEAN NOT NULL DEFAULT false` — advisory flag set by admin provisioning
  of temporary credentials (`identity.AdminCreateUser`, `identity.SetTemporaryPassword`). Never
  blocks authentication; causes the next login to issue a flagged, renewable token (the flag is
  carried across refresh by the token layer). Cleared
  automatically by every `UpdateIdentityPassword` write.

---

### tokens

import: `github.com/JLugagne/egauth/adapters/pgx/tokens`
implements: `tokens.Store[C any]`
constructor: `func NewStore[C any](db DBQuerier) *Store[C]`  — generic over custom claims type `C`

Methods:
- `SaveRefreshToken`, `FindRefreshToken`, `RevokeRefreshToken`, `RevokeFamily(ctx, tenantID, familyID uuid.UUID) error`
- `ConsumeRefreshToken(ctx, tenantID, tokenHash string) error` — atomic single-use
- `SaveAPIKey`, `FindAPIKeyByHash`
- `DeleteExpired(ctx, tenantID) (int64, error)` — keeps rows with NULL expires_at (non-expiring API keys)

Migrations:
```
001_create_tokens_table.sql
002_add_refresh_token_rotation.sql
003_add_refresh_token_auth_time.sql
004_add_expires_at_index.sql
005_add_refresh_token_must_change_password.sql
006_add_api_key_type_and_created_by.sql
007_add_api_key_revoked_at.sql
008_add_refresh_family_lifetime_and_kind.sql
```

Migration `005_add_refresh_token_must_change_password.sql` adds `must_change_password` (boolean, NOT
NULL DEFAULT false) to the `tokens` table. It records the forced-password-change gate on a refresh
family and is carried verbatim onto every rotated descendant, so a flagged session stays gated
across silent refresh (a user cannot escape by waiting for the access token to expire).

Migration `006_add_api_key_type_and_created_by.sql` adds two columns to the `tokens` table (API-key rows only):
- `type TEXT NOT NULL DEFAULT 'service'` — classifies the key as `'pat'` (personal access token,
  human principal) or `'service'` (machine identity). The default is `'service'` so legacy rows
  before this migration are never silently promoted to a human principal; they keep the more
  restricted machine identity. The store round-trips this as `tokens.KeyType` and `APIKey.Type`.
- `created_by UUID NULL` — the UUID of the human user who provisioned the key. `NULL` for legacy
  rows and for keys whose creator is not tracked. For service tokens this is the only back-link to
  a human, since the token's `Claims.Subject` is the key's own ID.

Migration `008_add_refresh_family_lifetime_and_kind.sql` adds two nullable columns to the `tokens`
table (refresh-token rows only):
- `family_created_at TIMESTAMPTZ NULL` — when the rotation FAMILY was created. It equals
  `created_at` on the initial pair and is carried unchanged onto every rotated descendant, so each
  rotation's `expires_at` is clamped to `family_created_at + MaxRefreshFamilyLifetime` (default 30
  days) instead of resetting the full `RefreshTTL`. `NULL` marks a legacy row; the issuer then falls
  back to that row's `created_at` as the anchor. `SaveRefreshToken` writes `created_at` when the
  record carries no explicit anchor.
- `kind TEXT NULL` — the principal classification (`'user'`/`'pat'`/`'service'`) of the credential
  that started the family, replayed verbatim onto every rotated descendant so a `WithRequiredKind`
  gate cannot flip after a silent refresh. `NULL`/empty is unclassified and normalises to the human
  default. It is distinct from the API-key-only `type` column.

`SaveAPIKey` and `FindAPIKeyByHash` both round-trip `type` and `created_by`. The `created_by` column
stores `NULL` when `APIKey.CreatedBy` is the zero UUID. `DeleteExpired` still hard-deletes expired
rows; per-key revocation is the soft `revoked_at` column added by migration `007`.

---

### sessions

import: `github.com/JLugagne/egauth/adapters/pgx/sessions`
implements: `sessions.Store`
constructor: `func NewStore(db DBQuerier) *Store`

Methods:
- `CreateSession`, `FindSessionByHash`, `UpdateSession(ctx, tenantID, session, expectedTokenHash string) error` (compare-and-set on token hash), `DeleteSession`, `DeleteSessionsByUserID`
- `DeleteExpired(ctx, tenantID) (int64, error)`

Migrations:
```
001_create_sessions_table.sql
```

---

### keystore

import: `github.com/JLugagne/egauth/adapters/pgx/keystore`
implements: `keystore.Store`
constructor: `func NewStore(db DBQuerier, opts ...Option) *Store`

Options:
- `WithClock(now func() time.Time)` — time source used to evaluate key activity/expiry. Defaults to `time.Now`: the store uses the **application** clock, not the database clock, so it agrees with the `keystore.Manager` that stamped `NotAfter`. Pass the same clock you give `keystore.WithClock`.

Methods:
- `CreateTenant(ctx, tenantID, initial keystore.SigningKey) error`
- `TenantExists(ctx, tenantID) (bool, error)`
- `PutSigningKey(ctx, tenantID, key keystore.SigningKey) error`
- `ActiveSigningKey(ctx, tenantID) (keystore.SigningKey, error)`
- `VerificationKeys(ctx, tenantID) (map[string]keystore.SigningKey, error)`
- `RotateSigningKey(ctx, tenantID, next keystore.SigningKey, retiredAt time.Time) error`
- `RetireExpiredKeys(ctx, tenantID, now time.Time) (int64, error)`
- `RevokeTenantKeys(ctx, tenantID) error`
- `DeleteTenant(ctx, tenantID) error`

`keystore.SigningKey` carries an `Alg` field (`HS256` default, or `RS256`/`ES256`/`ES384`/`ES512`/`EdDSA`); `Secret` holds the KEK-sealed HMAC secret for HS256 or the sealed PKCS#8 DER of the private key for an asymmetric alg — sealed under `keystore.SigningKeyContext(tenantID, keyID)`, so a key row moved to another tenant or key id no longer opens (`keystore.ErrCiphertextCorrupt`). `SigningKey` also redacts its opened `Secret` on `fmt`/`slog`. Provision/renew the algorithm via `keystore.ProvisionOptions.Alg` / `RenewOptions.Alg`; `Manager.JWKS` publishes the asymmetric public keys (HMAC stays metadata-only).

Tenant records live in `keystore_tenants`, independent of the key rows in `keystore_keys`. That split is what makes the sentinel contract implementable: `TenantExists` reports the tenant record (not the key count), `RevokeTenantKeys` deletes key rows but **keeps** the tenant row, so a revoked tenant reports `keystore.ErrNoActiveKey` (never `ErrTenantNotFound`, which a `Manager` built with `WithLazyProvisioning` would answer by minting a fresh key and thereby undoing the revocation), and `VerificationKeys` returns an **empty set with a nil error** so a `/.well-known/jwks.json` handler keeps serving after an emergency revoke. Only `DeleteTenant` removes the tenant record. `PutSigningKey` creates the tenant record when absent.

The backend runs the shared `keystore/keystoretest.StoreContractTesting` suite (`TestPgxKeystore_StoreContract`), which pins all of the above across backends.

Migrations:
```
001_create_keystore_keys_table.sql
002_add_key_algorithm.sql              -- adds the alg column (DEFAULT 'HS256'; additive, existing rows unchanged)
003_create_keystore_tenants_table.sql  -- tenant records independent of key rows; backfilled from
                                       -- keystore_keys, then keystore_keys.tenant_id becomes a FK
                                       -- onto it (ON DELETE CASCADE)
```

---

### mfa

import: `github.com/JLugagne/egauth/adapters/pgx/mfa`
implements: `mfa.Store`
constructor: `func NewStore(db DBQuerier, kek KEK) *Store`
`KEK` provides envelope encryption for TOTP secrets and is satisfied by `*keystore.KEK`:

```go
type KEK interface {
	Seal(sc keystore.SecretContext, plaintext []byte) ([]byte, error)
	Open(sc keystore.SecretContext, sealed []byte) ([]byte, error)
}
```

The secret is sealed under `TOTPSecretContext(tenantID, userID)` — tenant + `keystore.PurposeTOTPSecret` + the row's user id — bound into the AEAD as associated data, so a ciphertext from another row, tenant or subsystem cannot be opened here. `Open` still accepts blobs written before context binding existed; re-seal rows with the same helper to finish the migration (see `keystore.SecretContext`).

Methods:
- `SaveTOTP`, `GetTOTP`, `DeleteTOTP`
- `MarkTOTPUsed(ctx, tenantID, userID, step int64) (bool, error)` — replay prevention
- `IncrementTOTPAttempts(ctx, tenantID, userID) (int, error)`
- `ReplaceRecoveryCodes(ctx, tenantID, userID, codeHashes []string) error`
- `ConsumeRecoveryCode(ctx, tenantID, userID, codeHash string) error`
- `DeleteRecoveryCodes`

Migrations:
```
001_create_mfa_tables.sql
002_add_totp_failed_attempts.sql
```

---

### otp

import: `github.com/JLugagne/egauth/adapters/pgx/otp`
implements: `otp.Store`
constructor: `func NewStore(db DBQuerier) *Store`

Methods:
- `SaveOTP`, `GetOTP`, `DeleteOTP`
- `ConsumeOTP(ctx, tenantID, subjectID uuid.UUID, purpose string) (bool, error)`
- `IncrementOTPAttempts(ctx, tenantID, subjectID uuid.UUID, purpose string) (int, error)`
- `DeleteExpired(ctx, tenantID) (int64, error)`

Migrations:
```
001_create_otp_codes.sql
```

---

### passkey

import: `github.com/JLugagne/egauth/adapters/pgx/passkey`
implements: `passkey.Store`, `passkey.ChallengeStore`
constructors: `func NewStore(db DBQuerier) *Store`, `func NewChallengeStore(db DBQuerier) *ChallengeStore`

Methods:
- `SaveCredential(ctx, tenantID, c *passkey.Credential) error` — validates TenantID consistency
- `GetCredentials(ctx, tenantID, userID) ([]*passkey.Credential, error)` — empty slice if none
- `UpdateCredential(ctx, tenantID, c *passkey.Credential) error` — persists updated signature counter; returns `ErrCredentialNotFound` if absent
- `DeleteCredential(ctx, tenantID, userID, credentialID []byte) error` — returns `ErrCredentialNotFound` if absent

`ChallengeStore` methods (the SHARED ceremony-replay store a multi-replica deployment needs — the
in-memory one is per-process, so a ceremony begun on one pod cannot be finished on another):
- `Put(ctx, tenantID, challenge string, expiresAt time.Time) error` — upserts the issued challenge
- `Consume(ctx, tenantID, challenge string) (bool, error)` — single `DELETE ... RETURNING`, so exactly one of N racing Finish requests wins
- `DeleteExpired(ctx) (int64, error)` — pruning path for ceremonies that were never finished; run it periodically

Migrations:
```
001_create_passkey_credentials.sql
002_add_credential_management_metadata.sql
003_create_passkey_challenges.sql
```

---

### oauth

import: `github.com/JLugagne/egauth/adapters/pgx/oauth`
implements: `oauth.ProviderStore`
constructor: `func NewStore(db DBQuerier, kek KEK, opts ...StoreOption) *Store`
`KEK` provides envelope encryption for OAuth client secrets; `ctx` is carried for KMS-backed implementations:

```go
type KEK interface {
	Seal(ctx context.Context, sc keystore.SecretContext, plaintext []byte) ([]byte, error)
	Open(ctx context.Context, sc keystore.SecretContext, ciphertext []byte) ([]byte, error)
}
```

The `client_secret` is sealed under `ClientSecretContext(tenantID, providerName)` — tenant + `keystore.PurposeOAuthClientSecret` + the row's provider name — bound into the AEAD as associated data, so one tenant's sealed secret cannot be pasted into another's provider row. `Open` still accepts blobs written before context binding existed; re-seal rows with the same helper to finish the migration (see `keystore.SecretContext`).

StoreOption:
```go
func WithIssuerAllowlist(issuers []string) StoreOption
```
Default: no allowlist (all issuers permitted). When set, any issuer not listed is rejected — opt-in defence for multi-tenant bring-your-own-SSO.

Config type:
```go
type OIDCProviderConfig struct {
    ClientID, ClientSecret, AuthURL, TokenURL, Issuer, JWKSURL string
    Scopes []string
}
```

Methods:
- `UpsertProvider(ctx, tenantID, providerName string, config OIDCProviderConfig) error`
- `GetProvider(ctx, tenantID, providerName string) (*oauth.Provider, error)` — builds live OIDC provider
- `DeleteProvider(ctx, tenantID, providerName string) error`

Sentinel errors:
- `ErrInvalidProviderConfig` — empty ClientID or Issuer; enforced at both upsert and get
- `ErrIssuerNotAllowed` — issuer not on configured allowlist

Migrations:
```
001_init.sql
```

---

## Errors / behavior

- **Migration idempotency**: all `Migrate` calls track applied files in a `schema_migrations` table and take a Postgres advisory lock (keyed per module namespace) for the whole run, so concurrent `Migrate` calls targeting the same module serialize instead of racing. Every migration file must be idempotent (`IF NOT EXISTS` and friends); re-running `Migrate` is then safe, including when several instances start it concurrently during a rolling deploy.
- **Pool ownership**: caller owns and closes `*pgxpool.Pool`; stores hold a `DBQuerier` reference only.
- **Transaction support**: pass a `pgx.Tx` instead of a pool to enlist store operations in a caller-managed transaction.
- **Context usage**: all methods accept a `context.Context` and propagate cancellation/deadline to the database.
- **Expiry eviction**: no background janitor — expired rows stay until `DeleteExpired` / `DeleteExpiredVerificationTokens` is called explicitly (e.g. periodic cron). The DB enforces expiry at read time via conditional queries. Expiry eviction is NOT revocation: to kill one user's pending tokens immediately (password reset, disable) use `DeleteVerificationTokensForUser`.

## Gotchas

- **Run migrations from a dedicated migration job/init container** as the primary pattern (a single `Migrate` invocation that runs to completion before any application replica starts serving traffic) — this keeps schema changes and application rollout as separate, individually observable steps. Calling `Migrate` per-instance at application startup is supported as a convenience path (the advisory lock makes it safe for N replicas to call it concurrently) but every instance then pays the migration-check cost on every boot and a slow/failing migration is harder to distinguish from an application startup failure. Either way, missing schema causes SQL errors at runtime if `Migrate` is skipped entirely.
- **Separate `go.mod`**: add `require github.com/JLugagne/egauth/adapters/pgx <version>` to your module; it is not pulled in by the core `github.com/JLugagne/egauth` module.
- **Pool lifecycle**: the caller must call `pool.Close()` at shutdown; stores do not close the pool.
- **`tokens.Store[C]` generic**: the type parameter `C` is the custom-claims type embedded in API keys; use `tokens.Store[struct{}]` if no custom claims are needed.
- **`oauth.NewStore` options**: `WithIssuerAllowlist` is opt-in; omitting it allows any OIDC issuer — suitable for single-operator deployments, but tighten for public multi-tenant SaaS.
- **Memory stores vs pgx stores**: memory stores run an in-process janitor loop; pgx stores do not — schedule `DeleteExpired` externally.
