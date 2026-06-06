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
- `CreateUser`, `FindUserByID`, `FindUserByEmail`, `FindUserByPhone`, `UpdateUser`, `DeleteUser` (soft-delete + anonymise), `DisableUser`, `EnableUser`
- `UpdateUserEmail`, `UpdateUserPhone`, `UpdateUserRecoveryEmail`
- `AddIdentity`, `FindIdentityByProvider`, `FindIdentitiesByUserID`, `UpdateIdentityPassword`
- `IncrementFailedAttempts(ctx, tenantID, identityID, lockThreshold int, lockDuration time.Duration) error`
- `ResetFailedAttempts(ctx, tenantID, identityID) error`
- `CreateVerificationToken(ctx, tenantID, userID, kind string, ttl time.Duration, metadata []byte) (string, error)`
- `ConsumeVerificationToken(ctx, tenantID, token, kind string) (uuid.UUID, []byte, error)` — atomic single-use
- `DeleteExpiredVerificationTokens(ctx, tenantID) (int64, error)`

Migrations (schema evolution):
```
001_create_tables.sql
002_add_account_lockout.sql
003_create_verification_tokens.sql
004_add_phone.sql
005_add_recovery_email.sql
006_add_disabled_at.sql
```

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
```

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

### mfa

import: `github.com/JLugagne/egauth/adapters/pgx/mfa`
implements: `mfa.Store`
constructor: `func NewStore(db DBQuerier) *Store`

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
implements: `passkey.Store`
constructor: `func NewStore(db DBQuerier) *Store`

Methods:
- `SaveCredential(ctx, tenantID, c *passkey.Credential) error` — validates TenantID consistency
- `GetCredentials(ctx, tenantID, userID) ([]*passkey.Credential, error)` — empty slice if none
- `UpdateCredential(ctx, tenantID, c *passkey.Credential) error` — persists updated signature counter; returns `ErrCredentialNotFound` if absent
- `DeleteCredential(ctx, tenantID, userID, credentialID []byte) error` — returns `ErrCredentialNotFound` if absent

Migrations:
```
001_create_passkey_credentials.sql
```

---

### oauth

import: `github.com/JLugagne/egauth/adapters/pgx/oauth`
implements: `oauth.ProviderStore`
constructor: `func NewStore(db DBQuerier, opts ...StoreOption) *Store`

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

- **Migration idempotency**: all `Migrate` calls track applied files in a `schema_migrations` table; re-running is always safe.
- **Pool ownership**: caller owns and closes `*pgxpool.Pool`; stores hold a `DBQuerier` reference only.
- **Transaction support**: pass a `pgx.Tx` instead of a pool to enlist store operations in a caller-managed transaction.
- **Context usage**: all methods accept a `context.Context` and propagate cancellation/deadline to the database.
- **Expiry eviction**: no background janitor — expired rows stay until `DeleteExpired` / `DeleteExpiredVerificationTokens` is called explicitly (e.g. periodic cron). The DB enforces expiry at read time via conditional queries.

## Gotchas

- **Call `Migrate` once at startup** before any store method; missing schema causes SQL errors at runtime.
- **Separate `go.mod`**: add `require github.com/JLugagne/egauth/adapters/pgx <version>` to your module; it is not pulled in by the core `github.com/JLugagne/egauth` module.
- **Pool lifecycle**: the caller must call `pool.Close()` at shutdown; stores do not close the pool.
- **`tokens.Store[C]` generic**: the type parameter `C` is the custom-claims type embedded in API keys; use `tokens.Store[struct{}]` if no custom claims are needed.
- **`oauth.NewStore` options**: `WithIssuerAllowlist` is opt-in; omitting it allows any OIDC issuer — suitable for single-operator deployments, but tighten for public multi-tenant SaaS.
- **Memory stores vs pgx stores**: memory stores run an in-process janitor loop; pgx stores do not — schedule `DeleteExpired` externally.
