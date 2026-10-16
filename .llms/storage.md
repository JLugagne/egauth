# Storage, migrations and the v0.16 upgrade

`egauth.Storage` holds one store per concern: `Identity`, `Ceremonies`, `Deployment`, `Limiter`, `Tokens`, `Sessions`, `MFA`, `Passkeys`, `Federation`, `Keys`. `MFA` and `Passkeys` are always required because the enrollment decision reads them on every primary login. Every security store reports one `store.Durability` (`store.Ephemeral` or persistent); a mix fails `New`.

## memstore

`memstore.New(k)` fills every field with an empty, ephemeral store; `memstore.NewWithClock(k, clock)` follows a test clock (`egauthtest.NewClock`). Ephemeral storage is accepted only on a loopback origin, or with `Insecure.EphemeralState`.

## PostgreSQL

The adapter is a separate module, `github.com/JLugagne/egauth/adapters/pgx`.

- `pgxstore.Migrate(ctx, pool)` brings every module's schema up to date: expand-only, idempotent, one transaction under an advisory lock, recorded per module and file in `egauth_schema_migrations`. It never reads or rewrites sealed data.
- `pgxstore.New(ctx, pool)` returns a filled `egauth.Storage`. It only reads, and fails with an error naming the first missing migration when one is missing.
- Both take any handle that satisfies `pgxstore.DB` or `pgxstore.MigrationDB`, such as a pool.

## Your own backend

Implement the `store/*` contracts, embed `store.Base` (and `store.Reaper` for expiring rows), and run the matching `storetest` suite against it. Contract methods that must be atomic (single-use consumption, rotation, lockout counters) are what the suites assert; a non-atomic implementation fails them.

## Sealing

Secrets at rest (TOTP seeds, OAuth client secrets, tenant signing keys) are sealed with `kek.KEK`, which requires associated data on every operation, so a blob cannot be replayed into another tenant, subject or column. `kek.NewLocal(current, previous...)` takes 32-byte keys and rotates by listing the old ones. `New` refuses a KEK that cannot open existing data.

## Upgrading from v0.16

1. `pgxstore.Migrate`.
2. `egauth.UpgradeSecretsV016(ctx, storage, legacy, newKEK)` where `legacy, err := kek.LegacyLocalV016(oldKey)`: re-seals every legacy secret with associated data. Idempotent. `egauth.ErrUpgradeIncomplete` plus a report when rows open under no legacy form.
3. `egauth.UpgradeIdentifiersV016(ctx, storage)` after draining the v0.16 replicas: re-normalises v0.16 emails and phones. Idempotent. `egauth.ErrIdentifiersHeld` plus a report for identifiers it cannot make canonical; those accounts stay readable by subject.
4. Deploy. Every user logs in again; emailed links are invalid. Credentials and API keys carry over.
5. v0.18 drops the legacy tables.
