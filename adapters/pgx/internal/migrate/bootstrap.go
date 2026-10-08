package migrate

import (
	"context"
	"errors"
	"maps"
	"slices"
)

var legacyFiles = map[string][]string{
	"identity": {
		"001_create_tables.sql", "002_add_account_lockout.sql", "003_create_verification_tokens.sql",
		"004_add_phone.sql", "005_add_recovery_email.sql", "006_add_disabled_at.sql",
		"007_add_expires_at_index.sql", "008_add_password_change_columns.sql",
	},
	"keys": {"001_create_keystore_keys_table.sql", "002_add_key_algorithm.sql"},
	"mfa": {
		"001_create_mfa_tables.sql", "002_add_totp_failed_attempts.sql", "003_add_totp_last_attempt_at.sql",
		"004_add_recovery_attempts.sql",
	},
	"federation": {"001_init.sql"},
	"otp":        {"001_create_otp_codes.sql", "002_add_expires_at_index.sql", "003_create_otp_issuances.sql"},
	"passkey": {
		"001_create_passkey_credentials.sql", "002_add_credential_management_metadata.sql",
		"003_create_passkey_challenges.sql",
	},
	"sessions": {"001_create_sessions_table.sql", "002_add_expires_at_index.sql"},
	"tokens": {
		"001_create_tokens_table.sql", "002_add_refresh_token_rotation.sql", "003_add_refresh_token_auth_time.sql",
		"004_add_expires_at_index.sql", "005_add_refresh_token_must_change_password.sql",
		"006_add_api_key_type_and_created_by.sql", "007_add_api_key_revoked_at.sql",
		"008_add_refresh_token_amr.sql", "009_add_refresh_token_remember_me.sql",
	},
}

var legacyShape = []string{"applied_at timestamp with time zone", "version text"}

const legacyShapeSQL = `SELECT coalesce(array_agg(column_name::text || ' ' || data_type::text ORDER BY column_name), '{}'::text[])
FROM information_schema.columns
WHERE table_schema = current_schema() AND table_name = 'schema_migrations'`

const legacyVersions = `SELECT coalesce(array_agg(version), '{}'::text[]) FROM schema_migrations WHERE version IS NOT NULL`

const recordBootstrapped = `INSERT INTO egauth_schema_migrations (module, version) VALUES ($1, $2) ON CONFLICT (module, version) DO NOTHING`

func legacyOwner(file string) (string, bool) {
	owner, owners := "", 0
	for _, m := range slices.Sorted(maps.Keys(legacyFiles)) {
		if slices.Contains(legacyFiles[m], file) {
			owner = m
			owners++
		}
	}
	return owner, owners == 1
}

func bootstrap(ctx context.Context, db Querier, plan []planned) error {
	var shape []string
	if err := db.QueryRow(ctx, legacyShapeSQL).Scan(&shape); err != nil {
		return errors.Join(errors.New("migrate: inspect legacy schema_migrations"), err)
	}
	if !slices.Equal(shape, legacyShape) {
		return nil
	}
	var legacy []string
	if err := db.QueryRow(ctx, legacyVersions).Scan(&legacy); err != nil {
		return errors.Join(errors.New("migrate: read legacy schema_migrations"), err)
	}
	for _, m := range plan {
		for _, f := range m.files {
			if owner, unique := legacyOwner(f); !unique || owner != m.name || !slices.Contains(legacy, f) {
				continue
			}
			if _, err := db.Exec(ctx, recordBootstrapped, m.name, f); err != nil {
				return errors.Join(errors.New("migrate: record bootstrapped version"), err)
			}
		}
	}
	return nil
}
