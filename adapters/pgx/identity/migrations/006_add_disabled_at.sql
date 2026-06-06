-- Adds an optional administrative-disable timestamp. A disabled account is a REVERSIBLE
-- suspension distinct from the soft delete (deleted_at): the row, its email slot and all
-- associated data are retained so the account can be re-enabled, but authentication is refused
-- while disabled_at is set. NULL means the account is active. The column is nullable with no
-- default, so existing rows are active after the migration.
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMP WITH TIME ZONE;
