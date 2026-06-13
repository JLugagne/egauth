ALTER TABLE passkey_credentials ADD COLUMN IF NOT EXISTS nickname TEXT NOT NULL DEFAULT '';
ALTER TABLE passkey_credentials ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE passkey_credentials ADD COLUMN IF NOT EXISTS transports TEXT[];
ALTER TABLE passkey_credentials ADD COLUMN IF NOT EXISTS backup_eligible BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE passkey_credentials ADD COLUMN IF NOT EXISTS backup_state BOOLEAN NOT NULL DEFAULT false;
