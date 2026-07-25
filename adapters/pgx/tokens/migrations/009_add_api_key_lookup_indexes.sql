-- RevokeAPIKey looks a key up by WHERE id = $1 AND tenant_id = $2 AND claims IS NOT NULL, and
-- ListAPIKeysByCreator / RevokeAllAPIKeysForUser both filter WHERE tenant_id = $1 AND
-- created_by = $2 AND claims IS NOT NULL. Neither id nor created_by is covered by the table's
-- PRIMARY KEY (tenant_id, token_hash) or by any existing index (idx_tokens_user_id,
-- idx_tokens_family_id, idx_tokens_tenant_expires), so both queries sequential-scan the tokens
-- table — the highest-churn table in the schema. Both new indexes are scoped to API-key rows
-- (claims IS NOT NULL) since refresh tokens never populate id/created_by lookups.
CREATE INDEX IF NOT EXISTS idx_tokens_id ON tokens (tenant_id, id) WHERE claims IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tokens_created_by ON tokens (tenant_id, created_by) WHERE claims IS NOT NULL;
