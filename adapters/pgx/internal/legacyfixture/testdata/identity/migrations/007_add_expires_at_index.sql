CREATE INDEX IF NOT EXISTS idx_verification_tokens_tenant_expires ON verification_tokens (tenant_id, expires_at);
