CREATE INDEX IF NOT EXISTS idx_tokens_tenant_expires ON tokens (tenant_id, expires_at);
