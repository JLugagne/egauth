CREATE INDEX IF NOT EXISTS idx_sessions_tenant_expires ON sessions (tenant_id, expires_at);
