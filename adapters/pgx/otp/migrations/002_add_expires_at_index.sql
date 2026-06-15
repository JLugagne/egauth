CREATE INDEX IF NOT EXISTS idx_otp_codes_tenant_expires ON otp_codes (tenant_id, expires_at);
