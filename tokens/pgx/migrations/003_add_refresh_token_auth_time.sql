-- auth_time anchors step-up / "sudo mode" freshness: the time the subject actually
-- authenticated, preserved across refresh-token rotation (unlike the per-token created_at).
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS auth_time TIMESTAMPTZ NULL;
