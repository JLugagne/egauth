-- Adds password-rotation tracking columns to the identities table.
--
-- password_changed_at: records when the password hash was last set.
--   NULL means the change time is unknown (legacy credential) and is
--   treated as NOT due for rotation — age-based evaluation must treat
--   NULL/zero as not-due to avoid flagging every pre-existing user.
--
-- must_change_password: advisory flag set by admin provisioning or the
--   rotation-policy evaluator. It never blocks authentication; it causes
--   the next login to issue a flagged, access-only token that soft-redirects
--   to the password-change page. Cleared automatically on a successful
--   UpdateIdentityPassword write.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;
