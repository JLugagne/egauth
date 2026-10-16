-- Adds password-change tracking columns to the identities table.
--
-- password_changed_at: informational audit metadata recording when the
--   password hash was last set. NULL means the change time is unknown
--   (e.g. a legacy credential). It drives no behavior — egauth has no
--   age-based password rotation.
--
-- must_change_password: advisory flag set when an admin provisions a
--   temporary/one-time credential (AdminCreateUser, SetTemporaryPassword).
--   It never blocks authentication; it causes the next login to issue a
--   flagged, access-only token that soft-redirects to the password-change
--   page. Cleared automatically on a successful UpdateIdentityPassword write.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;
