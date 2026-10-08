-- must_change_password gates a rotation family on a forced password change. It is set on the
-- initial pair for a flagged (admin-provisioned/temporary) credential and carried verbatim onto
-- every rotated descendant, so the forced-change soft gate survives every silent refresh and the
-- user cannot escape it by waiting for the access token to expire. Cleared only by a fresh login.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT false;
