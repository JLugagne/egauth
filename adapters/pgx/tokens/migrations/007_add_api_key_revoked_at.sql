-- revoked_at marks a key as soft-revoked. NULL means the key is active; a non-NULL timestamp
-- records when the key was administratively revoked. Existing rows default to NULL (active).
-- FindAPIKeyByHash still returns revoked keys with this field populated; the verify layer
-- maps a non-NULL revoked_at to ErrAPIKeyRevoked so revoked keys stay visible to management
-- tooling and produce a distinct error from not-found.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ NULL;
