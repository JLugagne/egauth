-- remember_me records whether the rotation family was minted with "remember me". It is set on the
-- initial pair and carried verbatim onto every rotated descendant, so the refresh cookie keeps the
-- persistence the user chose at login instead of reverting to a session cookie on the first
-- silent refresh. Legacy rows default to false (session cookie), their previous behavior.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS remember_me BOOLEAN NOT NULL DEFAULT false;
