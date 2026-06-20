-- type classifies the key as a PAT (personal access token, human) or a service token (machine).
-- Existing rows pre-date this column; they are assumed to be service tokens (the more restricted
-- machine-identity default), which avoids silently granting human-principal status to legacy keys.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'service';

-- created_by records the uuid of the human who issued the key. NULL is valid for legacy rows
-- and for keys whose creator is not tracked.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS created_by UUID NULL;
