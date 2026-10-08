-- AMR (RFC 8176 authentication method references) proved when the rotation family was minted.
-- It is copied onto every rotated descendant so a stepped-up session keeps its assurance across a
-- silent refresh instead of decaying to an empty AMR (F-COMP-004). Stored as JSONB, matching the
-- claims column encoding. NULL marks a legacy row minted before the field existed and MUST read
-- back as a nil slice (never coerced to an empty one), so "no recorded assurance" stays
-- distinguishable from "assurance = []".
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS amr JSONB NULL;
