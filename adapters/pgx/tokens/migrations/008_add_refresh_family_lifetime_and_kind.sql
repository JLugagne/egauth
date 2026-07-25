-- family_created_at anchors the ABSOLUTE lifetime of a refresh-token family: it equals created_at
-- on the initial pair and is carried unchanged onto every rotated descendant, so each rotation's
-- expires_at can be clamped to family_created_at + MaxRefreshFamilyLifetime instead of resetting
-- the full RefreshTTL. A stolen token kept warm by continuous rotation therefore cannot keep the
-- family alive forever. NULL marks a legacy row written before the cap existed; the issuer then
-- falls back to that row's created_at as the anchor.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS family_created_at TIMESTAMPTZ NULL;

-- kind records the principal classification (user / pat / service) of the credential that started
-- a rotation family. Like auth_time and must_change_password it is set on the initial pair and
-- replayed verbatim onto every rotated descendant, so a Service/PAT family cannot silently become a
-- human one after a refresh and a WithRequiredKind gate keeps holding down the whole chain. NULL /
-- empty means "unclassified", which the middleware normalises to the human default.
ALTER TABLE tokens ADD COLUMN IF NOT EXISTS kind TEXT NULL;
