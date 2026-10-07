-- Review F3: remember, per conversation, how far up the ladder an entity/data type has
-- already been released, so repeated requests can progress one step at a time.
-- Only levels below the high-risk threshold are ever stored here.
CREATE TABLE disclosure_state (
    session_id TEXT NOT NULL,
    entity_pseudonym TEXT NOT NULL DEFAULT '',
    data_type TEXT NOT NULL,
    granted_level INTEGER NOT NULL CHECK (granted_level BETWEEN 0 AND 5),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (session_id, entity_pseudonym, data_type)
);

-- Approvals are matched by (session, entity, data type, level), not by a hash of the
-- whole request (which changes every turn as history grows).
ALTER TABLE approvals ADD COLUMN session_id TEXT NOT NULL DEFAULT '';
