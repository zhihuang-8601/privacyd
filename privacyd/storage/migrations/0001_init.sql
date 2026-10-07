CREATE TABLE entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    canonical_private_label TEXT NOT NULL,
    stable_pseudonym TEXT NOT NULL UNIQUE,
    sensitivity TEXT NOT NULL DEFAULT 'medium',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (entity_type, canonical_private_label)
);

CREATE TABLE aliases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL REFERENCES entities(id),
    alias_text TEXT NOT NULL,
    alias_type TEXT NOT NULL CHECK (alias_type IN
        ('hard_alias', 'soft_alias', 'role_reference', 'contextual_reference')),
    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    source TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (entity_id, alias_text)
);
CREATE INDEX idx_aliases_text ON aliases(alias_text);

-- Relation words are mentions/candidates, never facts, until a user verifies.
CREATE TABLE relations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_entity_id INTEGER REFERENCES entities(id),
    relation_type TEXT NOT NULL,
    object_entity_id INTEGER REFERENCES entities(id),
    object_value TEXT,
    confidence REAL NOT NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'candidate'
        CHECK (status IN ('candidate', 'verified', 'rejected')),
    created_at TEXT NOT NULL
);

-- What may be said about an entity at each disclosure level (L1..L5).
CREATE TABLE facets (
    entity_id INTEGER NOT NULL REFERENCES entities(id),
    level INTEGER NOT NULL CHECK (level BETWEEN 0 AND 5),
    value TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (entity_id, level)
);

CREATE TABLE privacy_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_key TEXT NOT NULL UNIQUE,
    task_type TEXT NOT NULL,
    data_type TEXT NOT NULL,
    default_disclosure_level INTEGER NOT NULL CHECK (default_disclosure_level BETWEEN 0 AND 5),
    state TEXT NOT NULL DEFAULT 'shadow'
        CHECK (state IN ('shadow', 'candidate', 'validated', 'active')),
    previous_state TEXT,
    confidence REAL NOT NULL DEFAULT 0,
    version INTEGER NOT NULL DEFAULT 1,
    observation_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    false_positive_count INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL DEFAULT 'local',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE learning_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_type TEXT NOT NULL,
    requested_information TEXT NOT NULL,
    before_level INTEGER,
    after_level INTEGER,
    task_succeeded INTEGER,
    user_action TEXT,
    teacher_provider TEXT,
    policy_version INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE approvals (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    entity_pseudonym TEXT,
    data_type TEXT NOT NULL,
    requested_level INTEGER NOT NULL,
    reason TEXT NOT NULL,
    decision TEXT NOT NULL DEFAULT 'pending'
        CHECK (decision IN ('pending', 'denied', 'allow_once', 'allow_class')),
    scope TEXT,
    consumed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    decided_at TEXT
);
