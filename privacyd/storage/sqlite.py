"""SQLite privacy store (entities, aliases, relations, rules, events, approvals).

Secret values never belong here: every free-text write goes through `_guard`.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..detector.secrets import contains_secret
from ..errors import SecretLeakError

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

ENTITY_PREFIX = {
    "person": "PERSON", "org": "ORG", "location": "LOC", "email": "EMAIL",
    "phone": "PHONE", "national_id": "ID", "ip": "IP", "path": "PATH",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _guard_with(detector, *texts: Any) -> None:
    for t in texts:
        if isinstance(t, str) and contains_secret(t, detector):
            raise SecretLeakError("refusing to persist secret-like value")


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        self._lock = threading.RLock()
        # Set by PrivacyEngine so known secret literals are refused too (review G3).
        self.secret_detector = None
        if str(path) != ":memory:":
            # The database holds real names/emails: owner-only, even if a wider file already exists.
            fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
            os.close(fd)
            os.chmod(str(path), 0o600)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self.migrate()

    def _guard(self, *texts: Any) -> None:
        _guard_with(self.secret_detector, *texts)

    # ---- migrations -------------------------------------------------
    def migrate(self) -> None:
        with self._lock:
            current = self._db.execute("PRAGMA user_version").fetchone()[0]
            for f in sorted(MIGRATIONS_DIR.glob("*.sql")):
                version = int(f.name.split("_")[0])
                if version > current:
                    self._db.executescript(f.read_text())
                    self._db.execute(f"PRAGMA user_version = {version}")
                    self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _q(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, tuple(params)).fetchall()

    def _x(self, sql: str, params: Iterable[Any] = ()) -> int:
        with self._lock:
            cur = self._db.execute(sql, tuple(params))
            self._db.commit()
            return cur.lastrowid or 0

    # ---- entities / pseudonyms -------------------------------------
    def get_or_create_entity(self, entity_type: str, label: str,
                             sensitivity: str = "medium") -> sqlite3.Row:
        self._guard(label)
        with self._lock:
            rows = self._q("SELECT * FROM entities WHERE entity_type=? AND canonical_private_label=?",
                           (entity_type, label))
            if rows:
                return rows[0]
            n = self._q("SELECT COUNT(*) FROM entities WHERE entity_type=?", (entity_type,))[0][0] + 1
            prefix = ENTITY_PREFIX.get(entity_type, entity_type.upper())
            pseudonym = f"[{prefix}_{n:03d}]"
            now = _now()
            eid = self._x(
                "INSERT INTO entities(entity_type, canonical_private_label, stable_pseudonym,"
                " sensitivity, created_at, updated_at) VALUES (?,?,?,?,?,?)",
                (entity_type, label, pseudonym, sensitivity, now, now))
            self.add_alias(eid, label, "hard_alias", 1.0, "canonical")
            return self.get_entity(eid)

    def get_entity(self, entity_id: int) -> sqlite3.Row | None:
        rows = self._q("SELECT * FROM entities WHERE id=?", (entity_id,))
        return rows[0] if rows else None

    def get_entity_by_pseudonym(self, pseudonym: str) -> sqlite3.Row | None:
        rows = self._q("SELECT * FROM entities WHERE stable_pseudonym=?", (pseudonym,))
        return rows[0] if rows else None

    # ---- aliases -----------------------------------------------------
    def add_alias(self, entity_id: int, text: str, alias_type: str,
                  confidence: float, source: str) -> None:
        self._guard(text)
        if not text.strip():
            return
        self._x(
            "INSERT INTO aliases(entity_id, alias_text, alias_type, confidence, source, created_at)"
            " VALUES (?,?,?,?,?,?) ON CONFLICT(entity_id, alias_text) DO UPDATE SET"
            " confidence=MAX(confidence, excluded.confidence)",
            (entity_id, text, alias_type, confidence, source, _now()))

    def all_aliases(self) -> list[sqlite3.Row]:
        return self._q("SELECT alias_text, alias_type, confidence, entity_id FROM aliases")

    def alias_version(self) -> tuple[int, int]:
        """Cheap change marker for caches: (row count, max id). Aliases are insert/upsert only."""
        row = self._q("SELECT COUNT(*), COALESCE(MAX(id), 0) FROM aliases")[0]
        return (row[0], row[1])

    # ---- relations ---------------------------------------------------
    def add_relation_candidate(self, subject_id: int | None, relation_type: str,
                               object_id: int | None, object_value: str | None,
                               confidence: float, source: str) -> int:
        """Always stored as a candidate; only `verify_relation` (user) makes it fact."""
        self._guard(relation_type, object_value)
        return self._x(
            "INSERT INTO relations(subject_entity_id, relation_type, object_entity_id,"
            " object_value, confidence, source, status, created_at)"
            " VALUES (?,?,?,?,?,?, 'candidate', ?)",
            (subject_id, relation_type, object_id, object_value, min(confidence, 0.99), source, _now()))

    def verify_relation(self, relation_id: int) -> None:
        self._x("UPDATE relations SET status='verified', confidence=1.0 WHERE id=?", (relation_id,))

    def relations_for(self, entity_id: int) -> list[sqlite3.Row]:
        return self._q("SELECT * FROM relations WHERE subject_entity_id=? OR object_entity_id=?",
                       (entity_id, entity_id))

    # ---- facets --------------------------------------------------------
    def set_facet(self, entity_id: int, level: int, value: str) -> None:
        self._guard(value)
        self._x("INSERT INTO facets(entity_id, level, value, created_at) VALUES (?,?,?,?)"
                " ON CONFLICT(entity_id, level) DO UPDATE SET value=excluded.value",
                (entity_id, int(level), value, _now()))

    def best_facet(self, entity_id: int, max_level: int) -> tuple[int, str] | None:
        rows = self._q("SELECT level, value FROM facets WHERE entity_id=? AND level<=?"
                       " ORDER BY level DESC LIMIT 1", (entity_id, int(max_level)))
        return (rows[0]["level"], rows[0]["value"]) if rows else None

    # ---- rules -----------------------------------------------------------
    def get_rule(self, rule_key: str) -> sqlite3.Row | None:
        rows = self._q("SELECT * FROM privacy_rules WHERE rule_key=?", (rule_key,))
        return rows[0] if rows else None

    def observe_rule(self, task_type: str, data_type: str, level: int,
                     source: str = "local") -> sqlite3.Row:
        """Create-or-bump a rule in `shadow`. Never touches an existing rule's state."""
        self._guard(task_type, data_type)
        key = f"{task_type}:{data_type}"
        now = _now()
        with self._lock:
            if self.get_rule(key) is None:
                self._x("INSERT INTO privacy_rules(rule_key, task_type, data_type,"
                        " default_disclosure_level, state, source, created_at, updated_at)"
                        " VALUES (?,?,?,?, 'shadow', ?, ?, ?)",
                        (key, task_type, data_type, int(level), source, now, now))
            self._x("UPDATE privacy_rules SET observation_count=observation_count+1,"
                    " updated_at=? WHERE rule_key=?", (now, key))
            return self.get_rule(key)

    def record_outcome(self, rule_key: str, *, succeeded: bool, false_positive: bool = False) -> None:
        col = "success_count" if succeeded else "failure_count"
        self._x(f"UPDATE privacy_rules SET {col}={col}+1,"
                " false_positive_count=false_positive_count+?, updated_at=? WHERE rule_key=?",
                (1 if false_positive else 0, _now(), rule_key))

    def set_rule_state(self, rule_key: str, state: str, confidence: float | None = None) -> None:
        self._x("UPDATE privacy_rules SET previous_state=state, state=?, version=version+1,"
                " confidence=COALESCE(?, confidence), updated_at=? WHERE rule_key=?",
                (state, confidence, _now(), rule_key))

    def active_rule_level(self, task_type: str, data_type: str) -> int | None:
        rows = self._q("SELECT default_disclosure_level FROM privacy_rules"
                       " WHERE rule_key=? AND state='active'", (f"{task_type}:{data_type}",))
        return rows[0][0] if rows else None

    # ---- learning events -----------------------------------------------
    def add_learning_event(self, *, task_type: str, requested_information: str,
                           before_level: int | None, after_level: int | None,
                           task_succeeded: bool | None = None, user_action: str | None = None,
                           teacher_provider: str | None = None,
                           policy_version: int | None = None) -> int:
        self._guard(task_type, requested_information, user_action, teacher_provider)
        return self._x(
            "INSERT INTO learning_events(task_type, requested_information, before_level,"
            " after_level, task_succeeded, user_action, teacher_provider, policy_version,"
            " created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (task_type, requested_information, before_level, after_level,
             None if task_succeeded is None else int(task_succeeded), user_action,
             teacher_provider, policy_version, _now()))

    def learning_events(self) -> list[sqlite3.Row]:
        return self._q("SELECT * FROM learning_events ORDER BY id")

    # ---- per-session disclosure state (review F3) -------------------------------
    def session_level(self, session_id: str, entity_pseudonym: str | None, data_type: str) -> int | None:
        rows = self._q("SELECT granted_level FROM disclosure_state WHERE session_id=?"
                       " AND entity_pseudonym=? AND data_type=?",
                       (session_id, entity_pseudonym or "", data_type))
        return rows[0][0] if rows else None

    def set_session_level(self, session_id: str, entity_pseudonym: str | None, data_type: str,
                          level: int) -> None:
        self._guard(data_type)
        self._x("INSERT INTO disclosure_state(session_id, entity_pseudonym, data_type, granted_level,"
                " updated_at) VALUES (?,?,?,?,?) ON CONFLICT(session_id, entity_pseudonym, data_type)"
                " DO UPDATE SET granted_level=MAX(granted_level, excluded.granted_level),"
                " updated_at=excluded.updated_at",
                (session_id, entity_pseudonym or "", data_type, int(level), _now()))

    # ---- approvals ---------------------------------------------------------
    def create_approval(self, *, request_id: str, request_hash: str, entity_pseudonym: str | None,
                        data_type: str, requested_level: int, reason: str,
                        session_id: str = "") -> str:
        self._guard(data_type, reason)
        aid = uuid.uuid4().hex
        self._x("INSERT INTO approvals(id, request_id, request_hash, entity_pseudonym, data_type,"
                " requested_level, reason, created_at, session_id) VALUES (?,?,?,?,?,?,?,?,?)",
                (aid, request_id, request_hash, entity_pseudonym, data_type,
                 int(requested_level), reason, _now(), session_id))
        return aid

    def find_pending_approval(self, session_id: str, entity_pseudonym: str | None,
                              data_type: str, level: int) -> sqlite3.Row | None:
        rows = self._q("SELECT * FROM approvals WHERE decision='pending' AND session_id=?"
                       " AND COALESCE(entity_pseudonym,'')=COALESCE(?,'') AND data_type=?"
                       " AND requested_level=? ORDER BY created_at LIMIT 1",
                       (session_id, entity_pseudonym, data_type, int(level)))
        return rows[0] if rows else None

    def get_approval(self, approval_id: str) -> sqlite3.Row | None:
        rows = self._q("SELECT * FROM approvals WHERE id=?", (approval_id,))
        return rows[0] if rows else None

    def decide_approval(self, approval_id: str, decision: str) -> None:
        scope = "class" if decision == "allow_class" else "once"
        self._x("UPDATE approvals SET decision=?, scope=?, decided_at=? WHERE id=? AND decision='pending'",
                (decision, scope, _now(), approval_id))

    def pending_approvals(self) -> list[sqlite3.Row]:
        return self._q("SELECT * FROM approvals WHERE decision='pending' ORDER BY created_at")

    def find_class_grant(self, data_type: str, level: int) -> sqlite3.Row | None:
        rows = self._q("SELECT * FROM approvals WHERE decision='allow_class' AND data_type=?"
                       " AND requested_level>=? LIMIT 1", (data_type, int(level)))
        return rows[0] if rows else None

    def consume_once_grant(self, session_id: str, entity_pseudonym: str | None,
                           data_type: str, level: int, approval_id: str | None = None) -> bool:
        """Atomically consume a matching unconsumed allow_once approval for this session."""
        with self._lock:
            rows = self._q(
                "SELECT id FROM approvals WHERE decision='allow_once' AND consumed=0"
                " AND session_id=? AND data_type=? AND requested_level>=?"
                " AND COALESCE(entity_pseudonym,'')=COALESCE(?,'')"
                " AND (? IS NULL OR id=?) ORDER BY created_at LIMIT 1",
                (session_id, data_type, int(level), entity_pseudonym, approval_id, approval_id))
            if not rows:
                return False
            self._x("UPDATE approvals SET consumed=1 WHERE id=?", (rows[0]["id"],))
            return True
