"""Exact-match known secrets (review G3)."""

import json
import logging
import os

import pytest

from conftest import FakeTeacher, resp, user_req
from privacyd.errors import ConfigError, SecretLeakError
from privacyd.known_secrets import load_known_secrets

PLAIN = "plainvalue7731"          # matches no pattern on its own


def test_values_from_env_vars_and_owner_only_file(tmp_path, monkeypatch):
    monkeypatch.setenv("MY_TOKEN", PLAIN)
    f = tmp_path / "secrets"
    f.write_text("# comment\n\nfilevalue-9921\n")
    os.chmod(f, 0o600)
    assert load_known_secrets(("MY_TOKEN", "UNSET_VAR"), str(f)) == [PLAIN, "filevalue-9921"]


def test_world_readable_secrets_file_is_refused(tmp_path):
    f = tmp_path / "secrets"
    f.write_text("x-secret-value\n")
    os.chmod(f, 0o644)
    with pytest.raises(ConfigError):
        load_known_secrets((), str(f))


def test_known_secret_is_redacted_everywhere_and_never_stored_or_logged(make_engine, store, caplog):
    caplog.set_level(logging.DEBUG)
    t = FakeTeacher(lambda r: resp(entities=[{"mention": PLAIN, "candidate_entity": None,
                                              "confidence": 0.9, "entity_type": "other"}]))
    e = make_engine(t, known_secrets=[PLAIN])
    out = e.process_request({"request": {"model": "m", "system": f"cfg {PLAIN}",
                                          "messages": [{"role": "user", "content": f"use {PLAIN} now"}]}})
    assert out["status"] == "allow"
    assert PLAIN not in json.dumps(out) and PLAIN not in json.dumps([r.__dict__ for r in t.seen])
    assert "[SECRET:known_secret]" in out["request"]["messages"][0]["content"]
    dump = json.dumps([tuple(r) for tab in ("entities", "aliases", "learning_events")
                       for r in store._q(f"SELECT * FROM {tab}")], default=str)
    assert PLAIN not in dump and PLAIN not in caplog.text


def test_store_refuses_known_literal(make_engine, store):
    make_engine(known_secrets=[PLAIN])
    with pytest.raises(SecretLeakError):
        store.get_or_create_entity("person", PLAIN)
