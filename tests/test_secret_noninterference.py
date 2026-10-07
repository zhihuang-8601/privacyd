import logging
import json

import pytest

from conftest import FakeTeacher, resp, user_req
from privacyd.errors import SecretLeakError

CANARIES = ["sk-CANARY1234567890abcdefgh", "ghp_CANARYcanary1234567890abcd",
            "hunter2-CANARY", "AKIACANARY1234567890"]
TEXT = ("my key is sk-CANARY1234567890abcdefgh and token ghp_CANARYcanary1234567890abcd, "
        "password: hunter2-CANARY, aws AKIACANARY1234567890, 密码：hunter2-CANARY "
        "-----BEGIN RSA PRIVATE KEY-----\nMIICANARY\n-----END RSA PRIVATE KEY-----")


def test_secrets_never_reach_provider_teacher_logs_or_db(make_engine, store, caplog):
    caplog.set_level(logging.DEBUG)
    t = FakeTeacher(lambda r: resp(sanitized_text=r.focus_text))
    e = make_engine(t, known_secrets=["literal-vault-value-9"])
    out = e.process_request(user_req(TEXT + " literal-vault-value-9 a@x.com"))
    assert out["status"] == "allow"
    blob = json.dumps(out)
    sent = json.dumps([r.__dict__ for r in t.seen])
    dump = json.dumps([tuple(r) for tab in ("entities", "aliases", "relations", "facets",
                       "privacy_rules", "learning_events", "approvals")
                       for r in store._q(f"SELECT * FROM {tab}")], default=str)
    for c in CANARIES + ["literal-vault-value-9", "MIICANARY"]:
        assert c not in blob and c not in sent and c not in dump and c not in caplog.text
    assert "[SECRET:" in blob


def test_secret_in_non_message_fields_scrubbed(make_engine):
    e = make_engine()
    req = {"request": {"model": "m", "messages": [{"role": "tool", "content": "ok",
           "tool_calls": [{"function": {"arguments": '{"api_key": "sk-CANARY1234567890abcdefgh"}'}}]}]}}
    assert "CANARY" not in json.dumps(e.process_request(req))


def test_store_refuses_secret_values(store):
    with pytest.raises(SecretLeakError):
        store.get_or_create_entity("person", "sk-CANARY1234567890abcdefgh")
    with pytest.raises(SecretLeakError):
        store.add_learning_event(task_type="t", requested_information="password: abc12345",
                                 before_level=0, after_level=1)


def test_teacher_learning_cannot_store_secret_alias(make_engine, store):
    e = make_engine(FakeTeacher(resp(
        entities=[{"mention": "password: hunter2", "candidate_entity": None,
                                       "confidence": 0.9, "entity_type": "person"}])))
    # mention isn't in the (scrubbed) text it was shown, so it's ignored, not stored
    out = e.process_request(user_req("password: hunter2"))
    assert out["status"] == "allow"
    assert store._q("SELECT * FROM aliases WHERE alias_text LIKE '%hunter2%'") == []
