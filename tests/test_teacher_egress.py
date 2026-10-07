"""Review R4: nothing secret leaves in the Teacher request, including task_type."""

import pytest

from conftest import FakeTeacher, resp, user_req
from privacyd.teacher import PrivacyTeacherRequest

CANARY = "SYNTHETIC-CANARY-EXTRA-1234"


@pytest.mark.parametrize("task_type,expected", [
    (CANARY, "general"), ("hunter2", "general"), ("Email Draft!", "general"), ("x" * 40, "general"),
    (None, "general"), (42, "general"), ("email_draft", "email_draft"), ("general", "general"),
])
def test_task_type_is_a_constrained_non_secret_category(make_engine, task_type, expected):
    t = FakeTeacher(resp())
    make_engine(t, known_secrets=[CANARY, "hunter2"]).process_request({**user_req("hello"), "task_type": task_type})
    assert t.seen[0].task_type == expected


@pytest.mark.parametrize("task_type", ["token=abcdefgh12345678", "sk-abcdefghijklmnop1234",
                                       "password: hunter2xx"])
def test_secret_shaped_task_types_are_rejected_by_the_format_check(make_engine, task_type):
    t = FakeTeacher(resp())
    make_engine(t).process_request({**user_req("hello"), "task_type": task_type})
    assert t.seen[0].task_type == "general"


def test_teacher_request_gate_blocks_known_secret_anywhere(make_engine, monkeypatch):
    t = FakeTeacher(resp())
    e = make_engine(t, known_secrets=[CANARY])
    # Simulate a secret reaching the entity context (e.g. a future code path): the gate must stop it.
    import privacyd.engine as engine_mod
    monkeypatch.setattr(engine_mod, "compile_entity_context",
                        lambda store, texts: [{"pseudonym": "[PERSON_001]", "type": "person",
                                               "relations": [{"relation": CANARY, "status": "candidate"}]}])
    out = e.process_request(user_req("hello [PERSON_001]"))
    assert out == {"status": "deny", "reason": "known_secret_in_teacher_request"}
    assert t.seen == []                                # the Teacher was never called


def test_teacher_request_gate_checks_numeric_json_values(make_engine, monkeypatch):
    t = FakeTeacher(resp())
    e = make_engine(t, known_secrets=["12345678"])
    import privacyd.engine as engine_mod
    monkeypatch.setattr(engine_mod, "compile_entity_context", lambda store, texts: [{"id": 12345678}])
    assert e.process_request(user_req("hello")) == {
        "status": "deny", "reason": "known_secret_in_teacher_request"}
    assert t.seen == []
