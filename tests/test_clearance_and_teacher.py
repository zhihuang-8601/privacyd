import json

from conftest import FakeTeacher, resp, user_req
from privacyd import clearance
from privacyd.teacher import OpenAITeacher


def test_clearance_binds_to_released_request(make_engine):
    e = make_engine()
    out = e.process_request(user_req("a@x.com"))
    assert clearance.verify(b"k" * 32, out["clearance_id"], out["request"])
    tampered = json.loads(json.dumps(out["request"]))
    tampered["messages"][0]["content"] = "a@x.com"
    assert not clearance.verify(b"k" * 32, out["clearance_id"], tampered)
    assert not clearance.verify(b"x" * 32, out["clearance_id"], out["request"])


def test_teacher_sees_only_scrubbed_focus_and_small_context(make_engine):
    t = FakeTeacher(lambda r: resp(sanitized_text=r.focus_text))
    e = make_engine(t, recent_context_messages=1)
    req = {"request": {"model": "m", "messages": [
        {"role": "user", "content": "old1 b@x.com"}, {"role": "assistant", "content": "old2"},
        {"role": "user", "content": "current a@x.com"}]}}
    e.process_request(req)
    seen = t.seen[0]
    assert "a@x.com" not in seen.focus_text and len(seen.recent_context) == 1
    assert "b@x.com" not in json.dumps(seen.recent_context)


def test_teacher_entities_become_soft_aliases_and_apply_at_egress(make_engine, store):
    e = make_engine()
    p = e.resolver.pseudonym_for("person", "王五")
    # Teacher "forgets" to replace 小王 in its output, but learns it as an alias
    t = FakeTeacher(resp(sanitized_text="小王 来了", entities=[
        {"mention": "小王", "candidate_entity": p, "confidence": 0.9}]))
    e.teacher = t
    out = e.process_request(user_req("小王 来了"))
    assert out["request"]["messages"][0]["content"] == f"{p} 来了"


def test_openai_teacher_parses_valid_json():
    body = {"sanitized_text": "ok", "residual_risk": "low"}
    t = OpenAITeacher("k", "m", transport=lambda *a: {"choices": [{"message": {"content": json.dumps(body)}}]})
    from privacyd.teacher import PrivacyTeacherRequest
    assert t.analyze(PrivacyTeacherRequest("t", "x")).sanitized_text == "ok"
