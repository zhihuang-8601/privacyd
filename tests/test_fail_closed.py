import json
import threading
import urllib.request

from conftest import FakeTeacher, resp, user_req
from privacyd.api import make_server
from privacyd.config import Config
from hermes_plugin import PrivacyMiddleware, blocked_request
from privacyd.errors import TeacherError
from privacyd.teacher import OpenAITeacher


def test_teacher_error_denies_without_plaintext(make_engine):
    e = make_engine(FakeTeacher(error=TeacherError("timeout")))
    out = e.process_request(user_req("林川 的邮箱 a@x.com"))
    assert out == {"status": "deny", "reason": "teacher_failure"}


def test_teacher_malformed_output_denies(make_engine):
    t = OpenAITeacher("k", "m", transport=lambda *a: {"choices": [{"message": {"content": "not json"}}]})
    out = make_engine(t).process_request(user_req("hi"))
    assert out["status"] == "deny"


def test_teacher_high_residual_risk_denies(make_engine):
    e = make_engine(FakeTeacher(resp(residual_risk="high")))
    assert e.process_request(user_req("hi"))["reason"] == "residual_risk_high"


def test_invalid_payload_denies(make_engine):
    assert make_engine().process_request({"nope": 1})["status"] == "deny"
    assert make_engine().process_request("x")["status"] == "deny"


def test_unexpected_exception_denies(make_engine):
    e = make_engine()
    e.scrub_text = lambda t: 1 / 0
    assert e.process_request(user_req("hi")) == {"status": "deny", "reason": "privacy_engine_error"}


def test_plugin_never_sends_raw_when_privacyd_down():
    mw = PrivacyMiddleware(endpoint="http://127.0.0.1:1/v1/process-request", timeout=1)
    req = {"model": "m", "messages": [{"role": "user", "content": "SECRET-RAW-TEXT"}], "stream": True}
    out = mw.on_llm_request(request=req)
    assert set(out) >= {"request", "source", "reason"}          # Hermes ignores anything else
    assert "SECRET-RAW-TEXT" not in json.dumps(out)
    assert set(out["request"]) == {"messages"}             # no unscreened settings copied
    assert "privacyd_unavailable" in out["reason"]


def test_blocked_request_covers_every_content_root():
    req = {"model": "m", "input": "RAW", "instructions": "RAW", "system": "RAW", "prompt": "RAW",
           "messages": [{"role": "user", "content": "RAW"}]}
    assert "RAW" not in json.dumps(blocked_request(req, "x"))
    assert "RAW" not in json.dumps(blocked_request({"unknown": "RAW"}, "x")["messages"])


def test_plugin_end_to_end_allow_and_block(make_engine):
    cfg = Config(port=0)
    port_holder = {}
    for teacher, expect_blocked in ((FakeTeacher(error=TeacherError("x")), True), (None, False)):
        server = make_server(cfg, make_engine(teacher))
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            mw = PrivacyMiddleware(endpoint=f"http://127.0.0.1:{port}/v1/process-request")
            req = {"model": "m", "messages": [{"role": "user", "content": "mail a@x.com"}]}
            out = mw.on_llm_request(request=req)
            text = json.dumps(out, ensure_ascii=False)
            assert "a@x.com" not in text
            assert ("blocked" in out["reason"]) is expect_blocked
            if not expect_blocked:
                assert "[EMAIL_001]" in out["request"]["messages"][0]["content"]
        finally:
            server.shutdown()


def test_non_loopback_bind_refused():
    import pytest
    from privacyd.errors import ConfigError
    with pytest.raises(ConfigError):
        Config(host="0.0.0.0")
