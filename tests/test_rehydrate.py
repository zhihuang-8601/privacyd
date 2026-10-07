"""Placeholder restoration (review G1): local display and allow-listed tool args only."""

import json
import threading
import urllib.error
import urllib.request

import pytest

from conftest import user_req
from hermes_plugin import PrivacyMiddleware
from privacyd.api import make_server
from privacyd.config import Config


def test_display_restores_known_pseudonyms_but_never_secrets(make_engine):
    e = make_engine()
    out = e.process_request(user_req("mail bob@corp.com, password: hunter2xx"))
    scrubbed = out["request"]["messages"][0]["content"]
    assert "[EMAIL_001]" in scrubbed and "[SECRET:credential]" in scrubbed
    r = e.rehydrate({"purpose": "display", "value": f"I wrote to {scrubbed} and [PERSON_999]"})
    assert r["status"] == "ok"
    assert "bob@corp.com" in r["value"]
    assert "hunter2xx" not in r["value"] and "[SECRET:credential]" in r["value"]
    assert "[PERSON_999]" in r["value"]          # unknown pseudonym left as is


def test_tool_args_only_for_allow_listed_tools(make_engine):
    e = make_engine()
    e.process_request(user_req("mail bob@corp.com"))
    args = {"to": "[EMAIL_001]", "nested": ["cc [EMAIL_001]"]}
    ok = e.rehydrate({"purpose": "tool_args", "tool_name": "send_email", "value": args},
                     allowed_tools=["send_email"])
    assert ok == {"status": "ok", "value": {"to": "bob@corp.com", "nested": ["cc bob@corp.com"]}}
    no = e.rehydrate({"purpose": "tool_args", "tool_name": "web_search", "value": args},
                     allowed_tools=["send_email"])
    assert no == {"status": "not_allowed", "value": args}


def test_field_level_allow_list_keeps_other_arguments_as_placeholders(make_engine):
    e = make_engine()
    e.process_request(user_req("mail bob@corp.com about 林川"))
    e.resolver.pseudonym_for("person", "林川")
    args = {"to": "[EMAIL_001]", "body": "about [PERSON_001]"}
    r = e.rehydrate({"purpose": "tool_args", "tool_name": "send_email", "value": args},
                    allowed_tools=["send_email.to"])
    assert r == {"status": "ok", "value": {"to": "bob@corp.com", "body": "about [PERSON_001]"}}
    other = e.rehydrate({"purpose": "tool_args", "tool_name": "send_sms", "value": args},
                        allowed_tools=["send_email.to"])
    assert other["status"] == "not_allowed"


@pytest.mark.parametrize("payload", [None, {}, {"purpose": "leak"}, "x"])
def test_bad_rehydrate_payload_is_denied(make_engine, payload):
    assert make_engine().rehydrate(payload)["status"] == "deny"


def _serve(engine, **cfg):
    srv = make_server(Config(port=0, **cfg), engine)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _post(port, path, body, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    rq = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=json.dumps(body).encode(),
                                method="POST", headers=headers)
    try:
        r = urllib.request.urlopen(rq)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_rehydrate_endpoint_requires_a_configured_token(make_engine):
    srv = _serve(make_engine())
    try:
        assert _post(srv.server_address[1], "/v1/rehydrate", {"purpose": "display", "value": "x"}) == \
            (503, {"status": "deny", "reason": "rehydrate_requires_token"})
    finally:
        srv.shutdown()
    srv = _serve(make_engine(), token="t0ken")
    try:
        port = srv.server_address[1]
        assert _post(port, "/v1/rehydrate", {"purpose": "display", "value": "x"})[0] == 401
        assert _post(port, "/v1/rehydrate", {"purpose": "display", "value": "x"}, "t0ken")[0] == 200
    finally:
        srv.shutdown()


def test_plugin_round_trip_through_privacyd(make_engine):
    engine = make_engine()
    srv = _serve(engine, token="t0ken", rehydrate_tools=("send_email",))
    try:
        mw = PrivacyMiddleware(endpoint=f"http://127.0.0.1:{srv.server_address[1]}/v1/process-request",
                               token="t0ken")
        out = mw.on_llm_request(request={"model": "m", "messages": [
            {"role": "user", "content": "email bob@corp.com about the plan"}]})
        assert "bob@corp.com" not in json.dumps(out)
        # the model answers / calls tools with placeholders
        assert mw.on_llm_output(response_text="Sent to [EMAIL_001].") == "Sent to bob@corp.com."
        assert mw.on_tool_request(tool_name="send_email", args={"to": "[EMAIL_001]"})["args"] == \
            {"to": "bob@corp.com"}
        assert mw.on_tool_request(tool_name="web_search", args={"q": "[EMAIL_001]"}) is None
        assert mw.on_llm_output(response_text="nothing to restore") is None
    finally:
        srv.shutdown()


def test_plugin_rehydration_fails_safe_when_privacyd_is_down():
    mw = PrivacyMiddleware(endpoint="http://127.0.0.1:1/v1/process-request", timeout=1)
    assert mw.on_llm_output(response_text="hi [EMAIL_001]") is None
    assert mw.on_tool_request(tool_name="send_email", args={"to": "[EMAIL_001]"}) is None
