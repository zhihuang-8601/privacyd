import json

from conftest import user_req


def test_unknown_request_shape_is_refused(make_engine):
    out = make_engine().process_request({"request": {"model": "m", "weird": "a@x.com"}})
    assert out == {"status": "deny", "reason": "invalid_request"}


def test_non_text_content_is_refused_not_passed_through(make_engine):
    parts = [{"type": "text", "text": "look"},
             {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]
    out = make_engine().process_request(
        {"request": {"model": "m", "messages": [{"role": "user", "content": parts}]}})
    assert out == {"status": "deny", "reason": "non_text_content"}


def test_protocol_ids_and_other_fields_are_untouched(make_engine):
    req = {"model": "gpt-x", "stream": True, "temperature": 0.2, "previous_response_id": "resp_abc123",
           "input": [{"type": "function_call_output", "call_id": "call_9f2", "id": "fc_1",
                      "output": "mail a@x.com"},
                     {"role": "user", "content": "hi a@x.com"}]}
    out = make_engine().process_request({"request": req})
    assert out["status"] == "allow"
    r = out["request"]
    assert r["previous_response_id"] == "resp_abc123" and r["stream"] is True and r["model"] == "gpt-x"
    assert r["input"][0]["call_id"] == "call_9f2" and r["input"][0]["id"] == "fc_1"
    assert "a@x.com" not in json.dumps(r)


def test_system_and_instructions_roots_are_scrubbed(make_engine):
    req = {"model": "m", "system": "key sk-CANARY1234567890abcdefgh", "instructions": "a@x.com",
           "messages": [{"role": "user", "content": "x"}]}
    out = make_engine().process_request({"request": req})
    assert "CANARY" not in json.dumps(out) and "a@x.com" not in json.dumps(out)


def test_responses_api_input_string_and_original_not_mutated(make_engine):
    req = {"model": "m", "input": "write to a@x.com"}
    snapshot = json.dumps(req)
    out = make_engine().process_request({"request": req})
    assert out["request"]["input"] == "write to [EMAIL_001]"
    assert json.dumps(req) == snapshot


def test_participant_name_is_scrubbed_but_tool_names_are_not(make_engine):
    req = {"model": "m", "messages": [
        {"role": "user", "name": "bob@corp.com", "content": "hi"},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "call_1", "type": "function",
             "function": {"name": "send_email", "arguments": "{}"}}]}],
        "input": [{"type": "function_call", "name": "lookup_user", "call_id": "call_2", "arguments": "{}"}]}
    out = make_engine().process_request({"request": req})
    r = out["request"]
    assert r["messages"][0]["name"] == "[EMAIL_001]"
    assert r["messages"][1]["tool_calls"][0]["function"]["name"] == "send_email"
    assert r["input"][0]["name"] == "lookup_user"


def test_extra_fields_are_scrubbed_but_do_not_make_a_shape_known(make_engine):
    e = make_engine()
    out = e.process_request({"request": {
        "model": "m", "messages": [{"role": "user", "content": "x"}],
        "metadata": {"user": "bob@corp.com"}, "user": "alice@corp.com",
        "extra_body": {"note": "key sk-CANARY1234567890abcdef"},
        "tools": [{"type": "function", "function": {"name": "f", "description": "call 13812345678",
                   "parameters": {"type": "object", "properties": {"to": {"type": "string"}}}}}]}})
    blob = json.dumps(out, ensure_ascii=False)
    for raw in ("bob@corp.com", "alice@corp.com", "CANARY", "13812345678"):
        assert raw not in blob
    assert out["request"]["tools"][0]["function"]["name"] == "f"
    assert e.process_request({"request": {"model": "m", "metadata": {"a": "b"}}})["status"] == "deny"


def test_secret_split_across_text_parts_is_redacted(make_engine):
    parts = [{"type": "text", "text": "key sk-CANARY1234567"},
             {"type": "text", "text": "890abcdefghijk and more"}]
    out = make_engine().process_request(
        {"request": {"model": "m", "messages": [{"role": "user", "content": parts}]}})
    texts = [p["text"] for p in out["request"]["messages"][0]["content"]]
    assert "CANARY" not in json.dumps(out) and "abcdefghijk" not in json.dumps(out)
    assert texts == ["key [SECRET:api_key]", " and more"]
