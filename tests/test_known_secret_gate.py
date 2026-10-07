"""Review R2/R3: known secrets are checked on the whole released request."""

import json

import pytest

from conftest import user_req

CANARY = "SYNTHETIC-CANARY-EXTRA-1234"


def run(make_engine, request, secrets=(CANARY,)):
    return make_engine(known_secrets=list(secrets)).process_request({"request": request})


def test_known_secret_in_structural_field_denies(make_engine):
    out = run(make_engine, {"model": "m", "messages": [{"role": "user", "content": "hello", "id": CANARY}]})
    assert out == {"status": "deny", "reason": "known_secret_in_request"}


def test_known_secret_in_response_schema_denies(make_engine):
    out = run(make_engine, {"messages": [{"role": "user", "content": "hello"}],
                            "response_format": {"type": "json_schema", "json_schema": {
                                "name": "result", "schema": {"type": "object", "description": CANARY}}}})
    assert out == {"status": "deny", "reason": "known_secret_in_request"}


def test_known_secret_as_dict_key_denies(make_engine):
    out = run(make_engine, {"model": "m", "messages": [{"role": "user", "content": "x"}],
                            "metadata": {CANARY: "v"}})
    assert out["status"] == "deny"


@pytest.mark.parametrize("value", ["SECRET", "credential", "known_secret", "PERSON_001", "[EMAIL_002]",
                                   "EMAIL", "RSON_0", "AMBIGUOUS", "abc", "1234", "202410"])
def test_values_colliding_with_placeholders_or_too_short_are_refused(make_engine, value):
    from privacyd.errors import ConfigError
    with pytest.raises(ConfigError) as exc:
        make_engine(known_secrets=["fine-secret-value", value])
    assert value not in str(exc.value)          # the value itself is never echoed


@pytest.mark.parametrize("value", ["hunter2", "PASSWORD9", "sunshine", "Tr0ub4dor&3", "12345678", "API_KEY_VALUE"])
def test_ordinary_secret_values_are_accepted(make_engine, value):
    e = make_engine(known_secrets=[value])
    once = e.scrub_text(f"x {value} y [SECRET:api_key] [PERSON_001]")
    assert value not in once and e.scrub_text(once) == once


def test_known_secret_in_content_is_redacted_not_denied(make_engine):
    out = run(make_engine, {"model": "m", "messages": [{"role": "user", "content": f"key {CANARY}"}]})
    assert out["status"] == "allow" and CANARY not in json.dumps(out)


def test_gate_is_inert_without_known_secrets(make_engine):
    out = make_engine().process_request(user_req("hello", ))
    assert out["status"] == "allow"


def test_secret_stays_stable_across_passes(make_engine):
    e = make_engine(known_secrets=[CANARY])
    text = f"a {CANARY} b [EMAIL_001] password: hunter2xx"
    outs = [text]
    for _ in range(3):
        outs.append(e.scrub_text(outs[-1]))
    assert outs[1] == outs[2] == outs[3] and CANARY not in outs[1]


@pytest.mark.parametrize("value, literal", [(12345678, "12345678"), (1234.5678, "1234.5678"),
                                           (True, "true"), (False, "false"), (None, "null")])
def test_known_secret_in_json_scalar_denies(make_engine, value, literal):
    request = {"messages": [{"role": "user", "content": "hello"}],
               "response_format": {"type": "json_schema", "json_schema": {
                   "name": "result", "schema": {"enum": [value]}}}}
    assert run(make_engine, request, secrets=(literal,)) == {
        "status": "deny", "reason": "known_secret_in_request"}


def test_ordinary_json_scalars_survive_when_no_secret_matches(make_engine):
    request = {"model": "m", "stream": True, "temperature": 0.5,
               "messages": [{"role": "user", "content": "hello"}],
               "metadata": {"count": 12345679, "enabled": False, "empty": None}}
    out = run(make_engine, request, secrets=("12345678",))
    assert out["status"] == "allow" and out["request"] == request


@pytest.mark.parametrize("value", ["PERS", "[PERS", "PERSO", "ERSO", "[EMAI", "PERSON_", "2345]"])
def test_partial_pseudonym_collisions_are_refused(make_engine, value):
    from privacyd.errors import ConfigError
    with pytest.raises(ConfigError):
        make_engine(known_secrets=[value])


def test_json_serializable_tuples_are_checked_like_lists(make_engine):
    numeric = run(make_engine, {
        "messages": ({"role": "user", "content": "hello"},),
        "response_format": {"schema": {"enum": (12345678,)}}}, secrets=("12345678",))
    assert numeric == {"status": "deny", "reason": "known_secret_in_request"}
    text = run(make_engine, {
        "messages": ({"role": "user", "content": CANARY},),
        "tools": ({"description": CANARY},)})
    assert text["status"] == "allow" and CANARY not in json.dumps(text["request"])


def test_known_secret_split_over_tuple_content_parts_is_scrubbed(make_engine):
    parts = ({"type": "text", "text": CANARY[:12]}, {"type": "text", "text": CANARY[12:]})
    out = run(make_engine, {"messages": ({"role": "user", "content": parts},)})
    assert out["status"] == "allow"
    joined = "".join(p["text"] for p in out["request"]["messages"][0]["content"])
    assert CANARY not in joined and "[SECRET:known_secret]" in joined
