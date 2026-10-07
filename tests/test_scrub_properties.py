"""Scrubbing must be idempotent: the egress pass re-scrubs already scrubbed text."""

import pytest

SAMPLES = [
    "my key sk-CANARY1234567890abcdef",
    "secret: hunter2xx",
    "OPENAI_API_KEY=abcdef0123456789abcd and DB_PASSWORD=Hunter2024x",
    "Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==",
    "mail bob@corp.com or call 138-1234-5678",
    "本项目由北京某某科技有限公司承建，地址在广东省深圳市南山区科技路18号",
    "身份证 110101199003074518，私钥 -----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----",
    "already scrubbed [PERSON_001] [SECRET:api_key] [EMAIL_002] [AMBIGUOUS_ENTITY]",
    "password: [SECRET:credential]",
]


@pytest.mark.parametrize("text", SAMPLES)
def test_scrub_is_idempotent(make_engine, text):
    e = make_engine()
    e.resolver.pseudonym_for("person", "王五")
    once = e.scrub_text(text)
    assert e.scrub_text(once) == once
    assert "[SECRET:[SECRET" not in once


def test_existing_placeholders_are_left_alone(make_engine):
    text = "already scrubbed [PERSON_001] [SECRET:api_key] [EMAIL_002] [AMBIGUOUS_ENTITY]"
    assert make_engine().scrub_text(text) == text
