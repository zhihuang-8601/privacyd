"""Regression tests for detector fixes (review F5-F8) plus false-positive guards."""

import time

import pytest

from privacyd.detector import RegexPiiDetector, SecretDetector


@pytest.mark.parametrize("text,secret", [
    ("OPENAI_API_KEY=abcdef0123456789abcdef", "abcdef0123456789abcdef"),
    ('{"client_secret": "Zx81kQp0LmN4"}', "Zx81kQp0LmN4"),
    ("DB_PASSWORD=Hunter2024x", "Hunter2024x"),
    ("我把密码改成了 Hunter2024!", "Hunter2024!"),
    ("Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==", "dXNlcjpwYXNzd29yZDEyMw=="),
])
def test_secret_forms_are_matched_exactly(text, secret):
    found = [text[f.start:f.end] for f in SecretDetector().detect(text)]
    assert secret in found


@pytest.mark.parametrize("text", [
    "Basic introduction to Python",      # 'Basic' alone is not an auth header
    "the token count is fine",
    "我们讨论了密码学的历史",
    "max_tokens limits the output",
])
def test_ordinary_text_is_not_flagged_as_secret(text):
    assert SecretDetector().detect(text) == []


@pytest.mark.parametrize("phone", ["13812345678", "138-1234-5678", "138 1234 5678"])
def test_mobile_number_formats(phone):
    text = f"call {phone} now"
    assert [text[f.start:f.end] for f in RegexPiiDetector().detect(text)] == [phone]


@pytest.mark.parametrize("text", ["call 1381234 later", "order 2024-1234-5678-99", "x" * 50 + "@"])
def test_phone_and_email_false_positives(text):
    assert RegexPiiDetector().detect(text) == []


@pytest.mark.parametrize("text,email", [
    ("mail Bob.Smith@Example.COM now", "Bob.Smith@Example.COM"),
    ("id=abc@x.com", "abc@x.com"),
    ("邮箱是bob@corp.com", "bob@corp.com"),
])
def test_emails_still_found_after_anchoring(text, email):
    assert [text[f.start:f.end] for f in RegexPiiDetector().detect(text)] == [email]


@pytest.mark.parametrize("blob", ["a" * 300_000, "QUJD" * 75_000, "1" * 300_000, "a." * 150_000])
def test_detectors_are_linear_on_long_lines(blob):
    t = time.time()
    RegexPiiDetector().detect(blob)
    SecretDetector().detect(blob)
    assert time.time() - t < 2.0   # was 214s for 300k chars
