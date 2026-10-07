"""Secret detection. Secrets are never context: they are replaced, never mapped.

Matches are replaced by a fixed token and are never stored, hashed into a
reversible map, sent to the Teacher, or logged.
"""

from __future__ import annotations

import re
from typing import Iterable

from .base import Finding

_SECRET_KEYWORDS = (
    r"password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?token|auth[_-]?token|"
    r"token|totp[_ -]?seed|totp[_ -]?secret|recovery[_ -]?codes?|private[_-]?key|"
    r"密码|口令|密钥|恢复码"
)

# (kind, pattern, group) -- group 0 = whole match, else only that group is the secret.
_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    ("private_key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S), 0),
    ("api_key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,}"), 0),
    ("api_key", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"), 0),
    ("api_key", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), 0),
    ("api_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0),
    ("api_key", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), 0),
    ("api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}"), 0),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=\-]{16,})"), 1),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), 0),
    ("totp_seed", re.compile(r"otpauth(?:-migration)?://[^\s\"'<>]+"), 0),
    # No leading \b: '_' is a word character, so \b would miss OPENAI_API_KEY, client_secret, DB_PASSWORD.
    ("credential", re.compile(
        r"(?i)(?:" + _SECRET_KEYWORDS + r")[A-Za-z0-9_]{0,32}"
        r"[\"']?\s*(?:[:=：]|\bis\b|是|改成了?|改为|设为|设置为|换成了?)\s*[\"']?([^\s\"',;，；]+)"), 1),
    ("basic_auth", re.compile(
        r"(?i)\b(?:Proxy-)?Authorization\s*[:=]\s*Basic\s+([A-Za-z0-9+/=]{8,})"), 1),
]


class SecretDetector:
    """Regex patterns plus exact-match literals (e.g. values the Secret Broker
    has registered). Literals are held in memory only."""

    def __init__(self, literals: Iterable[str] = ()):
        self._literals: set[str] = {s for s in literals if s and len(s) >= 4}

    def add_literal(self, value: str) -> None:
        if value and len(value) >= 4:
            self._literals.add(value)

    def has_known(self, text: str) -> bool:
        """Exact-literal check only (no patterns): used as the final egress gate."""
        return any(lit in text for lit in self._literals)

    @property
    def has_literals(self) -> bool:
        return bool(self._literals)

    def detect(self, text: str) -> list[Finding]:
        found: list[Finding] = []
        for kind, pattern, group in _PATTERNS:
            for m in pattern.finditer(text):
                start, end = m.span(group)
                if end > start:
                    found.append(Finding(start, end, kind, "secret"))
        for lit in self._literals:
            idx = text.find(lit)
            while idx != -1:
                found.append(Finding(idx, idx + len(lit), "known_secret", "secret"))
                idx = text.find(lit, idx + len(lit))
        return found


SECRET_KINDS = frozenset({kind for kind, _, _ in _PATTERNS} | {"known_secret"})

_DEFAULT = SecretDetector()


def contains_secret(text: str, detector: SecretDetector | None = None) -> bool:
    return bool((detector or _DEFAULT).detect(text))
