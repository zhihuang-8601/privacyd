"""Conservative regex PII detector (email, phone, national ID)."""

from __future__ import annotations

import re

from .base import Finding

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Anchored at the start of a run and bounded (RFC 5321 limits): the previous unbounded
    # pattern was quadratic on long alphanumeric lines (214s for 300k chars).
    ("email", re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,}")),
    ("national_id", re.compile(r"(?<!\d)\d{17}[\dXx](?![\dXx])")),
    ("phone", re.compile(r"(?<!\d)1[3-9]\d[ \-]?\d{4}[ \-]?\d{4}(?!\d)")),
    ("phone", re.compile(r"(?<!\d)\+\d{1,3}[ \-]?\(?\d{2,4}\)?[ \-]?\d{3,4}[ \-]?\d{3,4}(?!\d)")),
]


class RegexPiiDetector:
    def detect(self, text: str) -> list[Finding]:
        out: list[Finding] = []
        for kind, pattern in _PATTERNS:
            for m in pattern.finditer(text):
                out.append(Finding(m.start(), m.end(), kind, "pii"))
        return out
