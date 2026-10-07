"""Chinese-context detector: organisations, schools, addresses, home paths, private IPs.

The regular expressions and the leading-function-word cleanup below are adapted
from yubingz/hermes-desensitize (MIT, Copyright (c) 2026 yubingz), commit 4f6697c,
`src/hermes_desensitize/plugin.py` (PATTERNS, _ORG_LEAD_STRIP).
See THIRD_PARTY_NOTICES.md for the full licence text. Person names are NOT detected
here (upstream uses jieba for that; we deliberately add no dependency in v0.1);
they come from known aliases and the Teacher.
"""

from __future__ import annotations

import re

from .base import Finding

_ORG = re.compile(
    r"(?<![一-龥])[一-龥]{2,10}"
    r"(?:有限公司|集团公司|股份有限公司|有限责任公司"
    r"|研究院|研究所|设计院|设计研究院"
    r"|支行|分行|营业部|联社|总厂|分厂"
    r"|局|委员会|办公室|办公厅)")
_SCHOOL = re.compile(r"(?<![一-龥])[一-龥]{2,8}(?:大学|学院|研究院|实验室|学校)")
_ADDRESS = re.compile(
    r"(?:[一-龥]{2,4}(?:省|自治区))?"
    r"[一-龥]{2,7}?(?:市|自治州)"
    r"[一-龥]{2,7}?(?:区|县|镇|乡|街道)"
    r"(?:[一-龥0-9]{1,8}(?:路|街|道|巷|弄|号|村|小区|栋|单元|室))?"
    r"(?![一-龥0-9])")
_PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_HOME_PATH = re.compile(
    r"/home/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.\-/]+)?"
    r"|/Users/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.\-/]+)?")
_IDCARD = re.compile(
    r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)")

# Function words the greedy hanzi range swallows from the preceding clause.
_ORG_LEAD_STRIP = "由是为对向从与和及在"


class ChineseDetector:
    def __init__(self, public_entities: set[str] | None = None):
        self.public_entities = public_entities or set()

    def detect(self, text: str) -> list[Finding]:
        out: list[Finding] = []
        for pattern, kind in ((_ORG, "org"), (_SCHOOL, "org"), (_ADDRESS, "location")):
            for m in pattern.finditer(text):
                start, end = m.span()
                while end - start > 2 and text[start] in _ORG_LEAD_STRIP:
                    start += 1
                if text[start:end] in self.public_entities:
                    continue
                out.append(Finding(start, end, kind, "pii"))
        for pattern, kind in ((_PRIVATE_IP, "ip"), (_HOME_PATH, "path"), (_IDCARD, "national_id")):
            for m in pattern.finditer(text):
                out.append(Finding(m.start(), m.end(), kind, "pii"))
        return out
