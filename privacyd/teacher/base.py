"""Provider-neutral Privacy Teacher contract with strict validation.

The Teacher only *annotates*: it says which exact substrings of the (already locally
scrubbed) text are private. It never writes outbound text: `sanitized_text` is an
optional hint the gateway diffs against the original to find more annotations, and
is otherwise discarded. Pseudonyms are always allocated by the gateway. Nothing here
touches active policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from ..errors import TeacherError

RISKS = ("low", "medium", "high")
IMPORTANCE = ("low", "medium", "high")


@dataclass
class PrivacyTeacherRequest:
    task_type: str
    focus_text: str                       # already locally scrubbed
    recent_context: list[dict] = field(default_factory=list)   # [{"role","text"}] scrubbed
    entity_context: list[dict] = field(default_factory=list)   # pseudonym-level only


@dataclass
class TeacherEntity:
    mention: str
    candidate_entity: str | None
    confidence: float
    entity_type: str | None = None


@dataclass
class NeedMoreContext:
    required: bool
    type: str = ""
    minimum_detail: str = ""
    reason: str = ""
    entity: str | None = None
    importance: str = "medium"


@dataclass
class LearningCandidate:
    data_type: str
    task_type: str
    level: int


@dataclass
class PrivacyTeacherResponse:
    sanitized_text: str                   # optional hint only; never sent anywhere
    residual_risk: str
    entities: list[TeacherEntity] = field(default_factory=list)
    need_more_context: NeedMoreContext = field(default_factory=lambda: NeedMoreContext(False))
    candidate_patterns: list[LearningCandidate] = field(default_factory=list)


class PrivacyTeacher(Protocol):
    name: str

    def analyze(self, request: PrivacyTeacherRequest) -> PrivacyTeacherResponse: ...


def _bad(msg: str) -> TeacherError:
    return TeacherError(f"invalid teacher response: {msg}")


def parse_teacher_response(data: Any) -> PrivacyTeacherResponse:
    if not isinstance(data, dict):
        raise _bad("not an object")
    text = data.get("sanitized_text", "")
    if not isinstance(text, str):
        raise _bad("sanitized_text")
    risk = data.get("residual_risk")
    if risk not in RISKS:
        raise _bad("residual_risk")

    entities: list[TeacherEntity] = []
    for e in data.get("entities") or []:
        if not isinstance(e, dict) or not isinstance(e.get("mention"), str):
            raise _bad("entities")
        conf = e.get("confidence")
        if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not 0 <= conf <= 1:
            raise _bad("entities.confidence")
        cand = e.get("candidate_entity")
        if cand is not None and not isinstance(cand, str):
            raise _bad("entities.candidate_entity")
        etype = e.get("entity_type")
        if etype is not None and not isinstance(etype, str):
            raise _bad("entities.entity_type")
        entities.append(TeacherEntity(e["mention"], cand, float(conf), etype))

    need = NeedMoreContext(False)
    n = data.get("need_more_context")
    if n is not None:
        if not isinstance(n, dict) or not isinstance(n.get("required"), bool):
            raise _bad("need_more_context")
        if n["required"]:
            for k in ("type", "minimum_detail", "reason"):
                if not isinstance(n.get(k), str) or not n[k]:
                    raise _bad(f"need_more_context.{k}")
            imp = n.get("importance", "medium")
            if imp not in IMPORTANCE:
                raise _bad("need_more_context.importance")
            ent = n.get("entity")
            if ent is not None and not isinstance(ent, str):
                raise _bad("need_more_context.entity")
            need = NeedMoreContext(True, n["type"], n["minimum_detail"], n["reason"], ent, imp)

    patterns: list[LearningCandidate] = []
    learning = data.get("learning") or {}
    if not isinstance(learning, dict):
        raise _bad("learning")
    for p in learning.get("candidate_patterns") or []:
        if (not isinstance(p, dict) or not isinstance(p.get("data_type"), str)
                or not isinstance(p.get("task_type"), str)
                or not isinstance(p.get("level"), int) or isinstance(p.get("level"), bool)
                or not 0 <= p["level"] <= 5):
            raise _bad("learning.candidate_patterns")
        patterns.append(LearningCandidate(p["data_type"], p["task_type"], p["level"]))

    return PrivacyTeacherResponse(text, risk, entities, need, patterns)
