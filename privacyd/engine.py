"""Request processing: scrub -> (Teacher) -> disclosure decision -> egress gate.

Fail closed: any error becomes `deny` with a content-free reason code. The
original request is never returned except as scrubbed output of `allow`.
"""

from __future__ import annotations

import copy
import dataclasses
import difflib
import json
import logging
import re
import uuid
from typing import Any, Callable, Iterable

from . import clearance
from .detector import ChineseDetector, Detector, RegexPiiDetector, SecretDetector
from .detector.secrets import SECRET_KINDS
from .detector.base import Finding
from .entity import EntityResolver
from .errors import ConfigError, InvalidRequestError, PrivacydError, TeacherError
from .learning.events import record_disclosure
from .policy.disclosure import decide
from .policy.levels import HIGH_RISK_MIN, Level, level_for_detail
from .retrieval.privacy_context import compile_entity_context
from .storage import Store
from .storage.sqlite import ENTITY_PREFIX
from .teacher import PrivacyTeacher, PrivacyTeacherRequest, PrivacyTeacherResponse

log = logging.getLogger("privacyd")  # never log request content

# Only these top-level request fields carry model-visible text. Anything else is
# left untouched; a request with none of them is an unknown shape and is refused
# (guessing which strings are content vs protocol ids either leaks or corrupts).
CONTENT_ROOTS = ("messages", "input", "instructions", "prompt", "system")
# Other top-level fields that can carry user data (tool descriptions written for this user,
# end-user ids, provider metadata). Scrubbed too, but they do not make a request "known".
EXTRA_SCRUB_ROOTS = ("tools", "metadata", "user", "extra_body")

# Structural keys whose string values are protocol data, not user content. Rewriting
# them would break provider APIs (e.g. Responses item ids accept a restricted charset).
PASS_KEYS = {"model", "role", "type", "id", "call_id", "tool_call_id", "tool_use_id",
             "item_id", "previous_response_id", "status", "finish_reason", "object",
             "tool_choice", "response_format", "format"}
# `name` is a tool/function identifier in tool definitions and calls, but the *participant*
# name (often a real person or an email) inside a chat message, i.e. a dict that has `role`.
CONDITIONAL_PASS_KEYS = {"name"}

# Teacher annotations: entity types the gateway allocates pseudonyms for, and limits on
# what a mention may look like (no placeholders, no tiny or huge spans).
TEACHER_ENTITY_TYPES = {"person", "org", "location", "other"}
_PLACEHOLDER = re.compile(r"\[(?:[A-Z]+_\d{3}|AMBIGUOUS_ENTITY|SECRET:[a-z_]+)\]")
_PLACEHOLDER_TYPE = {"PERSON": "person", "ORG": "org", "LOC": "location"}
MENTION_MIN, MENTION_MAX = 2, 40
# If the Teacher's rewrite changes too much of the text OTHER than by inserting placeholders,
# it is not a redaction but a different text (e.g. injected instructions): refuse.
MAX_UNEXPLAINED_CHARS, MAX_UNEXPLAINED_RATIO = 8, 0.3

# Gateway pseudonyms that may be turned back into real values locally (secrets never can:
# they are not stored, and `[SECRET:...]` does not match this pattern).
PSEUDONYM = re.compile(r"\[[A-Z]+_\d{3}\]")
REHYDRATE_PURPOSES = ("display", "tool_args")

# Content parts that text scrubbing cannot protect.
NON_TEXT_TYPES = {"image", "image_url", "input_image", "audio", "input_audio", "file",
                  "input_file", "document", "video"}


def has_non_text(obj: Any) -> bool:
    if isinstance(obj, list):
        return any(has_non_text(v) for v in obj)
    if isinstance(obj, dict):
        return obj.get("type") in NON_TEXT_TYPES or any(has_non_text(v) for v in obj.values())
    return False


def deny(reason: str) -> dict:
    return {"status": "deny", "reason": reason}


def map_strings(obj: Any, fn: Callable[[str], str]) -> Any:
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, (list, tuple)):
        return [map_strings(v, fn) for v in obj]
    if isinstance(obj, dict):
        is_message = "role" in obj
        return {k: (v if isinstance(v, str) and (k in PASS_KEYS or
                                                 (k in CONDITIONAL_PASS_KEYS and not is_message))
                    else map_strings(v, fn))
                for k, v in obj.items()}
    return obj


Loc = tuple[str, int, "int | None"]   # (root key, message index, content-part index)


def _focus_location(request: dict) -> Loc | None:
    for root in ("messages", "input"):
        msgs = request.get(root)
        if not isinstance(msgs, list):
            continue
        for i in range(len(msgs) - 1, -1, -1):
            m = msgs[i]
            if not isinstance(m, dict) or m.get("role") != "user":
                continue
            c = m.get("content")
            if isinstance(c, str):
                return (root, i, None)
            if isinstance(c, list):
                for j in range(len(c) - 1, -1, -1):
                    if isinstance(c[j], dict) and isinstance(c[j].get("text"), str):
                        return (root, i, j)
            return None
    return None


def _get_text(request: dict, loc: Loc) -> str:
    c = request[loc[0]][loc[1]]["content"]
    return c if loc[2] is None else c[loc[2]]["text"]


def _set_text(request: dict, loc: Loc, text: str) -> None:
    m = request[loc[0]][loc[1]]
    if loc[2] is None:
        m["content"] = text
    else:
        m["content"][loc[2]]["text"] = text


def _message_texts(request: dict, before: Loc, n: int) -> list[dict]:
    out: list[dict] = []
    for m in request.get(before[0], [])[: before[1]]:
        if not isinstance(m, dict):
            continue
        c = m.get("content")
        if isinstance(c, list):
            c = " ".join(p["text"] for p in c if isinstance(p, dict) and isinstance(p.get("text"), str))
        if isinstance(c, str) and c:
            out.append({"role": str(m.get("role", "")), "text": c})
    return out[-n:] if n > 0 else []


def _mentions_from_rewrite(original: str, rewrite: str) -> list[tuple[str, str]] | None:
    """Spans of `original` that the Teacher's rewrite replaced by a bracketed placeholder,
    with a type guessed from that placeholder.

    Replacing a span with a placeholder is a redaction and is "explained". Any other change
    (rewording, insertions, deletions) is "unexplained"; too much of it means the rewrite is
    not a redaction of this text at all (e.g. injected instructions), so return None.
    The rewrite itself is never sent anywhere.
    """
    if not rewrite or rewrite == original:
        return []
    sm = difflib.SequenceMatcher(None, original, rewrite, autojunk=False)
    unexplained, out = 0, []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            continue
        span, repl = original[i1:i2].strip(), rewrite[j1:j2].strip()
        m = re.fullmatch(r"\[([A-Z]+)[^\[\]]*\]", repl)
        if op == "replace" and span and m:
            out.append((span, _PLACEHOLDER_TYPE.get(m.group(1), "other")))
        else:
            unexplained += max(i2 - i1, j2 - j1)
    if unexplained > max(MAX_UNEXPLAINED_CHARS, MAX_UNEXPLAINED_RATIO * len(original)):
        return None
    return out


MIN_KNOWN_SECRET_LEN = 4
_TASK_TYPE = re.compile(r"[a-z][a-z0-9_]{0,31}")


def known_secret_problem(value: str) -> str | None:
    """Why a value cannot be registered as a known secret, or None if it can.

    A value that is part of our own placeholder vocabulary would be re-detected inside the
    placeholders we generate: e.g. "SECRET" made the text grow on every pass and denied every
    request; "PERSON_001" collides with a real pseudonym. Conflicting values are refused
    explicitly instead of silently corrupting generated placeholders.
    """
    if not isinstance(value, str) or len(value) < MIN_KNOWN_SECRET_LEN:
        return f"shorter than {MIN_KNOWN_SECRET_LEN} characters"
    vocabulary = [f"[SECRET:{k}]" for k in SECRET_KINDS] + ["[AMBIGUOUS_ENTITY]"]
    prefixes = set(ENTITY_PREFIX.values()) | {"OTHER"}
    vocabulary.extend(f"[{p}_" for p in prefixes)
    if any(value in v for v in vocabulary):
        return "part of the placeholder vocabulary"
    suffixes = sorted({p[i:] for p in prefixes for i in range(len(p))}, key=len, reverse=True)
    if (re.fullmatch(r"\[?(?:" + "|".join(suffixes) + r")?(?:_\d*)?\]?", value)
            or re.fullmatch(r"\d+\]", value)):
        return "looks like a pseudonym"
    if value.isdigit() and len(value) <= 6:
        return "a short number (would collide with pseudonym numbering and ordinary numbers)"
    return None


class PrivacyEngine:
    def __init__(self, store: Store, *, teacher: PrivacyTeacher | None = None,
                 clearance_key: bytes | None = None,
                 known_secrets: Iterable[str] = (),
                 detectors: list[Detector] | None = None,
                 recent_context_messages: int = 2):
        self.store = store
        self.teacher = teacher
        self.resolver = EntityResolver(store)
        known_secrets = list(known_secrets)
        bad = [known_secret_problem(v) for v in known_secrets]
        if any(bad):
            # Never include the value itself in the message.
            raise ConfigError("known secret #%d rejected: %s" % next(
                (i + 1, b) for i, b in enumerate(bad) if b))
        self.secret_detector = SecretDetector(known_secrets)
        store.secret_detector = self.secret_detector      # the store refuses known literals too
        self.detectors: list[Detector] = (detectors if detectors is not None
                                          else [RegexPiiDetector(), ChineseDetector()])
        if not clearance_key or len(clearance_key) < 16:
            raise ConfigError("a clearance key of at least 16 bytes is required")
        self._key = clearance_key
        self._recent_n = recent_context_messages

    # ---- public ----------------------------------------------------------
    def process_request(self, payload: Any) -> dict:
        try:
            return self._process(payload)
        except PrivacydError as exc:
            log.warning("deny: %s", exc.code)
            return deny(exc.code)
        except Exception as exc:  # fail closed on anything unexpected
            log.warning("deny: internal %s", type(exc).__name__)
            return deny("privacy_engine_error")

    # ---- rehydration (review G1) ------------------------------------------------
    def rehydrate(self, payload: Any, allowed_tools: Iterable[str] = ()) -> dict:
        """Replace gateway pseudonyms with real values for LOCAL use only.

        purpose=display: the final answer shown to the user (Hermes stores it; the next
        outbound request is scrubbed again, so pseudonyms stay stable).
        purpose=tool_args: only for tools on the explicit allow-list (default: none); other
        tools receive the placeholders unchanged. Fails closed: on any error nothing is
        rehydrated.
        """
        try:
            if not isinstance(payload, dict) or payload.get("purpose") not in REHYDRATE_PURPOSES:
                raise InvalidRequestError("bad rehydrate payload")
            value = payload.get("value")
            if payload["purpose"] == "display":
                return {"status": "ok", "value": self._rehydrate_value(value)}
            # Allow-list entries: "tool" (every argument) or "tool.field" (only that
            # top-level argument, e.g. send_email.to, so the body cannot carry real names).
            tool = payload.get("tool_name")
            entries = set(allowed_tools)
            if tool in entries:
                return {"status": "ok", "value": self._rehydrate_value(value)}
            fields = {e.split(".", 1)[1] for e in entries if e.startswith(f"{tool}.")} if tool else set()
            if not fields or not isinstance(value, dict):
                return {"status": "not_allowed", "value": value}
            return {"status": "ok", "value": {k: (self._rehydrate_value(v) if k in fields else v)
                                              for k, v in value.items()}}
        except PrivacydError as exc:
            return deny(exc.code)
        except Exception as exc:
            log.warning("rehydrate deny: internal %s", type(exc).__name__)
            return deny("privacy_engine_error")

    def _rehydrate_value(self, value: Any) -> Any:
        if isinstance(value, str):
            def real(m: re.Match) -> str:
                ent = self.store.get_entity_by_pseudonym(m.group(0))
                return ent["canonical_private_label"] if ent else m.group(0)
            return PSEUDONYM.sub(real, value)
        if isinstance(value, list):
            return [self._rehydrate_value(v) for v in value]
        if isinstance(value, dict):
            return {k: self._rehydrate_value(v) for k, v in value.items()}
        return value

    # ---- scrubbing ---------------------------------------------------------
    def _safe_task_type(self, value: Any) -> str:
        """task_type leaves the machine (Teacher prompt) and is stored: only a short,
        non-secret category name is accepted (review R4)."""
        if (isinstance(value, str) and _TASK_TYPE.fullmatch(value)
                and not self.secret_detector.has_known(value) and not self.secret_detector.detect(value)):
            return value
        return "general"

    def _contains_known_secret(self, obj: Any) -> bool:
        if not self.secret_detector.has_literals:
            return False
        if isinstance(obj, str):
            return self.secret_detector.has_known(obj)
        if isinstance(obj, (list, tuple)):
            return any(self._contains_known_secret(v) for v in obj)
        if isinstance(obj, dict):
            return any(self._contains_known_secret(k) or self._contains_known_secret(v)
                       for k, v in obj.items())
        if obj is None or isinstance(obj, (bool, int, float)):
            # JSON scalars can carry a secret too (schema enums, numeric IDs, etc.).
            # Check their actual JSON representation rather than Python's True/None spellings.
            return self.secret_detector.has_known(json.dumps(obj, allow_nan=False))
        return False

    def _redact_split_secrets(self, obj: Any) -> Any:
        """A secret split across consecutive text parts of one message is invisible to
        per-string detection. Detect on the joined text and blank the covered pieces of
        every part (review G2). Applies to any list of {"text": str} parts."""
        if isinstance(obj, (list, tuple)):
            obj = list(obj)  # direct Python callers may supply JSON-serializable tuples
            obj = [self._redact_split_secrets(v) for v in obj]
            idx = [i for i, v in enumerate(obj) if isinstance(v, dict) and isinstance(v.get("text"), str)]
            if len(idx) < 2:
                return obj
            texts = [obj[i]["text"] for i in idx]
            joined = "".join(texts)
            spans = [(f.start, f.end, f.kind) for f in self.secret_detector.detect(joined)]
            if not spans:
                return obj
            offset = 0
            for i, t in zip(idx, texts):
                lo, hi = offset, offset + len(t)
                out, cursor = [], lo
                for a, b, kind in sorted(spans):
                    if b <= lo or a >= hi or (a >= lo and b <= hi):
                        continue               # not crossing this part's boundary: normal pass handles it
                    s_, e_ = max(a, lo), min(b, hi)
                    out.append(joined[cursor:s_])
                    out.append(f"[SECRET:{kind}]" if s_ == a else "")
                    cursor = e_
                out.append(joined[cursor:hi])
                obj[i] = {**obj[i], "text": "".join(out)}
                offset = hi
            return obj
        if isinstance(obj, dict):
            return {k: self._redact_split_secrets(v) for k, v in obj.items()}
        return obj

    def scrub_text(self, text: str) -> str:
        findings: list[Finding] = list(self.secret_detector.detect(text))
        for d in self.detectors:
            findings.extend(d.detect(text))
        findings.extend(self.resolver.find_mentions(text))
        # Never re-detect inside our own placeholders: `[SECRET:api_key]` contains a credential
        # keyword, and the egress pass relies on scrubbing being idempotent.
        # Known secret literals are never exempt (review R3): a placeholder-shaped string
        # in the input is not proof that it came from us.
        protected = [m.span() for m in _PLACEHOLDER.finditer(text)]
        if protected:
            findings = [f for f in findings if f.kind == "known_secret"
                        or all(f.end <= a or f.start >= b for a, b in protected)]
        accepted: list[Finding] = []
        for f in sorted(findings, key=lambda f: (-f.priority, -f.length, f.start)):
            if all(f.end <= a.start or f.start >= a.end for a in accepted):
                accepted.append(f)
        out = text
        for f in sorted(accepted, key=lambda f: f.start, reverse=True):
            if f.category == "secret":
                rep = f"[SECRET:{f.kind}]"
            elif f.category == "pii":
                rep = self.resolver.pseudonym_for(f.kind, text[f.start:f.end])
            else:
                rep = self.resolver.replacement(f)
            out = out[:f.start] + rep + out[f.end:]
        return out

    # ---- core --------------------------------------------------------------
    def _process(self, payload: Any) -> dict:
        if not isinstance(payload, dict) or not isinstance(payload.get("request"), dict):
            raise InvalidRequestError("payload.request must be an object")
        original: dict = payload["request"]
        task_type = self._safe_task_type(payload.get("task_type"))
        request_id = uuid.uuid4().hex
        request_hash = clearance.canonical_hash(original)
        approval_id = payload.get("approval_id")
        session_id = str(payload.get("session_id") or "")

        roots = [k for k in CONTENT_ROOTS if k in original]
        if not roots:
            raise InvalidRequestError("unrecognised request shape")
        if any(has_non_text(original[k]) for k in roots):
            return deny("non_text_content")

        safe = copy.deepcopy(original)
        roots = roots + [k for k in EXTRA_SCRUB_ROOTS if k in original]
        for k in roots:
            safe[k] = self._redact_split_secrets(safe[k])
            safe[k] = map_strings(safe[k], self.scrub_text)
        notes: list[str] = []
        disclosures: list[dict] = []

        loc = _focus_location(safe) if self.teacher else None
        if self.teacher and loc is not None:
            focus = _get_text(safe, loc)
            recent = _message_texts(safe, loc, self._recent_n)
            teacher_req = PrivacyTeacherRequest(
                task_type=task_type, focus_text=focus, recent_context=recent,
                entity_context=compile_entity_context(
                    self.store, [focus] + [r["text"] for r in recent]))
            # Egress gate for the Teacher too (review R4): the whole body, not just the focus.
            if self._contains_known_secret(dataclasses.asdict(teacher_req)):
                return deny("known_secret_in_teacher_request")
            resp = self.teacher.analyze(teacher_req)
            if resp.residual_risk == "high":
                return deny("residual_risk_high")
            # The Teacher never writes outbound text. Its rewrite (if any) is only diffed
            # against the original to find more mentions; everything is then replaced by
            # gateway-owned pseudonyms in ALL messages by the egress pass below.
            hinted = _mentions_from_rewrite(focus, resp.sanitized_text)
            if hinted is None:
                return deny("teacher_output_rejected")
            self._ingest_entities(resp, hinted, [focus] + [r["text"] for r in recent])

            if resp.need_more_context.required:
                result = self._handle_need(resp, task_type, request_id, request_hash,
                                           approval_id, disclosures, session_id)
                if result is not None:
                    return result
            for c in resp.candidate_patterns:
                self.store.observe_rule(c.task_type, c.data_type, c.level, source=self.teacher.name)

        # Egress gate: re-scrub everything (idempotent; catches Teacher output that
        # still contains a known alias/secret) and append any approved disclosure.
        for k in roots:
            safe[k] = map_strings(safe[k], self.scrub_text)
        if disclosures and loc is not None:
            note = "\n\n" + "\n".join(f"[privacy-gateway: {d['note']}]" for d in disclosures)
            _set_text(safe, loc, _get_text(safe, loc) + note)
        # Final egress gate (review R2): a known secret anywhere in the released request,
        # including structural fields and dict keys we do not rewrite, refuses the request.
        if self._contains_known_secret(safe):
            return deny("known_secret_in_request")
        return {"status": "allow", "request": safe, "request_id": request_id,
                "clearance_id": clearance.issue(self._key, safe),
                "disclosures": [{k: v for k, v in d.items() if k != "note"} for d in disclosures],
                "notes": notes}

    def _ingest_entities(self, resp: PrivacyTeacherResponse, hinted: list[tuple[str, str]],
                         seen_texts: list[str]) -> None:
        """Register Teacher annotations as gateway-owned aliases (never policy).

        Only exact substrings of what the Teacher was shown are accepted (anti-injection);
        placeholders, tiny/huge spans and secret-like strings are ignored. Linking to an
        existing entity needs confidence >= 0.5; otherwise a new gateway entity is made.
        """
        def shown(m: str) -> bool:
            return any(m in t for t in seen_texts)

        def acceptable(m: str) -> bool:
            return (MENTION_MIN <= len(m) <= MENTION_MAX and shown(m)
                    and not _PLACEHOLDER.search(m) and "[" not in m and "]" not in m)

        for e in resp.entities:
            m = e.mention.strip()
            if not acceptable(m):
                continue
            ent = None
            if e.candidate_entity and e.confidence >= 0.5:
                ent = self.store.get_entity_by_pseudonym(e.candidate_entity)
            if ent is None:
                etype = e.entity_type if e.entity_type in TEACHER_ENTITY_TYPES else "other"
                ent = self.store.get_or_create_entity(etype, m)
            self.store.add_alias(ent["id"], m, "soft_alias", max(e.confidence, 0.5), "teacher")
        for m, etype in hinted:
            if acceptable(m):
                ent = self.store.get_or_create_entity(etype, m)
                self.store.add_alias(ent["id"], m, "soft_alias", 0.6, "teacher_rewrite")

    def _handle_need(self, resp: PrivacyTeacherResponse, task_type: str, request_id: str,
                     request_hash: str, approval_id: str | None,
                     disclosures: list[dict], session_id: str = "") -> dict | None:
        need = resp.need_more_context
        requested = level_for_detail(need.minimum_detail)
        ent = self.store.get_entity_by_pseudonym(need.entity) if need.entity else None
        pseud = ent["stable_pseudonym"] if ent else None
        d = decide(self.store, task_type=task_type, data_type=need.type, entity_pseudonym=pseud,
                   requested=requested, session_id=session_id, approval_id=approval_id)
        if d.action == "approval_required":
            pending = self.store.find_pending_approval(session_id, pseud, need.type, int(d.level))
            aid = pending["id"] if pending else self.store.create_approval(
                request_id=request_id, request_hash=request_hash, entity_pseudonym=pseud,
                data_type=need.type, requested_level=int(d.level), reason=need.reason,
                session_id=session_id)
            record_disclosure(self.store, task_type=task_type, data_type=need.type,
                              before=int(d.baseline), after=int(d.baseline),
                              teacher_provider=self.teacher.name, user_action="approval_requested")
            return {"status": "approval_required", "request_id": request_id,
                    "approval": {"id": aid, "field": need.type, "requested_level": int(d.level),
                                 "reason": need.reason, "entity": pseud,
                                 "current_level": int(d.baseline)}}
        if d.level < HIGH_RISK_MIN:      # high-risk grants are never remembered
            self.store.set_session_level(session_id, pseud, need.type, int(d.level))
        record_disclosure(self.store, task_type=task_type, data_type=need.type,
                          before=int(d.baseline), after=int(d.level),
                          teacher_provider=self.teacher.name)
        facet = self.store.best_facet(ent["id"], int(d.level)) if ent else None
        note = (f"{pseud} ({need.type}, L{facet[0]}): {facet[1]}" if facet and pseud
                else f"no further detail released for {need.type}")
        disclosures.append({"field": need.type, "entity": pseud, "level": int(d.level),
                            "deferred": d.deferred, "note": note})
        return None
