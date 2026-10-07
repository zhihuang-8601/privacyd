"""Hermes `llm_request` middleware: ask privacyd, return only what it allows.

Contract (verified against NousResearch/hermes-agent hermes_cli/middleware.py @85db7c3):
the callback is invoked as `fn(**kwargs)`; `kwargs["request"]` is the provider kwargs;
it must return `{"request": {...complete replacement...}}`. Any other return value is
IGNORED and Hermes sends the original request. Exceptions are fail-open too.

So this callback never raises and never returns a non-`{"request": dict}` value: on any
non-allow outcome it returns a request containing only a fixed block
marker. That is best-effort fail-closed *inside the callback only*; it is not a
confidentiality boundary (Hermes observer hooks still see the raw conversation, and a
loader failure skips the middleware). Pair it with a hard egress proxy (v0.2).

Stdlib only, so the plugin directory can be copied into ~/.hermes/plugins as-is.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.parse
import urllib.request

log = logging.getLogger("privacy-gateway")

DEFAULT_ENDPOINT = "http://127.0.0.1:8765/v1/process-request"
PSEUDONYM = re.compile(r"\[[A-Z]+_\d{3}\]")
CONTENT_ROOTS = ("messages", "input", "instructions", "prompt", "system")
BLOCK_MARKER = "[PRIVACY_GATEWAY_BLOCKED_REQUEST]"
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
PROCESS_PATH = "/v1/process-request"


def validate_endpoint(url: str) -> str:
    """Parse, don't prefix-match (review R5): `http://127.0.0.1.evil.example/...` and
    `http://localhost@evil.example/...` used to pass a startswith() check."""
    parts = urllib.parse.urlsplit(url)
    try:
        parts.port                           # raises on a malformed port
    except ValueError:
        raise ValueError("privacyd endpoint has an invalid port") from None
    if (parts.scheme != "http" or parts.username is not None or parts.password is not None
            or "@" in parts.netloc or (parts.hostname or "") not in _LOOPBACK_HOSTS
            or parts.path != PROCESS_PATH or parts.query or parts.fragment):
        raise ValueError("privacyd endpoint must be http://<loopback>[:port]" + PROCESS_PATH)
    return urllib.parse.urlunsplit(("http", parts.netloc, PROCESS_PATH, "", ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None                          # a 3xx becomes an error: never re-send elsewhere


# The plugin sends UNSCRUBBED requests to privacyd: never through a proxy (HTTP_PROXY in the
# Hermes environment would otherwise receive them) and never following redirects.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


# Only fixed diagnostics reach Hermes' local trace. A syntactically valid string can
# still contain private data, so neither request settings nor response fields are copied.
_REASON_CODES = frozenset({"denied", "privacy_engine_error", "config_error", "secret_leak_blocked",
                           "teacher_failure", "invalid_request", "non_text_content",
                           "residual_risk_high", "teacher_output_rejected", "known_secret_in_request",
                           "known_secret_in_teacher_request", "unauthorized", "bad_host",
                           "unsupported_media_type", "not_found"})


def safe_code(value: object, default: str = "denied") -> str:
    """Return a known diagnostic code, never arbitrary service response text."""
    return value if isinstance(value, str) and value in _REASON_CODES else default


def blocked_request(request: object, reason: str) -> dict:
    """A request rebuilt from scratch that carries no user data (review R1).

    No original settings are copied: even model identifiers or numeric settings can carry
    a registered secret. Omitting the model deliberately leaves a blocked request unusable
    by providers that require it. Hermes still receives a dict replacement, so it cannot
    fall back to the original just because the callback returned an invalid result shape.
    `reason` stays in the caller's local trace; the provider body is a constant marker.
    """
    src = request if isinstance(request, dict) else {}
    out = {}
    marker = f"{BLOCK_MARKER}. No content was sent."
    if "input" in src and "messages" not in src:          # Responses-style request
        out["input"] = marker
    else:
        out["messages"] = [{"role": "user", "content": marker}]
    return out


class PrivacyMiddleware:
    def __init__(self, endpoint: str | None = None, token: str | None = None,
                 timeout: float = 30.0, task_type: str = "general"):
        self.endpoint = endpoint or os.environ.get("PRIVACYD_URL", DEFAULT_ENDPOINT)
        self.token = token or os.environ.get("PRIVACYD_TOKEN")
        self.timeout = timeout
        self.task_type = task_type
        self.endpoint = validate_endpoint(self.endpoint)
        self.rehydrate_url = self.endpoint[: -len(PROCESS_PATH)] + "/v1/rehydrate"

    def _call(self, payload: dict, url: str | None = None) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(url or self.endpoint, data=json.dumps(payload).encode(),
                                     headers=headers, method="POST")
        with _OPENER.open(req, timeout=self.timeout) as resp:  # validated loopback, no proxy/redirects
            return json.loads(resp.read())

    def on_llm_request(self, **kwargs) -> dict:
        request = kwargs.get("request")
        try:
            payload = {"request": request, "task_type": self.task_type,
                       "session_id": kwargs.get("session_id"), "task_id": kwargs.get("task_id"),
                       "provider": kwargs.get("provider"), "model": kwargs.get("model")}
            result = self._call(payload)
            status = result.get("status")
            if status == "allow" and isinstance(result.get("request"), dict):
                return {"request": result["request"], "source": "privacy-gateway",
                        "reason": f"privacyd clearance {result.get('clearance_id', '')}"}
            if status == "approval_required":
                reason = "approval_required"
            else:
                reason = safe_code(result.get("reason"))
        except Exception as exc:  # fail closed inside the callback
            log.warning("privacyd call failed: %s", type(exc).__name__)
            reason = "privacyd_unavailable"
        return {"request": blocked_request(request, reason), "source": "privacy-gateway",
                "reason": f"blocked: {reason}"}

    # ---- rehydration (review G1). Failure in either direction leaves the placeholders in
    # place, which is the safe outcome: nothing private is revealed by mistake.
    def _rehydrate(self, purpose: str, value, tool_name: str | None = None):
        try:
            result = self._call({"purpose": purpose, "value": value, "tool_name": tool_name},
                                url=self.rehydrate_url)
            return result.get("value") if result.get("status") == "ok" else None
        except Exception as exc:
            log.warning("privacyd rehydrate failed: %s", type(exc).__name__)
            return None

    def on_tool_request(self, **kwargs):
        """`tool_request` middleware: real values only for tools privacyd allow-lists."""
        args = kwargs.get("args")
        if not isinstance(args, dict) or not PSEUDONYM.search(json.dumps(args, ensure_ascii=False)):
            return None
        value = self._rehydrate("tool_args", args, kwargs.get("tool_name"))
        if not isinstance(value, dict):
            return None
        return {"args": value, "source": "privacy-gateway", "reason": "rehydrated allow-listed tool args"}

    def on_llm_output(self, response_text=None, **kwargs):
        """`transform_llm_output` hook: show the user real names instead of placeholders."""
        if not isinstance(response_text, str) or not PSEUDONYM.search(response_text):
            return None
        value = self._rehydrate("display", response_text)
        return value if isinstance(value, str) and value != response_text else None
