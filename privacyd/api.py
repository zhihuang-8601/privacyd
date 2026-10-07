"""Loopback HTTP API.

POST /v1/process-request                  (bearer token if configured)
POST /v1/rehydrate                        (bearer token required; disabled if unset)
POST /v1/approvals/<id>/decision          (admin token required; disabled if unset)
GET  /healthz
"""

from __future__ import annotations

import hmac
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .config import Config
from .engine import PrivacyEngine, deny
from .policy.approval import decide_approval

log = logging.getLogger("privacyd.api")


def _token_ok(expected: str | None, header: str | None, prefix: str = "Bearer ") -> bool:
    if not expected:
        return True
    return bool(header and header.startswith(prefix)
                and hmac.compare_digest(header[len(prefix):], expected))


def host_allowed(header: str | None, allowed) -> bool:
    """Exact match of the Host header's name (port ignored) against the allow-list.

    Exact matching, not suffix/prefix: `127.0.0.1.evil.com` must not pass.
    """
    h = (header or "").strip().lower()
    if h.startswith("["):                       # bracketed IPv6, optionally with :port
        name = h[: h.index("]") + 1] if "]" in h else h
    elif h.count(":") == 1:                     # host:port
        name = h.rsplit(":", 1)[0]
    else:                                       # bare host (or unbracketed IPv6)
        name = h
    return bool(name) and name in {a.lower() for a in allowed}


def make_server(config: Config, engine: PrivacyEngine) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # never log bodies / paths with ids
            pass

        def _send(self, code: int, body: dict) -> None:
            raw = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _body(self) -> dict | None:
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if n <= 0 or n > config.max_body_bytes:
                    return None
                data = json.loads(self.rfile.read(n))
                return data if isinstance(data, dict) else None
            except Exception:
                return None

        def _host_ok(self) -> bool:
            return host_allowed(self.headers.get("Host"), config.allowed_hosts)

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, deny("bad_host"))
            if self.path == "/healthz":
                self._send(200, {"ok": True})
            else:
                self._send(404, deny("not_found"))

        def do_POST(self):
            try:
                if not self._host_ok():
                    return self._send(403, deny("bad_host"))
                if not (self.headers.get("Content-Type") or "").lower().startswith("application/json"):
                    return self._send(415, deny("unsupported_media_type"))
                if self.path == "/v1/process-request":
                    if not _token_ok(config.token, self.headers.get("Authorization")):
                        return self._send(401, deny("unauthorized"))
                    body = self._body()
                    if body is None:
                        return self._send(400, deny("invalid_request"))
                    return self._send(200, engine.process_request(body))
                if self.path == "/v1/rehydrate":
                    # Turns pseudonyms back into real values: never served without a token.
                    if not config.token:
                        return self._send(503, deny("rehydrate_requires_token"))
                    if not _token_ok(config.token, self.headers.get("Authorization")):
                        return self._send(401, deny("unauthorized"))
                    body = self._body()
                    if body is None:
                        return self._send(400, deny("invalid_request"))
                    return self._send(200, engine.rehydrate(body, config.rehydrate_tools))
                if self.path.startswith("/v1/approvals/") and self.path.endswith("/decision"):
                    if not config.admin_token:
                        return self._send(503, deny("admin_disabled"))
                    if not _token_ok(config.admin_token, self.headers.get("X-Admin-Token"), ""):
                        return self._send(401, deny("unauthorized"))
                    body = self._body() or {}
                    aid = self.path.split("/")[3]
                    decide_approval(engine.store, aid, str(body.get("decision")))
                    return self._send(200, {"ok": True})
                self._send(404, deny("not_found"))
            except ValueError:
                self._send(400, deny("invalid_request"))
            except Exception:
                self._send(500, deny("privacy_engine_error"))

    return ThreadingHTTPServer((config.host, config.port), Handler)
