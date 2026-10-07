"""Review R5: the plugin only ever talks to a real loopback privacyd, directly."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from hermes_plugin.middleware import PrivacyMiddleware, validate_endpoint

GOOD = ["http://127.0.0.1:8765/v1/process-request", "http://localhost:8765/v1/process-request",
        "http://[::1]:8765/v1/process-request", "http://127.0.0.1/v1/process-request",
        "http://LOCALHOST:8765/v1/process-request"]
BAD = ["http://127.0.0.1.evil.example/v1/process-request",
       "http://localhost@evil.example/v1/process-request",
       "http://user:pw@127.0.0.1:8765/v1/process-request",
       "http://evil.example/v1/process-request",
       "https://127.0.0.1:8765/v1/process-request",
       "http://127.0.0.1:8765/v1/other",
       "http://127.0.0.1:8765/v1/process-request?x=1",
       "http://127.0.0.1:8765/v1/process-request#f",
       "http://127.0.0.1:99999/v1/process-request",
       "http://127.0.0.1:abc/v1/process-request",
       "ftp://127.0.0.1/v1/process-request", "127.0.0.1:8765"]


@pytest.mark.parametrize("url", GOOD)
def test_loopback_endpoints_are_accepted(url):
    assert validate_endpoint(url).endswith("/v1/process-request")
    PrivacyMiddleware(endpoint=url)


@pytest.mark.parametrize("url", BAD)
def test_non_loopback_or_malformed_endpoints_are_refused(url):
    with pytest.raises(ValueError):
        PrivacyMiddleware(endpoint=url)


def test_empty_endpoint_means_the_default_loopback_endpoint(monkeypatch):
    monkeypatch.delenv("PRIVACYD_URL", raising=False)
    assert PrivacyMiddleware(endpoint="").endpoint == "http://127.0.0.1:8765/v1/process-request"


def test_endpoint_from_environment_is_validated_too(monkeypatch):
    monkeypatch.setenv("PRIVACYD_URL", "http://localhost@evil.example/v1/process-request")
    with pytest.raises(ValueError):
        PrivacyMiddleware()


class _Recorder(BaseHTTPRequestHandler):
    hits = []
    reply = None

    def log_message(self, *a):
        pass

    def do_POST(self):
        type(self).hits.append(self.path)
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        code, headers, body = type(self).reply
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _server(reply):
    handler = type("H", (_Recorder,), {"hits": [], "reply": reply})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, handler


def test_redirects_are_never_followed():
    target, target_h = _server((200, {"Content-Type": "application/json"}, b'{"status":"allow","request":{}}'))
    port_t = target.server_address[1]
    redirector, _ = _server((307, {"Location": f"http://127.0.0.1:{port_t}/v1/process-request"}, b""))
    try:
        mw = PrivacyMiddleware(endpoint=f"http://127.0.0.1:{redirector.server_address[1]}/v1/process-request")
        out = mw.on_llm_request(request={"model": "m", "messages": [{"role": "user", "content": "RAW-TEXT"}]})
        assert "RAW-TEXT" not in json.dumps(out) and "blocked" in out["reason"]
        assert target_h.hits == []                       # the raw request was not re-sent
    finally:
        target.shutdown(); redirector.shutdown()
        target.server_close(); redirector.server_close()


def test_proxy_environment_is_ignored(monkeypatch):
    srv, h = _server((200, {"Content-Type": "application/json"},
                      b'{"status":"allow","request":{"model":"m","messages":[]}}'))
    try:
        for var in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.setenv(var, "http://127.0.0.1:9/")   # nothing listens there
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        mw = PrivacyMiddleware(endpoint=f"http://127.0.0.1:{srv.server_address[1]}/v1/process-request")
        out = mw.on_llm_request(request={"model": "m", "messages": [{"role": "user", "content": "x"}]})
        assert out["request"] == {"model": "m", "messages": []} and h.hits == ["/v1/process-request"], h.hits
    finally:
        srv.shutdown()
        srv.server_close()
