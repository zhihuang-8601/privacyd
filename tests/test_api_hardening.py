import json
import threading
import urllib.error
import urllib.request

import pytest

from conftest import user_req
from privacyd.api import host_allowed, make_server
from privacyd.config import Config

LOOPBACK = Config().allowed_hosts


@pytest.mark.parametrize("header,ok", [
    ("127.0.0.1:8765", True), ("127.0.0.1", True), ("localhost:8765", True), ("LOCALHOST", True),
    ("[::1]:8765", True), ("[::1]", True),
    ("evil.example.com", False), ("127.0.0.1.evil.com", False), ("evil.com:127.0.0.1", False),
    ("localhost.evil.com:8765", False), ("", False), (None, False),
])
def test_host_allowed(header, ok):
    assert host_allowed(header, LOOPBACK) is ok


def test_service_name_can_be_allowed_for_container_networks():
    assert host_allowed("privacyd:8765", LOOPBACK + ("privacyd",))
    assert not host_allowed("privacyd:8765", LOOPBACK)


def _post(port, body, headers):
    rq = urllib.request.Request(f"http://127.0.0.1:{port}/v1/process-request", data=body,
                                method="POST", headers=headers)
    try:
        r = urllib.request.urlopen(rq)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_api_checks_host_and_content_type(make_engine):
    srv = make_server(Config(port=0), make_engine())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    body = json.dumps(user_req("mail a@x.com")).encode()
    try:
        assert _post(port, body, {"Content-Type": "application/json"})[0] == 200
        assert _post(port, body, {"Content-Type": "application/json; charset=utf-8"})[0] == 200
        assert _post(port, body, {"Content-Type": "application/json", "Host": "evil.example.com"}) == \
            (403, {"status": "deny", "reason": "bad_host"})
        assert _post(port, body, {"Content-Type": "text/plain"}) == \
            (415, {"status": "deny", "reason": "unsupported_media_type"})
    finally:
        srv.shutdown()
