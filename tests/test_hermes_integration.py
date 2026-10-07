"""Runs our plugin through the REAL Hermes plugin loader and middleware chain.

Skipped unless HERMES_AGENT_SRC points at a hermes-agent checkout (needs hermes_cli
and its imports), e.g.  HERMES_AGENT_SRC=/path/to/hermes-agent pytest tests/test_hermes_integration.py
"""

import json
import os
import shutil
import sys
import threading
from pathlib import Path

import pytest

from conftest import FakeTeacher
from privacyd.api import make_server
from privacyd.config import Config
from privacyd.errors import TeacherError

SRC = os.environ.get("HERMES_AGENT_SRC")
pytestmark = pytest.mark.skipif(not SRC, reason="HERMES_AGENT_SRC not set")

PLUGIN_SRC = Path(__file__).resolve().parent.parent / "hermes_plugin"


@pytest.fixture
def hermes(tmp_path, monkeypatch):
    home = tmp_path / "home"
    shutil.copytree(PLUGIN_SRC, home / "plugins" / "privacy-gateway",
                    ignore=shutil.ignore_patterns("__pycache__"))
    (home / "config.yaml").write_text("plugins:\n  enabled: [privacy-gateway]\n")
    monkeypatch.setenv("HERMES_HOME", str(home))   # before importing hermes (it may cache it)
    sys.path.insert(0, SRC)
    from hermes_cli import plugins
    from hermes_cli.middleware import apply_llm_request_middleware
    from hermes_cli.plugins import PluginManager

    def load(port, token=None):
        monkeypatch.setenv("PRIVACYD_URL", f"http://127.0.0.1:{port}/v1/process-request")
        if token:
            monkeypatch.setenv("PRIVACYD_TOKEN", token)
        manager = PluginManager()
        manager.discover_and_load()
        monkeypatch.setattr(plugins, "get_plugin_manager", lambda: manager)
        assert "privacy-gateway" in manager._plugins
        return apply_llm_request_middleware

    yield load
    sys.path.remove(SRC)


def serve(engine, **cfg):
    server = make_server(Config(port=0, **cfg), engine)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


REQ = {"model": "m", "stream": True,
       "messages": [{"role": "user", "content": "mail a@x.com, key sk-CANARY1234567890abcdefgh"}]}


def test_allow_rewrites_request_in_real_hermes_chain(hermes, make_engine):
    server = serve(make_engine())
    try:
        result = hermes(server.server_address[1])(json.loads(json.dumps(REQ)))
        text = json.dumps(result.payload)
        assert "a@x.com" not in text and "CANARY" not in text
        assert result.payload["model"] == "m" and result.payload["stream"] is True
        assert result.changed and result.trace[0]["source"] == "privacy-gateway"
    finally:
        server.shutdown()


def test_deny_never_forwards_raw_in_real_hermes_chain(hermes, make_engine):
    server = serve(make_engine(FakeTeacher(error=TeacherError("x"))))
    try:
        result = hermes(server.server_address[1])(json.loads(json.dumps(REQ)))
        assert "a@x.com" not in json.dumps(result.payload) and "CANARY" not in json.dumps(result.payload)
    finally:
        server.shutdown()


def test_privacyd_down_never_forwards_raw_in_real_hermes_chain(hermes):
    result = hermes(1)(json.loads(json.dumps(REQ)))
    assert "a@x.com" not in json.dumps(result.payload) and "CANARY" not in json.dumps(result.payload)


def test_placeholders_are_restored_in_real_hermes_tool_and_output_paths(hermes, make_engine):
    from hermes_cli.middleware import apply_tool_request_middleware
    from hermes_cli.plugins import invoke_hook

    engine = make_engine()
    server = serve(engine, token="t0ken", rehydrate_tools=("send_email",))
    try:
        apply_llm = hermes(server.server_address[1], token="t0ken")
        sent = apply_llm({"model": "m", "messages": [{"role": "user", "content": "email bob@corp.com"}]})
        assert "bob@corp.com" not in json.dumps(sent.payload)

        allowed = apply_tool_request_middleware("send_email", {"to": "[EMAIL_001]"})
        assert allowed.payload == {"to": "bob@corp.com"}
        other = apply_tool_request_middleware("web_search", {"q": "[EMAIL_001]"})
        assert other.payload == {"q": "[EMAIL_001]"}

        shown = invoke_hook("transform_llm_output", response_text="Sent to [EMAIL_001].",
                            session_id="s1", model="m", platform="cli", turn_id="t1")
        assert "Sent to bob@corp.com." in shown
    finally:
        server.shutdown()


def test_denied_settings_and_numeric_secrets_do_not_survive_real_chain(hermes, make_engine):
    canary = "SYNTHETIC-CANARY-EXTRA-1234"
    server = serve(make_engine(known_secrets=[canary, "12345678"]))
    try:
        apply_llm = hermes(server.server_address[1])
        for request in (
            {"model": canary, "messages": [{"role": "user", "content": "hello"}]},
            {"model": "m", "seed": 12345678,
             "messages": [{"role": "user", "content": "hello"}]},
        ):
            result = apply_llm(request)
            assert result.changed
            assert canary not in json.dumps(result.payload) and "12345678" not in json.dumps(result.payload)
            assert set(result.payload) == {"messages"}
            assert result.trace[0]["reason"] == "blocked: known_secret_in_request"
    finally:
        server.shutdown()
