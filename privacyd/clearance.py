"""Signed clearance tokens so a later hard egress proxy can verify that a
request was released by privacyd (HMAC over the exact released payload)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path


def canonical_hash(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()


def load_or_create_key(path: Path) -> bytes:
    if path.exists():
        return path.read_bytes()
    key = os.urandom(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue(key: bytes, request: dict, ttl: int = 300) -> str:
    payload = json.dumps({"h": canonical_hash(request), "exp": int(time.time()) + ttl}).encode()
    return _b64(payload) + "." + _b64(hmac.new(key, payload, hashlib.sha256).digest())


def verify(key: bytes, token: str, request: dict) -> bool:
    try:
        p, s = token.split(".")
        payload = _unb64(p)
        if not hmac.compare_digest(_unb64(s), hmac.new(key, payload, hashlib.sha256).digest()):
            return False
        data = json.loads(payload)
        return data["exp"] >= time.time() and hmac.compare_digest(data["h"], canonical_hash(request))
    except Exception:
        return False
