from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigError


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass
class Config:
    db_path: str = "privacy.db"
    host: str = "127.0.0.1"
    port: int = 8765
    token: str | None = None            # bearer for /v1/process-request
    admin_token: str | None = None      # separate; enables approval-decision endpoint
    clearance_key_path: str | None = None
    teacher: str = "none"               # "none" | "openai"
    teacher_model: str = "gpt-4o-mini"
    teacher_base_url: str = "https://api.openai.com/v1"
    teacher_api_key: str | None = None
    teacher_timeout: float = 20.0
    # Host header names accepted by the API (DNS-rebinding defence). Add the service name when
    # privacyd is reached over a container network, e.g. PRIVACYD_ALLOWED_HOSTS=privacyd.
    allowed_hosts: tuple = ("127.0.0.1", "localhost", "[::1]", "::1")
    # Tools whose arguments may receive real values in place of pseudonyms (default none).
    # "tool" = every argument; "tool.field" = only that top-level argument (prefer this:
    # "send_email.to" restores the recipient but keeps names in the body as placeholders).
    # Never list tools that send data elsewhere (web search, generic HTTP, webhooks, shell).
    # Rehydration is only served when `token` is set.
    rehydrate_tools: tuple = ()
    # Exact-match secrets (review G3): names of env vars whose values must never leave, and/or
    # an owner-only file with one value per line. Kept in memory only.
    secret_env_vars: tuple = ()
    secrets_file: str | None = None
    recent_context_messages: int = 2
    max_body_bytes: int = 8 * 1024 * 1024

    def __post_init__(self) -> None:
        if not _is_loopback(self.host):
            raise ConfigError("privacyd binds to loopback only in v0.1")

    @property
    def key_path(self) -> Path:
        return Path(self.clearance_key_path or (self.db_path + ".clearance.key"))

    @classmethod
    def from_env(cls) -> "Config":
        e = os.environ.get
        return cls(
            db_path=e("PRIVACYD_DB", "privacy.db"),
            host=e("PRIVACYD_HOST", "127.0.0.1"),
            port=int(e("PRIVACYD_PORT", "8765")),
            token=e("PRIVACYD_TOKEN"),
            admin_token=e("PRIVACYD_ADMIN_TOKEN"),
            clearance_key_path=e("PRIVACYD_CLEARANCE_KEY"),
            teacher=e("PRIVACYD_TEACHER", "none"),
            teacher_model=e("PRIVACYD_TEACHER_MODEL", "gpt-4o-mini"),
            teacher_base_url=e("PRIVACYD_TEACHER_BASE_URL", "https://api.openai.com/v1"),
            teacher_api_key=e("PRIVACYD_TEACHER_API_KEY") or e("OPENAI_API_KEY"),
            secrets_file=e("PRIVACYD_SECRETS_FILE"),
            **({"secret_env_vars": tuple(v.strip() for v in e("PRIVACYD_SECRET_ENV_VARS").split(",") if v.strip())}
               if e("PRIVACYD_SECRET_ENV_VARS") else {}),
            **({"rehydrate_tools": tuple(t.strip() for t in e("PRIVACYD_REHYDRATE_TOOLS").split(",") if t.strip())}
               if e("PRIVACYD_REHYDRATE_TOOLS") else {}),
            **({"allowed_hosts": tuple(h.strip() for h in e("PRIVACYD_ALLOWED_HOSTS").split(",") if h.strip())}
               if e("PRIVACYD_ALLOWED_HOSTS") else {}),
        )
