"""Exact values of the user's real secrets (review G3).

Pattern detection is best effort; the one reliable defence is exact matching of values we
already know. They come from named environment variables of the privacyd process and/or an
owner-only file (one value per line, `#` comments). They stay in memory: never stored,
logged or returned.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .errors import ConfigError


def load_known_secrets(env_vars: tuple = (), secrets_file: str | None = None) -> list[str]:
    values = [os.environ[name] for name in env_vars if os.environ.get(name)]
    if secrets_file:
        path = Path(secrets_file)
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError:
            raise ConfigError("secrets file not readable") from None
        if mode & 0o077:
            raise ConfigError("secrets file must be owner-only (chmod 600)")
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                values.append(line)
    return values
