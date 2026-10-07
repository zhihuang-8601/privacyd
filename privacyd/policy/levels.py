"""Disclosure ladder L0..L5."""

from __future__ import annotations

from enum import IntEnum


class Level(IntEnum):
    L0 = 0  # opaque entity only
    L1 = 1  # broad role / relation
    L2 = 2  # contextual role
    L3 = 3  # organisation type / broad project category
    L4 = 4  # concrete company / location / project
    L5 = 5  # real identity / precise identifying detail


HIGH_RISK_MIN = Level.L4

# Teacher-supplied `minimum_detail` -> level. Unknown detail is treated as L5
# (most conservative), never as something cheap.
_DETAIL_LEVELS = {
    "opaque": Level.L0,
    "coworker": Level.L1, "relation": Level.L1, "role": Level.L1,
    "adult": Level.L1, "customer": Level.L1, "family": Level.L1,
    "engineer": Level.L2, "department": Level.L2, "language": Level.L2,
    "organization_type": Level.L3, "project_category": Level.L3,
    "company": Level.L4, "location": Level.L4, "project": Level.L4,
    "real_name": Level.L5, "identity": Level.L5, "address": Level.L5,
}


def level_for_detail(detail: str | None) -> Level:
    if not detail:
        return Level.L5
    return _DETAIL_LEVELS.get(detail.strip().lower(), Level.L5)


def clamp(value: int) -> Level:
    return Level(max(0, min(5, int(value))))
