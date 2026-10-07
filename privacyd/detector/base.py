from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

# Higher wins when spans overlap.
PRIORITY = {"secret": 3, "pii": 2, "entity": 1.5, "fuzzy": 1}
# Kinds found by greedy Chinese patterns: a known alias beats them, exact formats do not.
FUZZY_KINDS = {"org", "location"}


@dataclass(frozen=True)
class Finding:
    start: int
    end: int
    kind: str          # e.g. "api_key", "email", "person"
    category: str      # "secret" | "pii" | "entity"
    entity_id: int | None = None   # set for category == "entity"
    ambiguous: bool = False

    @property
    def length(self) -> int:
        return self.end - self.start

    @property
    def priority(self) -> float:
        if self.category == "pii" and self.kind in FUZZY_KINDS:
            return PRIORITY["fuzzy"]
        return PRIORITY[self.category]


class Detector(Protocol):
    def detect(self, text: str) -> list[Finding]: ...
