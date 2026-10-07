"""Stable pseudonyms + alias resolution.

* hard/soft aliases are substituted; role/contextual references (我老婆, 那个工程师)
  are only mentions and are never substituted or treated as fact.
* An alias text shared by several entities is ambiguous and is replaced by a
  generic placeholder rather than guessed.
"""

from __future__ import annotations

import re
from collections import defaultdict

from ..detector.base import Finding
from ..storage import Store

SUBSTITUTED_ALIAS_TYPES = {"hard_alias", "soft_alias"}


class EntityResolver:
    def __init__(self, store: Store):
        self.store = store
        self._cache_version: tuple[int, int] | None = None
        self._alias_index: list[tuple[str, frozenset[int]]] = []

    def pseudonym_for(self, entity_type: str, label: str) -> str:
        return self.store.get_or_create_entity(entity_type, label)["stable_pseudonym"]

    def link_alias(self, pseudonym: str, alias: str, alias_type: str = "soft_alias",
                   confidence: float = 0.7, source: str = "local") -> None:
        ent = self.store.get_entity_by_pseudonym(pseudonym)
        if ent is None:
            raise KeyError("unknown pseudonym")
        self.store.add_alias(ent["id"], alias, alias_type, confidence, source)

    def record_relation_mention(self, subject_pseudonym: str | None, relation_word: str,
                                confidence: float = 0.3, source: str = "local") -> int:
        """e.g. “我老婆”: stored as a *candidate*; never a verified fact."""
        subj = self.store.get_entity_by_pseudonym(subject_pseudonym) if subject_pseudonym else None
        return self.store.add_relation_candidate(
            subj["id"] if subj else None, relation_word, None, None, confidence, source)

    def _index(self) -> list[tuple[str, frozenset[int]]]:
        """Substitutable aliases, rebuilt only when the alias table changes (review F9)."""
        version = self.store.alias_version()
        if version != self._cache_version:
            by_text: dict[str, set[int]] = defaultdict(set)
            for row in self.store.all_aliases():
                if row["alias_type"] in SUBSTITUTED_ALIAS_TYPES:
                    by_text[row["alias_text"]].add(row["entity_id"])
            self._alias_index = [(a, frozenset(ids)) for a, ids in by_text.items() if a]
            self._cache_version = version
        return self._alias_index

    def find_mentions(self, text: str) -> list[Finding]:
        # Aliases are literals: plain substring search. (Compiling one regex per alias
        # thrashed re's 512-entry cache and dominated runtime with many aliases.)
        findings: list[Finding] = []
        for alias, ids in self._index():
            start = text.find(alias)
            while start != -1:
                end = start + len(alias)
                if len(ids) == 1:
                    findings.append(Finding(start, end, "entity", "entity", entity_id=next(iter(ids))))
                else:
                    findings.append(Finding(start, end, "entity", "entity", ambiguous=True))
                start = text.find(alias, end)
        return findings

    def replacement(self, f: Finding) -> str:
        if f.ambiguous:
            return "[AMBIGUOUS_ENTITY]"
        return self.store.get_entity(f.entity_id)["stable_pseudonym"]
