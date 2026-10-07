"""Privacy Context Compiler: a small, pseudonym-level context for the Teacher.

Never sends full history, real labels, or facets above L0.
"""

from __future__ import annotations

import re

from ..storage import Store

_PSEUDONYM = re.compile(r"\[[A-Z]+_\d{3}\]")


def compile_entity_context(store: Store, texts: list[str]) -> list[dict]:
    seen: dict[str, dict] = {}
    for text in texts:
        for p in _PSEUDONYM.findall(text):
            if p in seen:
                continue
            ent = store.get_entity_by_pseudonym(p)
            if ent is None:
                continue
            rels = [{"relation": r["relation_type"], "status": r["status"]}
                    for r in store.relations_for(ent["id"])][:5]
            seen[p] = {"pseudonym": p, "type": ent["entity_type"], "relations": rels}
    return list(seen.values())
