"""Disclosure controller: the model asks, local policy decides.

* Increase is one ladder step at a time above the baseline.
* Baseline = the higher of an *active* rule's level and what this conversation has already
  been granted for the same entity/data type (review F3), else L0.
* A step that lands on L4/L5 needs user approval (once, or class-wide). High-risk grants are
  never remembered as the conversation's baseline: "allow once" means once.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..storage import Store
from .levels import HIGH_RISK_MIN, Level, clamp


@dataclass
class Decision:
    action: str                # "grant" | "approval_required"
    baseline: Level
    requested: Level
    level: Level               # level granted (grant) or level awaiting approval
    deferred: bool = False     # granted less than requested


def decide(store: Store, *, task_type: str, data_type: str, entity_pseudonym: str | None,
           requested: Level, session_id: str = "", approval_id: str | None = None) -> Decision:
    active = store.active_rule_level(task_type, data_type)
    granted = store.session_level(session_id, entity_pseudonym, data_type)
    baseline = clamp(max(active if active is not None else 0, granted if granted is not None else 0))
    if requested <= baseline:
        return Decision("grant", baseline, requested, requested)

    target = clamp(min(int(requested), int(baseline) + 1))
    deferred = target < requested
    if target >= HIGH_RISK_MIN:
        if store.find_class_grant(data_type, int(target)) is not None:
            return Decision("grant", baseline, requested, target, deferred)
        if store.consume_once_grant(session_id, entity_pseudonym, data_type, int(target),
                                    approval_id):
            return Decision("grant", baseline, requested, target, deferred)
        return Decision("approval_required", baseline, requested, target, deferred)
    return Decision("grant", baseline, requested, target, deferred)
