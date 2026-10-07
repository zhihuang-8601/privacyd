"""User approval decisions. Called by the CLI / admin endpoint, never by a model."""

from __future__ import annotations

from ..storage import Store

DECISIONS = ("denied", "allow_once", "allow_class")


def decide_approval(store: Store, approval_id: str, decision: str) -> None:
    if decision not in DECISIONS:
        raise ValueError("decision must be one of " + ", ".join(DECISIONS))
    row = store.get_approval(approval_id)
    if row is None or row["decision"] != "pending":
        raise ValueError("approval not found or already decided")
    store.decide_approval(approval_id, decision)
    # Explicit user evidence for the learning system (evidence only; no promotion here).
    store.add_learning_event(
        task_type="approval", requested_information=row["data_type"], before_level=None,
        after_level=row["requested_level"], user_action=decision)
