from __future__ import annotations

from ..storage import Store


def record_disclosure(store: Store, *, task_type: str, data_type: str, before: int, after: int,
                      teacher_provider: str | None, user_action: str | None = None) -> None:
    """Record evidence and bump the shadow rule. Never changes rule state."""
    rule = store.observe_rule(task_type, data_type, after)
    store.add_learning_event(
        task_type=task_type, requested_information=data_type, before_level=before,
        after_level=after, user_action=user_action, teacher_provider=teacher_provider,
        policy_version=rule["version"])
