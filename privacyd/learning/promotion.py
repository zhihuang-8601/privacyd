"""Explicit, evidence-gated rule promotion: shadow -> candidate -> validated -> active.

Cloud output never calls this. Promotion is a local, deliberate action and
moves one state at a time. Rollback restores the previous state.
"""

from __future__ import annotations

from ..errors import PrivacydError
from ..policy.levels import HIGH_RISK_MIN
from ..storage import Store

ORDER = ["shadow", "candidate", "validated", "active"]

MIN_OBS_CANDIDATE = 3
MIN_OBS_VALIDATED = 5
MIN_SUCCESS_RATIO = 0.8


class PromotionRefused(PrivacydError):
    code = "promotion_refused"


def promote(store: Store, rule_key: str, *, approved_by: str | None = None) -> str:
    rule = store.get_rule(rule_key)
    if rule is None:
        raise PromotionRefused("unknown rule")
    state = rule["state"]
    if state == "active":
        raise PromotionRefused("already active")
    nxt = ORDER[ORDER.index(state) + 1]
    obs, ok = rule["observation_count"], rule["success_count"]
    done = ok + rule["failure_count"]

    if nxt == "candidate" and obs < MIN_OBS_CANDIDATE:
        raise PromotionRefused("not enough observations")
    if nxt == "validated":
        if obs < MIN_OBS_VALIDATED or done == 0 or ok / done < MIN_SUCCESS_RATIO:
            raise PromotionRefused("insufficient success evidence")
        if rule["false_positive_count"] > 0:
            raise PromotionRefused("false positives recorded")
    if nxt == "active":
        if not approved_by:
            raise PromotionRefused("activation requires explicit approver")
        if rule["default_disclosure_level"] >= HIGH_RISK_MIN and \
                store.find_class_grant(rule["data_type"], rule["default_disclosure_level"]) is None:
            raise PromotionRefused("high-risk level requires user class approval")

    confidence = (ok / done) if done else rule["confidence"]
    store.set_rule_state(rule_key, nxt, confidence)
    return nxt


def rollback(store: Store, rule_key: str) -> str:
    rule = store.get_rule(rule_key)
    if rule is None or not rule["previous_state"]:
        raise PromotionRefused("nothing to roll back")
    prev = rule["previous_state"]
    store.set_rule_state(rule_key, prev)
    return prev
