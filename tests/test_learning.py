import pytest

from conftest import FakeTeacher, resp, user_req
from privacyd.learning.promotion import PromotionRefused, promote, rollback


def seed(store, n=5, ok=5, level=1):
    for _ in range(n):
        store.observe_rule("t", "d", level)
    for _ in range(ok):
        store.record_outcome("t:d", succeeded=True)


def test_teacher_cannot_activate_rules(make_engine, store):
    t = FakeTeacher(resp(learning={
        "candidate_patterns": [{"data_type": "d", "task_type": "t", "level": 5}]}))
    make_engine(t).process_request(user_req("hi", task_type="t"))
    assert store.get_rule("t:d")["state"] == "shadow"
    assert store.active_rule_level("t", "d") is None


def test_promotion_requires_evidence_and_order(store):
    seed(store, n=2, ok=0)
    with pytest.raises(PromotionRefused):
        promote(store, "t:d")                       # too few observations
    seed(store, n=3, ok=5)
    assert promote(store, "t:d") == "candidate"
    assert promote(store, "t:d") == "validated"
    with pytest.raises(PromotionRefused):
        promote(store, "t:d")                       # activation needs an approver
    assert promote(store, "t:d", approved_by="user") == "active"
    assert rollback(store, "t:d") == "validated"


def test_false_positive_blocks_validation(store):
    seed(store)
    promote(store, "t:d")
    store.record_outcome("t:d", succeeded=True, false_positive=True)
    with pytest.raises(PromotionRefused):
        promote(store, "t:d")


def test_high_risk_rule_needs_class_approval(store):
    seed(store, level=4)
    promote(store, "t:d"); promote(store, "t:d")
    with pytest.raises(PromotionRefused):
        promote(store, "t:d", approved_by="user")
