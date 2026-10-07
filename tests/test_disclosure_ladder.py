"""Cross-turn disclosure ladder and approvals (review F3)."""

from conftest import FakeTeacher, resp, user_req
from privacyd.policy.approval import decide_approval


def setup(make_engine, store):
    t = FakeTeacher()
    e = make_engine(t)
    p = e.resolver.pseudonym_for("person", "林川")
    ent = store.get_entity_by_pseudonym(p)
    for lv, v in ((1, "coworker"), (2, "engineer"), (3, "semiconductor company"),
                  (4, "Acme Semi"), (5, "林川 real identity")):
        store.set_facet(ent["id"], lv, v)
    return e, t, p


def ask(e, t, p, session="s1", detail="real_name", typ="identity"):
    t.response = resp(need_more_context={"required": True, "type": typ, "minimum_detail": detail,
                                         "reason": "r", "entity": p})
    return e.process_request({**user_req("林川是谁"), "session_id": session})


def text(out):
    return out["request"]["messages"][0]["content"]


def test_repeated_asks_climb_one_step_per_turn_then_need_approval(make_engine, store):
    e, t, p = setup(make_engine, store)
    levels = []
    for _ in range(3):
        out = ask(e, t, p)
        levels.append(out["disclosures"][0]["level"])
    assert levels == [1, 2, 3]
    assert "semiconductor company" in text(out) and "Acme" not in text(out)
    out = ask(e, t, p)
    assert out["status"] == "approval_required" and out["approval"]["requested_level"] == 4
    assert "request" not in out


def test_sessions_are_independent(make_engine, store):
    e, t, p = setup(make_engine, store)
    ask(e, t, p, session="a"); ask(e, t, p, session="a")
    assert ask(e, t, p, session="b")["disclosures"][0]["level"] == 1


def test_pending_approval_is_reused_not_duplicated(make_engine, store):
    e, t, p = setup(make_engine, store)
    for _ in range(3):
        ask(e, t, p)
    a1, a2 = ask(e, t, p)["approval"]["id"], ask(e, t, p)["approval"]["id"]
    assert a1 == a2 and len(store.pending_approvals()) == 1


def test_allow_once_is_used_once_and_high_risk_is_not_remembered(make_engine, store):
    e, t, p = setup(make_engine, store)
    for _ in range(3):
        ask(e, t, p)
    aid = ask(e, t, p)["approval"]["id"]
    decide_approval(store, aid, "allow_once")
    out = ask(e, t, p)
    assert out["status"] == "allow" and "Acme Semi" in text(out)
    assert store.session_level("s1", p, "identity") == 3          # L4 was not stored
    assert ask(e, t, p)["status"] == "approval_required"          # asks again


def test_denied_approval_keeps_blocking(make_engine, store):
    e, t, p = setup(make_engine, store)
    for _ in range(3):
        ask(e, t, p)
    decide_approval(store, ask(e, t, p)["approval"]["id"], "denied")
    assert ask(e, t, p)["status"] == "approval_required"


def test_allow_class_covers_later_requests(make_engine, store):
    e, t, p = setup(make_engine, store)
    for _ in range(3):
        ask(e, t, p)
    decide_approval(store, ask(e, t, p)["approval"]["id"], "allow_class")
    assert ask(e, t, p)["status"] == "allow"
    assert ask(e, t, p)["status"] == "allow"


def test_asking_for_less_than_already_granted_does_not_climb(make_engine, store):
    e, t, p = setup(make_engine, store)
    ask(e, t, p); ask(e, t, p)                                   # now at L2
    out = ask(e, t, p, detail="coworker")                        # L1 is enough
    assert out["disclosures"][0]["level"] == 1 and "engineer" not in text(out)
