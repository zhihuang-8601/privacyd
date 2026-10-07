from conftest import FakeTeacher, resp, user_req
from privacyd.policy.approval import decide_approval
from privacyd.policy.levels import Level, level_for_detail


def need(detail, entity, typ="person_relationship"):
    return {"required": True, "type": typ, "minimum_detail": detail,
            "reason": "needed", "entity": entity}


def setup_entity(e, store):
    p = e.resolver.pseudonym_for("person", "林川")
    ent = store.get_entity_by_pseudonym(p)
    store.set_facet(ent["id"], 1, "coworker")
    store.set_facet(ent["id"], 4, "Acme Semiconductor")
    store.set_facet(ent["id"], 5, "林川 real identity")
    return p


def run(e, text="林川 说了什么", **extra):
    return e.process_request(user_req(text, **extra))


def test_minimum_disclosure_releases_coworker_only(make_engine, store):
    t = FakeTeacher()
    e = make_engine(t)
    p = setup_entity(e, store)
    t.response = resp(sanitized_text=f"{p} 说了什么", need_more_context=need("coworker", p))
    out = run(e)
    assert out["status"] == "allow"
    text = out["request"]["messages"][0]["content"]
    assert "coworker" in text
    assert "林川" not in text and "Acme" not in text


def test_ladder_steps_one_level_at_a_time(make_engine, store):
    t = FakeTeacher()
    e = make_engine(t)
    p = setup_entity(e, store)
    t.response = resp(sanitized_text=p, need_more_context=need("real_name", p))
    out = run(e)
    assert out["status"] == "allow"                       # L5 asked, only L1 granted
    assert out["disclosures"][0]["level"] == 1 and out["disclosures"][0]["deferred"]
    assert "real identity" not in out["request"]["messages"][0]["content"]


def test_unknown_detail_is_most_conservative():
    assert level_for_detail("gibberish") == Level.L5 and level_for_detail(None) == Level.L5


def test_high_risk_blocks_until_approved(make_engine, store):
    t = FakeTeacher()
    e = make_engine(t)
    p = setup_entity(e, store)
    # raise baseline so the *next step* is L4 (active rule at L3)
    store.observe_rule("general", "org_identity", 3)
    store.set_rule_state("general:org_identity", "active")
    store._x("UPDATE privacy_rules SET default_disclosure_level=3 WHERE rule_key='general:org_identity'")
    t.response = resp(sanitized_text=p, need_more_context=need("company", p, "org_identity"))
    out = run(e)
    assert out["status"] == "approval_required" and out["approval"]["requested_level"] == 4
    assert "request" not in out                            # nothing to forward
    aid = out["approval"]["id"]
    # still blocked while pending
    assert run(e, approval_id=aid)["status"] == "approval_required"
    decide_approval(store, aid, "allow_once")
    ok = run(e, approval_id=aid)
    assert ok["status"] == "allow" and "Acme" in ok["request"]["messages"][0]["content"]
    # allow_once is consumed
    assert run(e, approval_id=aid)["status"] == "approval_required"


def test_denied_approval_stays_blocked(make_engine, store):
    t = FakeTeacher()
    e = make_engine(t)
    p = setup_entity(e, store)
    store.observe_rule("general", "org_identity", 3)
    store.set_rule_state("general:org_identity", "active")
    t.response = resp(sanitized_text=p, need_more_context=need("company", p, "org_identity"))
    aid = run(e)["approval"]["id"]
    decide_approval(store, aid, "denied")
    assert run(e, approval_id=aid)["status"] == "approval_required"


def test_model_cannot_self_authorize(make_engine, store):
    """Teacher output has no field that can grant access."""
    t = FakeTeacher()
    e = make_engine(t)
    p = setup_entity(e, store)
    r = resp(sanitized_text=p, need_more_context=need("real_name", p))
    t.response = r
    out = run(e)
    assert "林川 real identity" not in str(out)
