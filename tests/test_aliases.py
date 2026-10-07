from conftest import user_req


def content(r):
    return r["request"]["messages"][0]["content"]


def test_aliases_converge_on_one_entity(make_engine, store):
    e = make_engine()
    p = e.resolver.pseudonym_for("person", "王五")
    e.resolver.link_alias(p, "王先生", "soft_alias", 0.9)
    e.resolver.link_alias(p, "小王", "soft_alias", 0.8)
    out = content(e.process_request(user_req("王五、王先生和小王是同一个人")))
    assert out == f"{p}、{p}和{p}是同一个人"


def test_ambiguous_alias_not_guessed(make_engine):
    e = make_engine()
    p1 = e.resolver.pseudonym_for("person", "王五")
    p2 = e.resolver.pseudonym_for("person", "王六")
    e.resolver.link_alias(p1, "小王")
    e.resolver.link_alias(p2, "小王")
    out = content(e.process_request(user_req("小王来了")))
    assert "小王" not in out and "[AMBIGUOUS_ENTITY]" in out and p1 not in out


def test_relation_word_never_verified_fact(make_engine, store):
    e = make_engine()
    p = e.resolver.pseudonym_for("person", "林川")
    rid = e.resolver.record_relation_mention(p, "我老婆")
    row = store._q("SELECT * FROM relations WHERE id=?", (rid,))[0]
    assert row["status"] == "candidate" and row["confidence"] < 0.5
    # role references are never substituted as if they were identity
    e.resolver.link_alias(p, "我老婆", "role_reference", 0.3)
    assert content(e.process_request(user_req("我老婆很高兴"))) == "我老婆很高兴"
    # high-confidence input still can't create a verified relation without a user
    rid2 = store.add_relation_candidate(None, "spouse", None, "x", 1.0, "teacher")
    assert store._q("SELECT status, confidence FROM relations WHERE id=?", (rid2,))[0][0] == "candidate"
