from conftest import user_req


def test_same_entity_same_pseudonym(make_engine):
    e = make_engine()
    a = e.process_request(user_req("mail a@x.com now"))
    b = e.process_request(user_req("again a@x.com"))
    pa = a["request"]["messages"][0]["content"]
    pb = b["request"]["messages"][0]["content"]
    assert "a@x.com" not in pa and "[EMAIL_001]" in pa and "[EMAIL_001]" in pb


def test_different_entities_differ(make_engine):
    e = make_engine()
    out = e.process_request(user_req("a@x.com b@x.com"))["request"]["messages"][0]["content"]
    assert "[EMAIL_001]" in out and "[EMAIL_002]" in out
