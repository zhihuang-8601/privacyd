from conftest import user_req


def scrub(e, text):
    return e.process_request(user_req(text))["request"]["messages"][0]["content"]


def test_org_address_path_ip_are_pseudonymised(make_engine):
    e = make_engine()
    out = scrub(e, "本项目由北京某某科技有限公司承建，地址在广东省深圳市南山区科技路18号，"
                   "资料在 /home/alice/project/招标.pdf，服务器 192.168.1.5")
    for raw in ("某某科技有限公司", "南山区", "/home/alice", "192.168.1.5"):
        assert raw not in out
    assert "[ORG_001]" in out and "[LOC_001]" in out and "[PATH_001]" in out and "[IP_001]" in out


def test_leading_function_word_is_not_swallowed(make_engine):
    out = scrub(make_engine(), "由北京某某科技有限公司承建")
    assert out.startswith("由")


import pytest


@pytest.mark.xfail(strict=True, reason="known limit: without word segmentation the greedy org "
                   "pattern swallows preceding hanzi, so the same company can get two pseudonyms "
                   "until an alias is registered (upstream uses jieba; we add no dependency)")
def test_cold_start_same_org_same_pseudonym(make_engine):
    e = make_engine()
    a = scrub(e, "合作方是某某科技有限公司")
    b = scrub(e, "某某科技有限公司的报价")
    assert a.count("[ORG_001]") == 1 and "[ORG_001]" in b


def test_registered_alias_makes_org_pseudonym_stable(make_engine):
    e = make_engine()
    p = e.resolver.pseudonym_for("org", "某某科技有限公司")
    a = scrub(e, "合作方是某某科技有限公司")
    b = scrub(e, "某某科技有限公司的报价")
    assert a == f"合作方是{p}" and b == f"{p}的报价"


def test_valid_chinese_id_card_is_caught(make_engine):
    out = scrub(make_engine(), "身份证 110101199003074518 谢谢")
    assert "110101199003074518" not in out
