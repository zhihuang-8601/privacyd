# hermes-privacy-gateway

A local privacy layer for the [Hermes](https://github.com/NousResearch/hermes-agent) AI agent.
Before Hermes sends a request to a cloud model, a local service (`privacyd`) replaces personal
information with stable placeholders, removes secrets, and releases more detail only step by
step. Answers are turned back into real names locally. MIT licensed. 中文说明见下方。

> **Status: research prototype.** Not deployed, not audited, and **not a hard confidentiality
> boundary**: Hermes middleware is fail-open, and no egress proxy exists yet. See the
> [known limits](docs/adrs/0001-trust-boundaries.md#known-limits-do-not-over-claim).

## What it does

- **Pseudonymises** names, emails, phone numbers, IDs, organisations and addresses into stable
  placeholders such as `[PERSON_001]` (the same entity keeps the same placeholder; the mapping
  stays in a local SQLite database).
- **Treats secrets as capabilities, not context**: API keys, passwords, private keys, tokens and
  exact values you register are removed, never stored, never sent, never restorable.
- **Progressive disclosure**: a model may *ask* for more context, but local policy decides, one
  level per turn (L0 opaque → L5 identity); high-risk levels need the user's approval.
- **Optional cloud "Teacher"** that only *annotates* what is private; it never writes the text
  that is sent, and pseudonyms are always assigned locally.
- **Local restoration**: answers shown to the user, and arguments of explicitly allow-listed
  tools, get real values back on the user's machine only.
- **Fails closed**: on any error the request is replaced by a fixed blocked marker.

## Layout

| Path | What |
|---|---|
| `privacyd/` | detectors, entity/alias resolution, disclosure policy, Teacher interface, SQLite storage, HTTP API |
| `hermes_plugin/` | Hermes plugin (`llm_request` / `tool_request` middleware, `transform_llm_output` hook); stdlib only |
| `tests/` | unit, property and adversarial regression tests; optional integration test against a real Hermes checkout |
| `docs/adrs/0001-trust-boundaries.md` | design, invariants and known limits |
| `docs/SECURITY.md` | review findings, fixes and the tests that pin them |

## Quick start

```bash
pip install -e .[dev]
pytest -q
PRIVACYD_DB=privacy.db privacyd serve          # loopback only, 127.0.0.1:8765
```

Install the plugin into Hermes:

```bash
cp -r hermes_plugin ~/.hermes/plugins/privacy-gateway
hermes plugins enable privacy-gateway
```

Main settings (environment): `PRIVACYD_TOKEN`, `PRIVACYD_TEACHER=none|openai`,
`PRIVACYD_SECRET_ENV_VARS` / `PRIVACYD_SECRETS_FILE` (exact secrets to block),
`PRIVACYD_REHYDRATE_TOOLS` (e.g. `send_email.to`; default none).
Integration test against a real Hermes source tree:
`HERMES_AGENT_SRC=/path/to/hermes-agent pytest -q tests/test_hermes_integration.py`.

No runtime dependencies beyond the Python standard library (3.10+).

## Design note: the optional cloud Teacher

The local part of privacyd is rule-based (pattern detectors, alias resolution, a local
SQLite store, a disclosure policy). It does not run a language model.

The optional Teacher is a cloud model that sees text that has already been scrubbed
locally (imperfectly) and only annotates it. It does two things:

- It marks spans it believes are private. The gateway turns them into local aliases and
  assigns the placeholders itself; the Teacher never writes outbound text.
- It suggests which kind of data a task type may need, at which disclosure level. These
  suggestions are recorded as `shadow` rules and can move shadow → candidate → validated →
  active only through a deliberate local action backed by enough evidence; activation needs
  an explicit approver, and high-risk levels need the user's class approval. The cloud can
  never change a rule by itself.

The point of this stage is learning, not a finished protection boundary. Because the text
sent to the Teacher can still carry residual personal context, the Teacher should only be
used with a provider that offers zero data retention. A local-model backend for the Teacher
is future work; today the Teacher needs a cloud model.

## Not done yet

- A hard egress proxy that only forwards requests carrying a valid `clearance_id`.
- Verifying whether all of Hermes' auxiliary model calls pass through the middleware.
- Container deployment where Hermes and privacyd run separately.
- A Claude Teacher adapter (currently OpenAI-compatible endpoints only), and an optional
  local-model backend for the Teacher.

## Credits

Chinese-context detection patterns are adapted from
[yubingz/hermes-desensitize](https://github.com/yubingz/hermes-desensitize) (MIT); see
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

---

## 中文简介

Hermes 隐私网关：在 Hermes 把请求发给云端模型之前，由本地服务 `privacyd` 把人名、邮箱、电话等换成稳定代号，抹掉密钥，并且只按需、逐级放出更多细节；回答回来后在本地还原成真名。**当前是研究原型**，未部署、未审计，也还不是"硬边界"，详见上面的已知局限。
