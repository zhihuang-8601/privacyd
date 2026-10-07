# Security review record

The implementation went through internal adversarial reviews: every suspected weakness was
turned into a reproducing experiment, then fixed and pinned by a regression test. Code comments
refer to these IDs (e.g. `review R2`).

This record shows what was checked. It is **not** a claim of complete protection; see the
known limits in [`adrs/0001-trust-boundaries.md`](adrs/0001-trust-boundaries.md).

## Findings and fixes

| ID | Finding (reproduced before fixing) | Fix | Regression tests |
|---|---|---|---|
| F1 | The Teacher's free text became the outbound user message verbatim (an injected rewrite was forwarded) | The Teacher only annotates; its text is never sent; rewrites that are not redactions are refused | `test_teacher_annotations.py`, `test_known_flaws.py` |
| F2 | Teacher-invented placeholders were not owned by the gateway; a name it caught reappeared raw in the next turn's history | Annotations become gateway-owned aliases applied to every message | `test_teacher_annotations.py`, `test_known_flaws.py` |
| F3 | The disclosure ladder never passed L1, so high-risk approval was unreachable | Per-conversation disclosure state; approvals matched by (session, entity, type, level) | `test_disclosure_ladder.py` |
| F4 | A chat participant `name` (often a real name or email) passed through | Scrubbed in messages; kept for tool/function names | `test_request_shape.py` |
| F5 | Credential keywords inside identifiers (`OPENAI_API_KEY=`, `client_secret`, `DB_PASSWORD`) were missed | Keyword matching no longer depends on a word boundary | `test_detector_regressions.py` |
| F6 | `Authorization: Basic …` headers were missed | Added | `test_detector_regressions.py` |
| F7 | Phone numbers with separators were missed | Added | `test_detector_regressions.py` |
| F8 | Quadratic email regex: a 300k-character line took 214 s and stalled the service | Anchored, bounded pattern (0.08 s) | `test_detector_regressions.py` |
| F9 | Alias matching recompiled one regex per alias (2000 aliases × 200 messages: 17.5 s) | Literal search with a versioned index (0.1 s) | `test_known_flaws.py` |
| F10 | The database (real names) was created world-readable | Created/tightened to 0600 | `test_known_flaws.py` |
| F11 | A missing clearance key silently fell back to an all-zero key | Key required | `test_known_flaws.py` |
| F12 | The API accepted any Host header and Content-Type (DNS rebinding / cross-site POST) | Exact Host allow-list, JSON only | `test_api_hardening.py` |
| G1 | Placeholders reached tools, so actions on real data failed | Local restoration for display and allow-listed tool arguments (field-level), token-protected | `test_rehydrate.py` |
| G2 | Tool descriptions/metadata were not scrubbed; secrets split across text parts were missed; our own placeholders were re-detected | Extra fields scrubbed; joined-text secret detection; idempotent scrubbing | `test_request_shape.py`, `test_scrub_properties.py` |
| G3 | Pattern detection alone cannot be complete | Exact-match known secrets from env vars or a 0600 file | `test_known_secrets.py` |
| R1 | On deny/outage the blocked request still carried tool descriptions, metadata, etc. | Blocked requests are rebuilt from a fixed marker only; reason text is sanitised | `test_plugin_failure_paths.py` |
| R2 | Known secrets in structural fields (ids, response schemas, numbers, dict keys) were released | Whole-request egress gate on values and keys; a hit denies | `test_known_secret_gate.py` |
| R3 | Placeholder-shaped text shielded known secrets; some secret values corrupted placeholders | No exemption for known secrets; values colliding with placeholder vocabulary cannot be registered | `test_known_secret_gate.py` |
| R4 | `task_type` reached the Teacher unchecked | Constrained category; whole Teacher request checked first | `test_teacher_egress.py` |
| R5 | The plugin's loopback check was a string prefix (`127.0.0.1.evil.example` passed) | URL parsed and validated; proxies ignored and redirects refused on the unscrubbed hop | `test_plugin_endpoint.py` |

## Reporting

Please report suspected vulnerabilities privately through GitHub's
"Report a vulnerability" (security advisories) on this repository rather than in a public issue.
