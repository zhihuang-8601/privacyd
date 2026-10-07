# ADR 0001: Trust boundaries, fail-closed behaviour and known limits

Status: accepted (v0.1)

## Decision

privacyd runs as a local sidecar. Hermes' `llm_request` middleware sends the pending provider
request to it and forwards only the replacement request privacyd returns with
`status: "allow"`. Placeholders are turned back into real values only locally: in the answer
shown to the user (`transform_llm_output`) and in arguments of allow-listed tools
(`tool_request`).

```
Hermes -> llm_request  -> privacyd (scrub, Teacher annotations, disclosure policy) -> clearance_id
       <- transform_llm_output / tool_request <- privacyd /v1/rehydrate (token, allow-list)
                                privacyd |-> SQLite privacy.db (0600)
                                         |-> Privacy Teacher (cloud, one provider, annotates only)
```

## Invariants (each guarded by tests; see [`../SECURITY.md`](../SECURITY.md) for the review findings behind them)

* **Secrets.** Values found by the (best-effort) patterns, or matching a *known* secret value
  supplied via `PRIVACYD_SECRET_ENV_VARS` / an owner-only `PRIVACYD_SECRETS_FILE`, are replaced
  by `[SECRET:kind]` before anything else. They are never stored (the store's write guard uses
  the same detector), sent to the Teacher, logged, or restorable.
* **Known secrets are checked on everything that leaves.** The released provider request
  (every value and dict key, including fields we never rewrite such as ids and response
  schemas) and the whole Teacher request are checked for known secret literals; a hit denies
  (`known_secret_in_request`, `known_secret_in_teacher_request`). Numeric/boolean/null values
  are checked using their JSON spelling; JSON-serializable tuples supplied by direct Python
  callers are treated as arrays. Values that collide with our
  placeholder vocabulary, short numbers and values under 4 characters cannot be registered.
* **Blocked requests carry nothing.** On deny, approval, outage or a malformed privacyd
  response, the plugin returns only a fixed marker. It copies no original settings, model
  identifiers, reason text or approval fields. Omitting the model intentionally makes the
  replacement unusable by providers that require it. Hermes still receives a dict replacement;
  diagnostics stay in the local trace and are restricted to known codes. This does not prevent
  Hermes or another transport from falling back elsewhere; the hard egress boundary is still absent.
* **The plugin talks only to loopback privacyd, directly.** The endpoint is parsed (http,
  loopback host, no userinfo, exact path); proxies are ignored and redirects are refused,
  because this hop carries unscrubbed data.
* **Fail closed.** Any error (Teacher failure, invalid Teacher output, internal exception,
  invalid payload, unknown request shape, non-text content) yields `deny` with a content-free
  reason. Detectors are linear-time and alias matching is indexed, so long inputs or many
  aliases do not stall the service (review F8/F9).
* **The Teacher only annotates.** It never writes outbound text. Its exact-substring
  annotations (and spans its optional rewrite replaced with a placeholder) become
  gateway-owned aliases; pseudonyms are always allocated by the gateway and applied to every
  message. A rewrite with too many non-placeholder changes is refused
  (`teacher_output_rejected`); `residual_risk: high` is refused.
* **Disclosure.** Rises one ladder step per turn above the higher of an active rule and what
  this conversation (session id) already received for the same entity/data type. L4/L5 needs a
  user decision, matched by (session, entity, data type, level); pending approvals are reused;
  high-risk grants are never remembered as a baseline. Decisions only via CLI or an
  admin-token endpoint, never via the request path.
* **Restoration is local and narrow.** `/v1/rehydrate` is served only when a token is set;
  tool arguments are restored only for allow-listed tools (`tool` or `tool.field`, default
  none, enforced by privacyd). Every failure leaves placeholders in place.
* Relation words (“我老婆”) are stored only as `candidate` relations; learning output only
  creates `shadow` rules; activation is an explicit, evidence-gated local action.

## Known limits (do not over-claim)

1. **Hermes middleware is fail-open.** If the plugin is not loaded, crashes, or Hermes itself
   fails, the original request can be sent. `clearance_id` (HMAC over the exact released payload)
   exists for a v0.2 hard egress proxy, which is **not built yet**. Without it there is no hard
   confidentiality boundary.
2. Other enabled Hermes plugins can read the raw conversation through observer hooks.
3. In bootstrap mode the Teacher sees locally scrubbed text of the last user message plus a few
   earlier ones; names the local detectors miss are exposed to it by design.
4. Pattern detection is best effort. Not covered by patterns: bank card numbers, keyword-less
   tokens, raw TOTP seeds, AWS secret keys — register such values as known secrets.
5. `/v1/rehydrate` is a de-pseudonymisation oracle for anyone holding the token. Allow-listed
   tools receive real values; never allow-list tools that can send data elsewhere.
6. Restored answers are stored by Hermes and replayed; they are scrubbed again on the next
   outbound request, which relies on pseudonyms staying stable.
7. `privacy.db` is plaintext SQLite (owner-only). Protect it with disk encryption.
8. Dict keys are not scrubbed; Chinese organisation/address patterns are greedy without word
   segmentation (cold-start may split one company into two pseudonyms until an alias exists).
9. **Container deployment is not supported yet**: privacyd accepts extra Host names
   (`PRIVACYD_ALLOWED_HOSTS`) but still binds to loopback, and the plugin only connects to
   loopback. Running Hermes and privacyd as two containers (e.g. on a NAS) needs a design.
10. Verified against the real Hermes loader: `llm_request`, `tool_request`,
    `transform_llm_output`. Not verified: whether auxiliary LLM calls (titles, compression,
    vision, MoA) go through `llm_request`; the minimum supported Hermes version.
