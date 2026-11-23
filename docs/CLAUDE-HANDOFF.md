# Claude handoff: systemapi agent, backend, and management dashboard

## Intent and ownership

The user asked to finish the local host security core here, then extend the flow:

    secsvc -> local systemapi agent -> systemapi backend -> management dashboards

The implementation in this repository adds configurable Debian, Red Hat, Rocky,
Ubuntu, Alpine, and Arch profiles, six check groups, persistent findings, and a
local report contract. No agent upload, backend ingestion, or dashboard changes
have been made. Do that work in the owning repositories after inspecting their
current authentication, tenancy, enrollment, storage, and UI conventions. Do not
assume any remote endpoint named below already exists.

Read `docs/modules.md`, `docs/architecture.md`, `internal/engine/report.go`,
`internal/modules/modules.go`, and `internal/api/api.go` first. The DESIGN file
points at the surrounding systemapi/adssh/sah ecosystem. Preserve suite enrollment
and control-plane audit ownership in systemapi; secsvc is a single-host service.

## Existing local integration surface

- HTTP over `/run/secsvc/sock`; no TCP listener. Use the existing no-proxy Unix
  client behavior. Unix socket permissions are not authorization.
- `GET /v1/report`, `GET /v1/modules`, `GET /v1/status`, `GET /v1/catalog` require
  `security.read` in an Ed25519 `secsvc/2` grant scoped to the exact host.
- A report has schema `secsvc-report/1`, host, generated_at, last_scan,
  config_sha256, scan_config_sha256, config_changed, system.platform,
  system.modules with per-check coverage, and findings.
- Findings carry id, kind, severity, subject, summary, observation,
  first_seen, last_seen. The ID is stable across recurrence; it is not an event ID.
- `GET /v1/audit?limit=N` requires `security.audit`. It returns a tail of the
  newest audit segment (max 200), not a durable event cursor. `findings.jsonl` is also capped, not a reliable
  delivery queue. Do not pretend either is lossless export.
- The legacy `caps` list in status remains advisory and is separate from the
  new module/check coverage. The report covers module state plus all open IDS
  findings; legacy detector capability probes remain in `/v1/status`.
- Configuration mutations remain full replacements, require `security.config`,
  consume a lease, and require watch coverage for added/removed module inputs.
  Distribute new signed grants for mutations; do not persist signing seeds in
  dashboard clients or give an agent blanket config permission just to collect.

## Agent collector work

1. Integrate with the existing agent scheduler and enrolled machine identity.
   Obtain short-lived read grants through the approved authority; grant expiry is
   at most 15 minutes. The daemon needs only the verifier public key. Document
   rotation and socket access provisioning without widening directory modes by
   default.
2. Poll report snapshots at a bounded cadence. Fetch status/caps separately and
   retain its own observation time; separate GETs are not one atomic snapshot.
   Do not trigger a scan for every dashboard refresh.
3. Spool uploads locally with a size/age bound, retry/backoff/jitter, and a
   visible overflow/drop count. Prefer an existing agent transport and durable
   queue. Agent receipt timestamps are distinct from last_scan.
4. Wrap reports with enrolled machine/tenant identity from the authenticated
   transport, agent version, monotonic upload sequence or unique upload ID, and
   receipt metadata. A report's `host` string is a label, not tenancy authority.
5. Keep grants, signing material, shadow content, and ntfy bearer topics out of
   uploads/logs. Reports still contain operationally sensitive paths and IDS
   summaries; apply existing access and retention policies.
6. Add an agent-side integration test using a real Unix-socket daemon: valid,
   absent, expired, wrong-host, and insufficient-entitlement grants; daemon
   offline; config changes; retries; queue exhaustion; duplicate uploads.

## Backend work

- Define a versioned ingestion API in the existing API conventions. Validate
  report schema, bounded arrays/strings/body sizes, kind/state enums, timestamps,
  and machine ownership. Unknown schema versions should be explicit errors or
  quarantined input, not silently accepted as healthy.
- Key data by authenticated tenant + enrolled machine, not host or finding ID
  alone. Implement authorization tests for cross-tenant and cross-machine access.
- Store the latest snapshot, coverage/check states, config hashes, last successful
  scan, upload receipt time, and findings. Use idempotent ingestion by upload ID
  or sequence. Prevent delayed/replayed uploads from replacing newer snapshots;
  host wall-clock timestamps alone are not sufficient ordering.
- Track finding occurrences/history separately from the stable finding ID. A
  finding that recurs after resolution is a new occurrence of the same rule.
- Preserve observed/retained/stale distinctions. Absence from a snapshot does
  not by itself prove remediation: disabled checks withdraw findings, platform
  changes or errors invalidate coverage. Diff complete snapshots using coverage
  and configuration; do not label a disabled check's disappearance as fixed.
- Snapshot polling can miss findings that open and close between polls. If
  lossless security event history is a requirement, add a durable cursor/export
  protocol to secsvc first, with an epoch, sequence, acknowledgement, retention,
  resync/gap behavior, and restart tests. Tail polling is insufficient.
- Define retention and aggregation for finding history and snapshots. Expose
  filtered/paginated fleet and machine security views through the existing RBAC.
- Keep server audit separate from the host hash chain. Local audit verification
  is tamper evidence within its threat model, not remote attestation.

## Dashboard work

- Fleet view: enrolled machine, distro/version, last actual scan, last upload,
  coverage state, enabled modules, high/medium counts, retained/stale counts.
- Machine view: per-check results and reasons, active findings, first/last seen,
  occurrence timeline, configuration fingerprint and pending changes.
- Render missing data as unknown/offline/stale. Zero findings with disabled,
  failed, unsupported, or pending checks must not be green/secure.
- Distinguish resolved, withdrawn (configuration disabled), and retained
  (coverage lost). Explain incomplete SSH static analysis and container scope.
- Escape all displayed strings; subjects and old IDS summaries contain host
  observations. Filter/sort on structured fields, not HTML snippets.
- If adding configuration controls, send mutations through the existing agent
  command/grant workflow. Show a concrete diff, preserve full-replace fields,
  require appropriate permissions, and record the control-plane audit action.

## Off-host anchor

secsvc's side is done (hardening batch 2); the collector side is a systemapi.io
batch and has not been started. Read `docs/architecture.md`, "Off-host anchor",
for the exact contract. In short:

- Each host has an anchor key, separate from the grant key. Its public key is
  `anchor_pub` (hex) in `GET /v1/status`. Record it at enrollment through the
  authenticated agent transport and pin it; do not take it from a head
  response (heads do not carry it). A changed `anchor_pub` is a re-key event
  for an operator, never a silent update.
- `GET /v1/audit/head` (`security.audit`) returns
  `{"head":{"host","seq","hash","segment","time"},"sig"}`. Verify `sig` as
  Ed25519 over `secsvc-audit-head-v1\n` + the compact JSON of `head` in that
  field order, with the pinned key. Store every verified head server-side,
  keyed by tenant and enrolled machine, not by `head.host`.
- Detection: a head whose `seq` is lower than a stored one, or whose `hash`
  differs at a `seq` already seen, is a truncation or rewrite. Alert; do not
  overwrite the stored head.
- `POST /v1/audit/witness` needs a `security:witness` grant (its own purpose,
  ceiling `security.audit` and `security.witness`; no other purpose carries
  it; it spends its lease) and takes `{"seq","hash","witness","time"}` with
  `witness` an identifier of the collecting party (at most 128 characters)
  and `time` RFC 3339 (at most 35). Post back a head you stored earlier.
  `200 {"ok":true}` means the chain holds it and it is stored. `409
  witness_mismatch` means the chain does not hold it now (a seq past the end,
  or another hash): that is the truncation or rewrite event the dashboard
  must surface; the host refuses and audits it (`audit.witness_refused`) but
  stays up. `409 witness_unverifiable` means the row is in a segment the host
  pruned; post a newer head. A stored witness that stops matching later makes
  the host report `audit_truncated` until an operator acts.
- Cadence: one head fetch and at most one witness per collection interval is
  enough; the host keeps the newest 500 witnesses. Do not call
  `GET /v1/audit/verify` on a schedule: it walks every segment, runs one at a
  time, and is limited to once a minute per grant actor.
- What it proves: the host signed what it said, when the collector saw it.
  Root on the host holds the anchor key, so it can sign a rewritten chain
  going forward; the protection is that the collector's stored heads and
  witnesses are out of root's reach.
- Tests the collector needs: valid head; bad signature; wrong pinned key;
  seq regression; hash change at a known seq; witness accepted; witness
  refused with `witness_mismatch` and `witness_unverifiable`; a grant of
  another purpose; spent
  lease; daemon offline.

## Local-core follow-ups before broad production claims

All six profiles have fixture coverage. Debian/Ubuntu/Rocky/Alpine also passed
container smoke tests; Red Hat/Arch container checks remain. Complete a native
test matrix for all six distros (systemd and OpenRC, AppArmor/SELinux,
minimal installs, and read permission failures); effective SSH evaluation;
package inventory and signed advisory/CVE sources; firewall policy collectors;
service/persistence collectors; IPv6/per-interface hardening; optional policy
thresholds/exceptions with audit and expiry; durable event export if required.
Do not silently turn these into automatic remediation. Package manager names
in the module registry are descriptive metadata, not implemented scanners.

## Acceptance criteria for the next phase

One real host produces a report, its enrolled agent uploads it, the backend
stores it idempotently within the correct tenant, and the dashboard displays it.
Tests must cover offline/stale agents, missing permissions, unsupported distro,
failed checks retaining findings, explicit disable/withdrawal, recurring findings,
config pending, out-of-order uploads, schema mismatch, and tenant isolation.
