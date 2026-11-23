# secsvc hardening, batch 2: contract

2026-11-23. This batch takes the items left open by batch 1 (`hardening-1.md`). Ryan approved it on 2026-11-23 as step 3 of 4. Branch: `fix/hardening-2`, based on `fix/hardening-1`.

Every fix below comes with:
- a test that fails if the fix is reverted;
- a `Threats:` note in the code it changes;
- a stable refusal code from `internal/codes`.

## Changes

| # | Problem | Change |
| --- | --- | --- |
| R1 | Every status, audit or verify call reads all of `audit.jsonl` into memory, with no size cap and no rotation. | **Segmented chain.** Rows go to `audit/NNNNNN.jsonl` segments, each capped (default 4 MiB or 20,000 rows). The hash chain continues across segments: the first row of a new segment has `prev` = the last hash of the previous one.<br>**Runtime reads.** Status, `GET /v1/audit?limit=N` and the in-process tail check read only the newest segment plus `audit.head`. The runtime check verifies the newest segment, and that its first row links to a `segments.json` index. The index holds each closed segment's first seq, last seq and last hash, and is written atomically like the anchor.<br>**Full verify.** `audit verify` (CLI and `GET /v1/audit/verify`) walks every segment with a bounded buffer, and is the one that detects a rewritten old segment. It is a heavier operation: rate-limit it to once a minute through the API.<br>**Retention.** Optional `audit_keep_segments` in the config (default: keep all). Pruning drops the oldest segments and keeps their index entry, so the chain stays anchored. Every prune writes an `audit.pruned` row naming the dropped range and its last hash.<br>**Migration.** None: an existing single-file chain must be moved with an explicit `secsvc audit migrate --dir D`, which refuses while a daemon holds the store. It splits the file into segments, verifies the whole chain, writes the index and anchor, and appends `audit.migrated`. A daemon that finds the old layout refuses with `audit_layout`.<br>We are the only users, so breaking the format is fine. Add a migration note to README "Breaking changes". |
| R2 | Truncation and rewrite of the chain are only detectable locally; root can rewrite both files. | **Off-host anchor, secsvc side only.** `GET /v1/audit/head` (needs `security.audit`) returns `{host, seq, hash, segment, time}`, signed by an anchor key that secsvc generates at first start (`anchor.key`, 0600, O_EXCL; its public key is in status). It also accepts `POST /v1/audit/witness`, which needs a new entitlement `security.witness` and a lease-spending grant. The body is a witness record `{seq, hash, witness, time}`, which secsvc stores in `witness.jsonl` and checks at runtime: the chain must still contain that seq with that hash, otherwise `audit_truncated`.<br>The agent or control-plane side that fetches heads and posts witnesses is a separate systemapi.io batch; this batch defines and tests the secsvc contract. Document it in `docs/architecture.md` and in `docs/CLAUDE-HANDOFF.md`, "Off-host anchor". |
| R3 | Paging leaks the host name, paths and listener addresses to a public ntfy topic. | **Pages carry no host detail.** Each page holds only a severity, a count, a finding-kind summary and an opaque finding id. Host, paths, subjects and addresses stay local (`secsvc call findings`). A config flag `page_detail: true` restores the detail, with a doc warning that the topic is public to anyone who learns or guesses it. A test asserts that the default page body contains no host, path or address. Document that the topic must be treated as a secret. |
| R4 | The API's 10s write timeout can cut off a scan's response while pages are being sent. | Scans send pages asynchronously after the response, through a bounded queue. Each page is audited when sent (`page.sent` or `page.failed`). The response returns as soon as the findings are committed. The write timeout stays at 10s and becomes a tested guarantee. |

## Out of scope

- The agent and control-plane collection of anchors and witnesses (systemapi.io).
- Dashboards.
- Remote report upload.

## Verification

- `gofmt`, vet, `go test -count=1 -race ./...`, and the Docker root suite all pass.
- The distro smoke test is run where images are cached.
- An adversarial review is done before any push.
