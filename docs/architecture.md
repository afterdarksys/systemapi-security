# secsvc

`secsvc` is one process on one host. sahinit supervises it when that supervisor is PID 1. The process answers HTTP over a Unix socket. Grants are `secsvc/2` Ed25519 documents. The daemon stores the public key and spends each lease id once. The audit chain is the host record.

## Startup

`secsvc serve` requires `--dir`, `--pub`, `--host`, and `--socket`. `--interval` defaults to `30s` and must be at least `5s`. A shorter interval returns `usage` before the state directory exists.

Order after that check:

1. A `--host` that names no machine is `host_unset`, before the state directory exists: empty, `localhost`, `localhost.localdomain`, `ip6-localhost`, `ip6-loopback`, `localhost6`, `localhost6.localdomain6`, any name under `.localhost`, or an IP literal. Names are not resolved. Then host grammar, then load the public key. Log step `validate`.
2. Open the state directory at mode `0700`. Log step `store`.
3. Listen on the absolute socket path. Log step `listen`.
4. `chmod` the socket to `0660`.
5. Write one byte, `\n`, to the file descriptor in `SAHINIT_READY_FD` when that variable is set. The descriptor number is the variable's value. Log step `ready`.
6. Start the scan loop, then serve HTTP until `SIGINT` or `SIGTERM`.

The ready byte is written only after `Listen` succeeds. A clean shutdown unlinks the socket and returns success.

The parent of the socket is created at mode `0750` when it is missing. An existing socket inode is removed and replaced. A symlink at the socket path or its parent is `bad_socket`.

## Grant

Domain string `secsvc-grant-v2\n`. The signed fields are `v`, `actor`, `host`, `purpose`, `iat`, `exp`, `lease_id`, `entitlements`, and `watch`; all are required. Signature is Ed25519 and is checked before a star, a filesystem root, expiry, `iat`, TTL, the purpose ceiling, and the host. Maximum document size is 16 KiB. Maximum TTL is 900 seconds. An `iat` more than 60 seconds ahead of the daemon clock is `grant_future` (401). `exp - iat` above 900 seconds, or `exp` not after `iat`, is `grant_ttl`, so a grant cut far into the future never becomes usable in its last minutes. A `secsvc/1` grant, which has no `iat`, is `grant_bad_shape`; reissue it with this binary's `secsvc grant`, which signs `iat` as the current time. A lease id matches `^[A-Za-z0-9_-]{8,64}$`.

| purpose | ceiling |
| --- | --- |
| `security:read` | `security.audit`, `security.read` |
| `security:config` | those, plus `security.baseline`, `security.config`, `security.notify` |
| `security:operate` | those, plus `security.scan` |
| `security:witness` | `security.audit`, `security.witness` |

`security.witness` is a write, so only the `security:witness` purpose carries it: a read, config, or operate grant cannot post a witness (asking for it is `grant_purpose`). The witnessing party gets a `security:witness` grant.

`*` is `grant_star`. A watch of `/` is `grant_root_slash`. The daemon refuses a grant whose host differs from `--host` with `grant_host`. A second use of the same lease id is `grant_spent`. Spend is recorded before the commit and stays recorded when the commit fails. A blocked ntfy egress check returns before the lease is spent.

A grant's `watch` list covers an `auth_log` or `watch` path that a config replace adds or removes. An unchanged path may sit outside the grant; an uncovered changed path is `forbidden`. `listen_allow` entries are addresses, not paths.

Global fields need coverage of what they govern, so a grant scoped to one path cannot change them. A `listen_allow` change (as a set) needs a grant that covers `/proc/net/tcp` and `/proc/net/tcp6`, for example `--watch /proc/net`. An `auth_fail_limit` or `auth_window_s` change needs coverage of every `auth_log` set before or after the replace, and is refused when neither is set. Otherwise the replace is `config_scope` (403) and spends nothing.

## HTTP

Header `X-Secsvc-Grant`. One value. Body cap 64 KiB. Header cap 32 KiB. Read header timeout 5s, read and write timeouts 10s. The write timeout is a tested guarantee for scans: a scan answers once its findings are committed and pages afterwards (see IDS), so a slow ntfy never holds the response. Unknown paths return `404` `{"error":"bad_path"}` before the grant is read. A known path with the wrong method returns `405` before the grant is read. A grant that lacks the route entitlement is `403` `forbidden` before the body is parsed.

| method | path | entitlement |
| --- | --- | --- |
| `GET` | `/v1/audit` | `security.audit` |
| `GET` | `/v1/audit/head` | `security.audit` |
| `GET` | `/v1/audit/verify` | `security.audit` |
| `POST` | `/v1/audit/witness` | `security.witness` |
| `POST` | `/v1/baseline` | `security.baseline` |
| `GET` | `/v1/catalog` | `security.read` |
| `GET` | `/v1/config` | `security.read` |
| `PUT` | `/v1/config` | `security.config` |
| `PUT` | `/v1/contact` | `security.notify` |
| `GET` | `/v1/findings` | `security.read` |
| `GET` | `/v1/modules` | `security.read` |
| `GET` | `/v1/report` | `security.read` |
| `POST` | `/v1/scan` | `security.scan` |
| `GET` | `/v1/status` | `security.read` |

`POST /v1/scan` and `POST /v1/baseline` require an empty body. Both spend the grant's lease, so a second scan on the same grant is `grant_spent`. The internal scan loop spends nothing. `PUT /v1/config` replaces the whole config. `{}` is a valid replace and clears `auth_log`, `watch`, and `listen_allow`. `GET /v1/audit` that fails chain verification returns `500` `audit_bad`. `GET /v1/audit?limit=N` returns the last N rows of the newest segment only, so just after a segment rolls it returns fewer than N. `GET /v1/audit/verify` is the full walk of every segment. One walk runs at a time, and each grant actor gets one walk a minute; any other call is `429` `rate_limited` at once, before anything is read. `POST /v1/audit/witness` spends its lease. Audit JSON uses the API field names `seq`, `prev`, `time`, `actor`, `lease_id`, `action`, `detail`, `hash`.

`GET /v1/status` also carries `anchor_pub`, the hex Ed25519 public key that signs audit heads (see Audit), and the config view carries `audit_keep_segments` and `page_detail`.

## Capabilities

`GET /v1/status` includes `caps`. Each entry is a name from a fixed registry, a state of `ok`, `degraded`, or `absent`, and a reason from a closed set. `ok` has an empty reason. The registry is `audit`, `auth`, `grant_v1`, `integrity`, `listen`, and `notify`.

| reason | when |
| --- | --- |
| `flag_off` | the detector is not configured |
| `target_missing` | the auth log is absent, or any watched path is absent |
| `unbaselined` | a watched path has no baseline record |
| `no_key` | `grant_v1`: no grant public key is loaded |
| `unreadable` | a target is not a readable regular file, or the listener table is oversized |
| `unsupported_os` | this host has no listener table |
| `audit_bad` | the hash chain does not verify |
| `bad_contact` | a stored contact does not parse |
| `probe_error` | any other probe failure |

`grant_v1` is `ok` only when the daemon holds a loaded public key, and `absent` with `no_key` otherwise (the name is kept for the registry; the format it verifies is now `secsvc/2`). `integrity` is `ok` only when every watched path is a readable regular file with a baseline record; otherwise it is `degraded` with `unreadable`, then `target_missing`, then `unbaselined`, the worst first. Status never claims coverage it lacks. A probe is read-only. It does not follow a symlink and it does not read file contents. The report carries no path, contact, listener address, or error string. A result does not grant: `GET /v1/status` still requires `security.read`, and a degraded capability leaves every other route on its own entitlement. `GET /v1/catalog` remains the route and entitlement list.

The Unix client sets `Transport.Proxy` to `notify.NoProxy`, a function that returns no proxy. Go treats a nil `Proxy` as `ProxyFromEnvironment`, which would honor `HTTPS_PROXY` and could observe the request. The client does not clone `http.DefaultTransport`.

## State directory

Mode `0700`. Files are mode `0600`.

| file | contents |
| --- | --- |
| `config.json` | `auth_log`, `auth_fail_limit`, `auth_window_s`, `watch`, `listen_allow`, `modules`, `audit_keep_segments`, `page_detail` |
| `contact` | the ntfy contact string |
| `baseline.json` | `{"v":2,"records":{...}}`: per watched path, SHA-256, size, full mode, uid, gid |
| `ids-state.json` | auth position (path, inode, device, offset), open findings, coalesce times, last scan |
| `spent.json` | lease id to expiry |
| `audit/NNNNNN.jsonl` | hash chain segments, mode `0600` in a `0700` directory |
| `audit/segments.json` | index of closed segments: first seq, last seq, last hash |
| `audit.head` | anchor: last seq and hash of the chain |
| `anchor.key` | Ed25519 seed that signs audit heads; created once with `O_EXCL`; never printed |
| `witness.jsonl` | witness records an off-host party posted and the chain held, newest last; before an append it is compacted to at most 500 in at most 64 KiB when it would reach 1000 lines or 128 KiB (half the room to the highest seqs, so the highest-seq witness is always kept, the rest to the newest arrivals, in arrival order), so it stays far below its 256 KiB read cap |
| `audit.jsonl.migrated` | the single-file chain after `secsvc audit migrate`, kept for the operator |
| `lock` | POSIX record lock held by the daemon for its lifetime |
| `findings.jsonl` | capped edge log, 500 lines or 1 MiB |

`GET /v1/config` returns `contact_sha256` and `contact_state`. The contact URL is not a response field and is not an audit field.

## Audit

Each row's hash is SHA-256 over the canonical JSON of `seq`, `prev`, `time`, `actor`, `lease_id`, `action`, and `detail`. The first `prev` is 64 zero hex digits. A rewritten, reordered, truncated, or extra-field line fails verification. A symlink is not followed. A failed append marks the chain broken so later appends fail closed. `secsvc audit verify --dir DIR` runs the full walk with no grant. A missing chain with no anchor verifies as zero rows.

**Segments.** Rows go to `audit/NNNNNN.jsonl`, numbered from `000001`. A segment holds at most 20,000 rows or 4 MiB; the row that would pass either cap goes to the next segment. The hash chain runs across segments: the first row of segment N has `prev` equal to the last hash of segment N-1. Closing a segment writes its entry to `audit/segments.json` (temp file, fsync, rename, directory fsync) before the next segment's first row, so a crash between them leaves a closed index and no next segment, which opens and continues. A segment past the one the index leaves open, or an index whose last entry does not link to the newest segment, is `audit_bad`.

**Runtime reads.** Status, `GET /v1/audit`, and `GET /v1/audit/head` read only `audit.head`, `audit/segments.json`, the newest segment (capped at 4 MiB), and `witness.jsonl`; an append reads nothing and writes the row, the anchor, and on a roll the index. The running daemon is the only writer, so the index must equal the one it holds in memory and the newest segment must end at the row it last wrote; otherwise `audit_truncated`. A runtime read does not open old segments, so it does not see a rewritten or deleted old segment.

**Full verify.** `secsvc audit verify` and `GET /v1/audit/verify` walk every segment on disk, one line at a time with a buffer of one line (64 KiB), against the index: each closed segment must start at its entry's first seq, link to the previous entry's hash, and end at its own entry's last seq and hash; otherwise `audit_bad`. A missing segment is `audit_truncated` unless the newest `audit.pruned` row covers it (see Retention). This is the check that catches a rewritten old segment. In the daemon it takes neither the engine lock nor the store lock: the chain snapshots the index, the newest segment, and the witnesses under its own lock, then walks the closed segments, which do not change, without it, so scans and appends go on. A prune that lands during a walk appends its `audit.pruned` row but leaves the files until the walk ends, and the end of the walk deletes them. A stored witness the chain no longer holds fails the walk with `audit_truncated`, and `secsvc audit verify` prints `witness seq N` on a second stderr line.

**Retention.** `audit_keep_segments` in the config (default 0, keep all; at most 1,000,000) keeps that many closed segments. When a segment closes and more are kept than allowed, the daemon first appends `audit.pruned` with `from`, `through` (segment numbers), and the `last_seq` and `hash` of segment `through`, then deletes those files. The index keeps every entry, so the oldest retained segment stays linked. The full verify accepts missing segments only up to the newest `audit.pruned` row's `through`, and only when that row's `last_seq` and `hash` equal the index entry; a file a failed delete left behind still verifies, and the next roll retries the delete. Changing `audit_keep_segments` (or `page_detail`) needs a grant whose watch covers the state directory, otherwise `config_scope`, because it deletes audit history.

**Layout and migration.** A state directory with `audit.jsonl` is the old single-file layout: open, the daemon, and verify refuse it with `audit_layout`. `secsvc audit migrate --dir DIR` holds the store lock (`store_busy` under a daemon), verifies the old file line by line against `audit.head` exactly as batch 1 did (a non-empty chain with no anchor is `audit_truncated`: run `secsvc audit anchor` first), writes the segments and index into a temporary directory, renames it to `audit/`, renames the old file to `audit.jsonl.migrated`, and appends `audit.migrated` with the `seq`, `hash`, and segment count. An existing `audit/` is `audit_layout`. A crash between the two renames leaves both, and open, verify, and migrate refuse with `audit_layout`: move `audit.jsonl` aside by hand, then run `secsvc audit verify` (that chain has no `audit.migrated` row). `secsvc audit anchor` works only on the single-file layout.

`audit.head` holds `seq` and `hash` of the last row, wherever its segment. It is created with the first row, written atomically after each append (temp file, fsync, rename, directory fsync), and read before the chain. Open, verify, and every runtime re-read (status, `GET /v1/audit`) return `audit_truncated` when the chain ends before the anchor's seq, when the row at that seq has a different hash, when the chain is more than one row past the anchor, when the chain is missing or empty while the anchor exists, or when a non-empty chain has no anchor. An anchor exactly one row behind (a crash between the row and the anchor) is moved up on open. A running daemon also checks that the row it last wrote is still on disk with the same hash, so deleting the anchor and truncating the chain under it is `audit_truncated` too.

A chain written before anchors existed is anchored once by the operator: `secsvc audit anchor --dir DIR` verifies the whole chain, writes the anchor, and appends `audit.anchor_init` with the `seq` and `hash` it anchored. It holds the store lock (`lock`, a POSIX record lock that `serve` takes for its lifetime), so it refuses with `store_busy` while a daemon owns the directory, and refuses with `anchor_exists` when an anchor is already there.

**Residual:** the anchor is local. Root, or anyone who can write the state directory, can rewrite or delete every file together while the daemon is stopped. The anchor stops a truncation of the chain alone, not an attacker with the directory. The off-host anchor below is what catches that, once the agent side exists.

### Off-host anchor (secsvc side)

`anchor.key` is an Ed25519 seed that `serve` creates in the state directory at the first start (`O_EXCL|O_NOFOLLOW`, mode `0600`, fsynced). It is never printed or returned; a group- or world-readable key is `seed_perms` at startup. Its public key is `anchor_pub` in `GET /v1/status`. It is a different key from the grant key.

`GET /v1/audit/head` (`security.audit`) runs the runtime check, then returns `{"head":{"host","seq","hash","segment","time"},"sig"}`. `sig` is base64 Ed25519 over the bytes `secsvc-audit-head-v1\n` followed by the compact JSON of `head` in that field order. The domain line keeps a head signature from being valid as anything else. An empty chain has `seq` 0, the genesis hash, and `segment` 0. The response does not carry the public key: a verifier pins `anchor_pub` out of band, once.

`POST /v1/audit/witness` (`security.witness`, spends the lease) takes a strict body `{"seq","hash","witness","time"}`: `seq` at least 1, `hash` 64 lowercase hex, `witness` matching `^[A-Za-z0-9:._@/-]{1,128}$`, `time` RFC 3339 and at most 35 characters. Anything else is `bad_path`. secsvc stores a witness only when the chain holds it now: the row at `seq` exists and has that `hash`. Then it appends the witness to `witness.jsonl` and audits `audit.witness`. A `seq` past the end or another hash is `witness_mismatch` (409). A row inside a pruned segment, other than that segment's last row (whose hash the index keeps), is `witness_unverifiable` (409). A refused witness is not stored and does not break the chain; it is audited as `audit.witness_refused` with the actor and lease of the verified grant, the witness record, and the code, so a bad poster is traceable. The `witness` label is the poster's data, not an identity. A witness that was stored and later stops matching is tampering with the chain: the runtime read (newest witness, which must also be the one the daemon last stored), open, and the full verify (every stored witness) report `audit_truncated`, fail closed across restarts. The operator investigates with `secsvc audit verify`, which names the witness's seq. Root can delete `witness.jsonl` with everything else; the protection is the copy the witnessing party keeps.

## IDS

Three detectors, off until configured.

Auth tail reads `auth_log` from a stored position: path, inode, device, and offset. A different inode or device, or a size below the offset, is rotation and restarts at 0, so a new file that grew past the old offset is still read. Copytruncate rotation keeps the inode: lines written after the copy and past the saved offset before the next scan are missed, because the file only looks rotated once its size drops below the offset. Prefer create-mode rotation (logrotate's default) for the auth log. The first scan of a path with no saved position for it (a new install, a changed `auth_log`, or state from an older binary) starts at the end of the file and pages on nothing, because old lines would otherwise be dated now. The IP in the summary comes only from sshd's fixed structure, the token after the last ` from ` that precedes the last ` port `, and must parse as an IP; otherwise the summary has no IP. PAM `rhost=` is not read. Matching is a fixed substring list. The raw line is not a finding. Five failures in 300 seconds is the default, and the finding is `auth_fail` at severity `high`. An unreadable log suppresses `auth_fail` for that scan and records `auth_log_unavailable` at `medium`.

Integrity `Lstat`s each watch path and does not follow a symlink. A symlink, a missing baselined path, a changed hash or size, a changed mode (file type, setuid, setgid, sticky, or permission bits), uid, or gid, or an unreadable baselined file is `high`. A version-1 baseline (a bare path map, permission bits only) is neither compared nor upgraded, because adopting the file's current setuid bit, uid, or gid would bless a change made before the upgrade: it loads as no records, every watched path is `integrity_unbaselined` and the `integrity` cap is `unbaselined`, until an explicit `POST /v1/baseline` writes version 2 with its `baseline.set` audit row. A missing or unloadable baseline never resolves an integrity finding: an open `integrity_changed`, `integrity_missing`, `integrity_symlink`, `integrity_not_file`, or `integrity_oversize` on a watched path with no baseline record stays open at its severity until a scan against a real baseline shows the file matching, or the path leaves the watch list. An unbaselined path is `medium`. `POST /v1/baseline` measures the current watch list. Every open of a configured path, by a scan or by the status probe, is `O_NONBLOCK|O_NOFOLLOW` and checks with fstat that the file is regular before any read; a FIFO, socket, or device is `integrity_not_file` (or `auth_log_unavailable`, or a capability `unreadable`) with internal code `not_regular`, never a blocking read. Reads are capped (1 MiB per auth scan, 4 MiB per hashed file).

Listeners decode `/proc/net/tcp` and `/proc/net/tcp6` only when `listen_allow` is non-empty. An address outside that list is `listen_unexpected` at `high`. A truncated table is `listen_truncated` at `medium`. A decode failure is `unsupported`, so a partial table is not treated as clean.

Only severity `high` is paged. A `medium` finding is audited and marked paged immediately, so it does not page on a later scan. The same kind pages at most once per 60 seconds (`page.coalesced`). With no contact file, paging is off and the finding is still marked paged.

**Pages are sent after the scan commits.** A scan decides its pages, marks each finding `pending` (durably, in `ids-state.json` with the scan's commit), and queues the pages on a bounded queue (64); the response returns then. A pager goroutine sends each page (5 s timeout) and audits `page.sent` or `page.failed` with the kind, the contact fingerprint, the page id, and the error code. A finding becomes paged only on `page.sent`. A failed send or a full queue (`queue_full`) clears `pending` and leaves the finding unpaged, so the next scan pages it again. A bad contact at decision time is `page.failed` in the scan itself. At shutdown `serve` stops the scan loop first and the pager after it; pages still queued stay `pending`, and at the next start `serve` queues every pending page again before the first scan, so neither a stop nor a crash between the commit and the send loses a page (a crash during a send may send it twice).

**Pages carry no host detail.** The ntfy topic is public to anyone who learns or guesses it, so treat the contact as a secret and the page as public. By default a body is

- `secsvc high KIND: N high finding(s) open, ref PAGEID`

where `KIND` is the finding kind, `N` the number of open high findings after the scan, and `PAGEID` 16 random hex characters stored with the finding. It names no host, path, subject, summary, or address. `secsvc call findings` (and the report) shows `page_id` next to the local detail. `page_detail: true` in the config restores the old bodies, clipped at 200 bytes on a UTF-8 boundary, and puts that detail on the public topic:

- `secsvc auth_fail on HOST: SUMMARY`
- `secsvc integrity_changed on HOST: SUBJECT`
- `secsvc listen_unexpected on HOST: SUBJECT`

The contact form is the same string `notices.js` accepts: `push:ntfy:https://ntfy.sh/` plus a topic of 20 to 64 characters from `[A-Za-z0-9_-]`. Email, another host, userinfo, a port, a query, a fragment, and a trailing slash are `bad_contact`.

## ntfy

`http.Transport.Proxy` is `notify.NoProxy`. TLS minimum version is 1.3. `ServerName` is `ntfy.sh`. Redirects are refused. The client timeout is 5 seconds. DNS answers are pinned to public addresses; any loopback, private, link-local, CGNAT, multicast, unspecified, documentation, or benchmarking address, including `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, and `2001:db8::/32`, is `blocked_address`. There is no allow-private switch. A response is success only for status 2xx. Logs and audit rows store the contact's SHA-256, never the topic.

`PUT /v1/contact` parses, checks egress, then spends the lease.

## Fail closed

A bad grant, a bad path, a bad contact, a blocked address, a broken audit chain, and a failed spend return an error and leave the previous state in place. The scan loop does not save detector memory when the audit append fails, so the next scan retries the page. Socket mode is not authentication. The process logs stable codes and does not log seeds, grant documents, or contact URLs.

## Distro modules and report snapshots

See [modules.md](modules.md) for the module registry, fixed read surfaces,
authorization, coverage states, and the `secsvc-report/1` contract. Module
results and detector-config fingerprints are persisted with `ids-state.json`.
Explicitly disabling a module/check writes `ids.withdrawn` for removed findings;
incomplete checks retain prior findings. Status includes `system` and
`config_changed`; the original capability registry remains unchanged.

`OpenRec` now stores first/last seen times and whether a finding was observed in
the last scan. Old state without these additive fields remains readable. Older
binaries use strict state parsing, so downgrade requires an explicit state
migration/backup plan; do not overwrite the new state with an older binary.
