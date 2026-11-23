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

`*` is `grant_star`. A watch of `/` is `grant_root_slash`. The daemon refuses a grant whose host differs from `--host` with `grant_host`. A second use of the same lease id is `grant_spent`. Spend is recorded before the commit and stays recorded when the commit fails. A blocked ntfy egress check returns before the lease is spent.

A grant's `watch` list covers an `auth_log` or `watch` path that a config replace adds or removes. An unchanged path may sit outside the grant; an uncovered changed path is `forbidden`. `listen_allow` entries are addresses, not paths.

Global fields need coverage of what they govern, so a grant scoped to one path cannot change them. A `listen_allow` change (as a set) needs a grant that covers `/proc/net/tcp` and `/proc/net/tcp6`, for example `--watch /proc/net`. An `auth_fail_limit` or `auth_window_s` change needs coverage of every `auth_log` set before or after the replace, and is refused when neither is set. Otherwise the replace is `config_scope` (403) and spends nothing.

## HTTP

Header `X-Secsvc-Grant`. One value. Body cap 64 KiB. Header cap 32 KiB. Read header timeout 5s, read and write timeouts 10s. Unknown paths return `404` `{"error":"bad_path"}` before the grant is read. A known path with the wrong method returns `405` before the grant is read. A grant that lacks the route entitlement is `403` `forbidden` before the body is parsed.

| method | path | entitlement |
| --- | --- | --- |
| `GET` | `/v1/audit` | `security.audit` |
| `GET` | `/v1/audit/verify` | `security.audit` |
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

`POST /v1/scan` and `POST /v1/baseline` require an empty body. Both spend the grant's lease, so a second scan on the same grant is `grant_spent`. The internal scan loop spends nothing. `PUT /v1/config` replaces the whole config. `{}` is a valid replace and clears `auth_log`, `watch`, and `listen_allow`. `GET /v1/audit` that fails chain verification returns `500` `audit_bad`. Audit JSON uses the API field names `seq`, `prev`, `time`, `actor`, `lease_id`, `action`, `detail`, `hash`.

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
| `config.json` | `auth_log`, `auth_fail_limit`, `auth_window_s`, `watch`, `listen_allow`, `modules` |
| `contact` | the ntfy contact string |
| `baseline.json` | `{"v":2,"records":{...}}`: per watched path, SHA-256, size, full mode, uid, gid |
| `ids-state.json` | auth position (path, inode, device, offset), open findings, coalesce times, last scan |
| `spent.json` | lease id to expiry |
| `audit.jsonl` | hash chain |
| `audit.head` | anchor: last seq and hash of the chain |
| `lock` | POSIX record lock held by the daemon for its lifetime |
| `findings.jsonl` | capped edge log, 500 lines or 1 MiB |

`GET /v1/config` returns `contact_sha256` and `contact_state`. The contact URL is not a response field and is not an audit field.

## Audit

Each row's hash is SHA-256 over the canonical JSON of `seq`, `prev`, `time`, `actor`, `lease_id`, `action`, and `detail`. The first `prev` is 64 zero hex digits. A rewritten, reordered, truncated, or extra-field line fails verification. A symlink is not followed. A failed append marks the chain broken so later appends fail closed. `secsvc audit verify --dir DIR` checks `audit.jsonl` with no grant. A missing chain with no anchor verifies as zero rows.

`audit.head` holds `seq` and `hash` of the last row. It is created with the first row, written atomically after each append (temp file, fsync, rename, directory fsync), and read before the chain. Open, verify, and every runtime re-read (status, `GET /v1/audit`) return `audit_truncated` when the chain ends before the anchor's seq, when the row at that seq has a different hash, when the chain is more than one row past the anchor, when the chain is missing or empty while the anchor exists, or when a non-empty chain has no anchor. An anchor exactly one row behind (a crash between the row and the anchor) is moved up on open. A running daemon also checks that the row it last wrote is still on disk with the same hash, so deleting the anchor and truncating the chain under it is `audit_truncated` too.

A chain written before anchors existed is anchored once by the operator: `secsvc audit anchor --dir DIR` verifies the whole chain, writes the anchor, and appends `audit.anchor_init` with the `seq` and `hash` it anchored. It holds the store lock (`lock`, a POSIX record lock that `serve` takes for its lifetime), so it refuses with `store_busy` while a daemon owns the directory, and refuses with `anchor_exists` when an anchor is already there.

**Residual:** the anchor is local. Root, or anyone who can write the state directory, can rewrite or delete both files together while the daemon is stopped, or run `secsvc audit anchor` after deleting the anchor. The anchor stops a truncation of the chain alone, not an attacker with the directory. An off-host anchor, kept by the agent, is a later batch.

## IDS

Three detectors, off until configured.

Auth tail reads `auth_log` from a stored position: path, inode, device, and offset. A different inode or device, or a size below the offset, is rotation and restarts at 0, so a new file that grew past the old offset is still read. Copytruncate rotation keeps the inode: lines written after the copy and past the saved offset before the next scan are missed, because the file only looks rotated once its size drops below the offset. Prefer create-mode rotation (logrotate's default) for the auth log. The first scan of a path with no saved position for it (a new install, a changed `auth_log`, or state from an older binary) starts at the end of the file and pages on nothing, because old lines would otherwise be dated now. The IP in the summary comes only from sshd's fixed structure, the token after the last ` from ` that precedes the last ` port `, and must parse as an IP; otherwise the summary has no IP. PAM `rhost=` is not read. Matching is a fixed substring list. The raw line is not a finding. Five failures in 300 seconds is the default, and the finding is `auth_fail` at severity `high`. An unreadable log suppresses `auth_fail` for that scan and records `auth_log_unavailable` at `medium`.

Integrity `Lstat`s each watch path and does not follow a symlink. A symlink, a missing baselined path, a changed hash or size, a changed mode (file type, setuid, setgid, sticky, or permission bits), uid, or gid, or an unreadable baselined file is `high`. A version-1 baseline (a bare path map, permission bits only) is neither compared nor upgraded, because adopting the file's current setuid bit, uid, or gid would bless a change made before the upgrade: it loads as no records, every watched path is `integrity_unbaselined` and the `integrity` cap is `unbaselined`, until an explicit `POST /v1/baseline` writes version 2 with its `baseline.set` audit row. An unbaselined path is `medium`. `POST /v1/baseline` measures the current watch list. Every open of a configured path, by a scan or by the status probe, is `O_NONBLOCK|O_NOFOLLOW` and checks with fstat that the file is regular before any read; a FIFO, socket, or device is `integrity_not_file` (or `auth_log_unavailable`, or a capability `unreadable`) with internal code `not_regular`, never a blocking read. Reads are capped (1 MiB per auth scan, 4 MiB per hashed file).

Listeners decode `/proc/net/tcp` and `/proc/net/tcp6` only when `listen_allow` is non-empty. An address outside that list is `listen_unexpected` at `high`. A truncated table is `listen_truncated` at `medium`. A decode failure is `unsupported`, so a partial table is not treated as clean.

Only severity `high` is paged. A `medium` finding is audited and marked paged immediately, so it does not page on a later scan. The same kind pages at most once per 60 seconds. With no contact file, paging is off and the finding is still marked paged.

Page bodies differ from a bare ntfy title. Each body names the kind, the host, and a short subject, clipped at 200 bytes on a UTF-8 boundary:

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
