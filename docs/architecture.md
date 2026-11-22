# secsvc

`secsvc` is one process on one host. sahinit supervises it when that supervisor is PID 1. The process answers HTTP over a Unix socket. Grants are `secsvc/1` Ed25519 documents. The daemon stores the public key and spends each lease id once. The audit chain is the host record.

## Startup

`secsvc serve` requires `--dir`, `--pub`, `--host`, and `--socket`. `--interval` defaults to `30s` and must be at least `5s`. A shorter interval returns `usage` before the state directory exists.

Order after that check:

1. Host grammar, then load the public key. Log step `validate`.
2. Open the state directory at mode `0700`. Log step `store`.
3. Listen on the absolute socket path. Log step `listen`.
4. `chmod` the socket to `0660`.
5. Write one byte, `\n`, to the file descriptor in `SAHINIT_READY_FD` when that variable is set. The descriptor number is the variable's value. Log step `ready`.
6. Start the scan loop, then serve HTTP until `SIGINT` or `SIGTERM`.

The ready byte is written only after `Listen` succeeds. A clean shutdown unlinks the socket and returns success.

The parent of the socket is created at mode `0750` when it is missing. An existing socket inode is removed and replaced. A symlink at the socket path or its parent is `bad_socket`.

## Grant

Domain string `secsvc-grant-v1\n`. Signature is Ed25519 and is checked before expiry, a star, a filesystem root, TTL, the purpose ceiling, and the host. Maximum document size is 16 KiB. Maximum TTL is 900 seconds. A lease id matches `^[A-Za-z0-9_-]{8,64}$`.

| purpose | ceiling |
| --- | --- |
| `security:read` | `security.audit`, `security.read` |
| `security:config` | those, plus `security.baseline`, `security.config`, `security.notify` |
| `security:operate` | those, plus `security.scan` |

`*` is `grant_star`. A watch of `/` is `grant_root_slash`. The daemon refuses a grant whose host differs from `--host` with `grant_host`. A second use of the same lease id is `grant_spent`. Spend is recorded before the commit and stays recorded when the commit fails. A blocked ntfy egress check returns before the lease is spent.

A grant's `watch` list covers an `auth_log` or `watch` path that a config replace adds or removes. An unchanged path may sit outside the grant. `listen_allow` entries are addresses, not paths.

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

`POST /v1/scan` and `POST /v1/baseline` require an empty body. `PUT /v1/config` replaces the whole config. `{}` is a valid replace and clears `auth_log`, `watch`, and `listen_allow`. `GET /v1/audit` that fails chain verification returns `500` `audit_bad`. Audit JSON uses the API field names `seq`, `prev`, `time`, `actor`, `lease_id`, `action`, `detail`, `hash`.

## Capabilities

`GET /v1/status` includes `caps`. Each entry is a name from a fixed registry, a state of `ok`, `degraded`, or `absent`, and a reason from a closed set. `ok` has an empty reason. The registry is `audit`, `auth`, `grant_v1`, `integrity`, `listen`, and `notify`.

| reason | when |
| --- | --- |
| `flag_off` | the detector is not configured |
| `target_missing` | every configured target is absent |
| `unreadable` | a target is not a readable regular file, or the listener table is oversized |
| `unsupported_os` | this host has no listener table |
| `audit_bad` | the hash chain does not verify |
| `bad_contact` | a stored contact does not parse |
| `probe_error` | any other probe failure |

`grant_v1` is a property of this binary and is `ok` on every report. A probe is read-only. It does not follow a symlink and it does not read file contents. The report carries no path, contact, listener address, or error string. A result does not grant: `GET /v1/status` still requires `security.read`, and a degraded capability leaves every other route on its own entitlement. `GET /v1/catalog` remains the route and entitlement list.

The Unix client sets `Transport.Proxy` to `notify.NoProxy`, a function that returns no proxy. Go treats a nil `Proxy` as `ProxyFromEnvironment`, which would honor `HTTPS_PROXY` and could observe the request. The client does not clone `http.DefaultTransport`.

## State directory

Mode `0700`. Files are mode `0600`.

| file | contents |
| --- | --- |
| `config.json` | `auth_log`, `auth_fail_limit`, `auth_window_s`, `watch`, `listen_allow`, `modules` |
| `contact` | the ntfy contact string |
| `baseline.json` | SHA-256 records for watched paths |
| `ids-state.json` | offsets, open findings, coalesce times, last scan |
| `spent.json` | lease id to expiry |
| `audit.jsonl` | hash chain |
| `findings.jsonl` | capped edge log, 500 lines or 1 MiB |

`GET /v1/config` returns `contact_sha256` and `contact_state`. The contact URL is not a response field and is not an audit field.

## Audit

Each row's hash is SHA-256 over the canonical JSON of `seq`, `prev`, `time`, `actor`, `lease_id`, `action`, and `detail`. The first `prev` is 64 zero hex digits. A rewritten, reordered, truncated, or extra-field line fails verification. A symlink is not followed. A failed append marks the chain broken so later appends fail closed. `secsvc audit verify --dir DIR` checks `audit.jsonl` with no grant. A missing chain inside a real directory verifies as zero rows.

## IDS

Three detectors, off until configured.

Auth tail reads `auth_log` from a stored offset. Matching is a fixed substring list. The raw line is not a finding. Five failures in 300 seconds is the default, and the finding is `auth_fail` at severity `high`. An unreadable log suppresses `auth_fail` for that scan and records `auth_log_unavailable` at `medium`.

Integrity `Lstat`s each watch path and does not follow a symlink. A symlink, a missing baselined path, a changed hash, or an unreadable baselined file is `high`. An unbaselined path is `medium`. `POST /v1/baseline` measures the current watch list.

Listeners decode `/proc/net/tcp` and `/proc/net/tcp6` only when `listen_allow` is non-empty. An address outside that list is `listen_unexpected` at `high`. A truncated table is `listen_truncated` at `medium`. A decode failure is `unsupported`, so a partial table is not treated as clean.

Only severity `high` is paged. A `medium` finding is audited and marked paged immediately, so it does not page on a later scan. The same kind pages at most once per 60 seconds. With no contact file, paging is off and the finding is still marked paged.

Page bodies differ from a bare ntfy title. Each body names the kind, the host, and a short subject, clipped at 200 bytes on a UTF-8 boundary:

- `secsvc auth_fail on HOST: SUMMARY`
- `secsvc integrity_changed on HOST: SUBJECT`
- `secsvc listen_unexpected on HOST: SUBJECT`

The contact form is the same string `notices.js` accepts: `push:ntfy:https://ntfy.sh/` plus a topic of 20 to 64 characters from `[A-Za-z0-9_-]`. Email, another host, userinfo, a port, a query, a fragment, and a trailing slash are `bad_contact`.

## ntfy

`http.Transport.Proxy` is `notify.NoProxy`. TLS minimum version is 1.3. `ServerName` is `ntfy.sh`. Redirects are refused. The client timeout is 5 seconds. DNS answers are pinned to public addresses; any loopback, private, link-local, CGNAT, multicast, unspecified, documentation, or benchmarking address, including `198.51.100.0/24` and `203.0.113.0/24`, is `blocked_address`. There is no allow-private switch. A response is success only for status 2xx. Logs and audit rows store the contact's SHA-256, never the topic.

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
