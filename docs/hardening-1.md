# secsvc hardening, batch 1: contract

2026-11-22. Source: the independent audit of `289299c`. Branch: `fix/hardening-1`.

Every fix below comes with:
- a test that fails if the fix is reverted;
- a `Threats:` note in the code it changes;
- a stable code from `internal/codes` for each refusal.

| # | Problem | Fix |
| --- | --- | --- |
| S1 | Truncating or deleting the audit chain goes undetected. Appends restart at seq 1. | A local anchor, `audit.head`, kept next to `audit.jsonl`. It holds the last seq and the hash of the last row, and is written atomically after each append (temp file, fsync, rename, directory fsync). Verify and open fail with `audit_truncated` when the chain ends before the anchor's seq or hash, or when the chain is missing while the anchor exists. The anchor is created with the first row; an empty chain with no anchor is a fresh store. **Residual:** root can rewrite both files. An off-host anchor is a later batch, through the agent. Docs must say this plainly. |
| S2 | A FIFO or other special file hangs the daemon: status blocks while holding `e.mu`, and the IDS goes silent. | Every scan and status open of a configured path uses `O_NONBLOCK\|O_NOFOLLOW` (as modules already does). It then checks with fstat that the file is regular before reading. A non-regular file is a finding or coverage error (`not_regular`), never a blocking read. Reads have a size cap. |
| S3 | `POST /v1/scan` never spends its lease, so one grant replays for 15 minutes. | A scan spends its lease exactly once, as config mutations do. A second scan with the same grant is refused with `lease_spent`. Update the test that scans with an already-spent lease. |
| S4 | A config grant scoped to one path can change global settings (`listen_allow`, `auth_fail_limit`, `auth_window_s`). | `AllowChange` treats every global field as needing a grant whose coverage includes it. A narrow-path grant can change only the watch entries it covers. Otherwise `config_scope`. |
| S5 | Integrity baselines record only the 0777 bits. Setuid/setgid/sticky, uid and gid changes go unreported. | The baseline records the full mode bits (including setuid, setgid and sticky), uid, gid and file type. A change to any of them is a finding. The baseline format is versioned. An old baseline is re-taken once, with an audit row, instead of silently compared. |
| S6 | The shipped unit pins `--host localhost`. | The unit and the service templates take the host from configuration with no default value. `serve` refuses `localhost` and empty with `host_unset`. A test checks this. |
| S7 | Auth-log tailing has three problems. **(a)** It misses rotation when the new file grows past the saved offset. **(b)** The first scan dates old lines "now" and pages on them. **(c)** It takes the IP from attacker text. | **(a)** Track inode and device as well as offset: a different inode, or a size below the offset, means rotation. **(b)** On the first scan with no saved state, start at the end of the file (the baseline) and do not page on history. **(c)** Parse the IP only from the fixed sshd message structure: the token after the last ` from ` that precedes ` port `. It must parse as an IP. Otherwise no IP is reported. |
| S8 | Caps reports `covered` when it is not. | The integrity cap is `ok` only when every watched path exists and is baselined, otherwise `degraded` with a reason. `grant_v1` reports whether a public key is loaded. Status never claims coverage it lacks. |
| S9 | The shadow-file group owner is not checked. | The permissions module checks the shadow file's group: root, or the distro's shadow group. A finding otherwise. |
| S10 | Grants have no not-before. A far-future grant becomes usable in its last 15 minutes. | Grants carry `iat`, signed. The daemon refuses a grant with `iat` in the future (beyond 60 seconds of skew), or with `exp - iat` above the 15-minute ceiling. Old grants without `iat` are refused (`grant_bad_shape`). This is a format change, so the version is bumped to `secsvc/2`, and the Go vectors are updated. |
| S11 | Leftovers from earlier tools. | Remove `modules.RequiredPaths` (only tests call it, and its comment claims it is the grant gate). Remove the `ntfy` substring check, which can never match. Make the blocked documentation ranges match the comment by adding 2001:db8::/32. |

## Out of this batch

- An off-host audit anchor (agent and backend).
- Audit log rotation and bounded reads (audit item 9). This is the next batch, together with the anchor.
- ntfy topic exposure (item 10). Document that the topic is a secret and the content leaves the host.
- The API write timeout (item 12).

## Verification

- `./build.sh` and `go test -count=1 -race ./...` pass.
- The distro smoke script runs where Docker is available.
- An adversarial review of the batch is done before any push.
