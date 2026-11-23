# systemapi-security

Local host security service for one Linux machine. The binary is `secsvc`. It listens on a Unix socket, checks `secsvc/2` Ed25519 grants, keeps an append-only audit chain in capped segments with a local anchor (`audit.head`) and a signed head plus stored witnesses for an off-host anchor (root can still rewrite every local file; the agent side that collects heads is a later systemapi.io batch), and runs a host IDS plus configurable distro security modules. High findings page through ntfy.sh without host detail.

**sah** means Service Automation Hub. This repository is its own module, `github.com/afterdarksys/systemapi-security`.

This is a local host service. Suite enrollment stays in systemapi. Packet inspection is out of scope. sahcore stays docs-only. The control-plane audit stays in systemapi. `secsvc` does not import sash, adssh, or systemapi.

The shipped unit is `units/secsvc.json`. sahinit has no `User=`, so that unit cannot drop privileges. The unit ships `--host ""` because sahinit does not expand variables: set it to the host name the grants carry. `serve` refuses an empty host, a loopback name such as `localhost`, or an IP literal with `host_unset`, so an unedited unit does not start. Until sahinit is PID 1, an operator can run `secsvc serve` under any supervisor.

```bash
go build -o secsvc ./cmd/secsvc
# or: ./build.sh
```

## Breaking changes (hardening batch 1)

- Grants are `secsvc/2` with a signed `iat`. `secsvc/1` grants are refused (`grant_bad_shape`); re-sign them with this binary's `secsvc grant`.
- `--host` must be a real host name. Empty, `localhost` and the other loopback names, and IP literals are `host_unset`. Set it in the unit, `service.env`, or `conf.d/secsvc`.
- An existing audit chain has no `audit.head` and is now `audit_truncated`. Run `secsvc audit anchor --dir /var/lib/secsvc` once, with the daemon stopped, then start it.
- A version-1 integrity baseline is not used. Every watched path reports unbaselined until you re-baseline with `secsvc call baseline` and a `security.baseline` grant.
- `listen_allow` and the auth thresholds need grant coverage of what they govern (`config_scope` otherwise), and `POST /v1/scan` spends its lease.

## Breaking changes (hardening batch 2)

- The audit chain is segmented under `audit/`. A state directory with `audit.jsonl` is refused with `audit_layout`; with the daemon stopped, run `secsvc audit migrate --dir /var/lib/secsvc` (run `secsvc audit anchor` first if it reports `audit_truncated` on a chain from before `audit.head`).
- `GET /v1/audit?limit=N` returns rows from the newest segment only; use `GET /v1/audit/verify` or `secsvc audit verify` for the whole chain.
- `GET /v1/audit/verify` runs one walk at a time and once a minute per grant actor (`429` `rate_limited`); poll the cheaper `GET /v1/status` instead.
- Page bodies no longer name the host, a path, a subject, or an address; look a page's `ref` up in `secsvc call findings` (`page_id`), or set `page_detail: true` in the config to restore the old bodies.
- Audit actions `notify.sent`, `notify.failed` and `notify.coalesced` are now `page.sent`, `page.failed` and `page.coalesced`; update anything that filters the audit by action.
- Posting a witness needs the new purpose `security:witness` (ceiling `security.audit`, `security.witness`); no other purpose carries it, so issue the collector `secsvc grant --purpose security:witness`.
- `audit_keep_segments` and `page_detail` changes need a grant whose `--watch` covers the state directory (`config_scope` otherwise); issue the grant with `--watch /var/lib/secsvc`.

## Operator

```bash
secsvc keygen --seed-out /etc/secsvc/seed
secsvc grant --seed /etc/secsvc/seed --actor ops --host HOST \
  --purpose security:operate --ttl 10m --lease lease-op0001
secsvc serve --dir /var/lib/secsvc --pub /etc/secsvc/pub.hex \
  --host HOST --socket /run/secsvc/sock --interval 30s
secsvc call status --socket /run/secsvc/sock --grant /tmp/grant.json
secsvc audit verify --dir /var/lib/secsvc
secsvc audit anchor --dir /var/lib/secsvc   # once, for a chain from before audit.head
secsvc audit migrate --dir /var/lib/secsvc  # once, daemon stopped, for a single-file chain
```

The ntfy topic in the contact is a bearer: anyone who learns or guesses it reads every page. Treat it as a secret. Pages carry only a kind, a count and a reference unless `page_detail` is on.

`keygen` prints the public key as 64 hex characters and writes the seed with `O_EXCL` at mode `0600`. The seed is not printed. `grant` checks policy before it loads the seed or signs. A purpose with no `--entitlement` flags receives that purpose's full ceiling. `--ttl` is a whole number of seconds, at most `15m`.

`call` sends `X-Secsvc-Grant` and does not verify the document itself. The daemon does. A contact file must be a regular file at mode `0600`. Config and contact text stay off stderr. Exit `0` prints the API JSON. Exit `2` is usage or local configuration. Exit `1` is a refusal or a failed call. The first stderr line is a stable code from `internal/codes`.

`serve` exits `0` after `SIGINT` or `SIGTERM`. Any serve error, including `--interval` under `5s`, exits `2` and prints the code. An interval under `5s` returns before the state directory is created.

## API

The socket is the only listener. Routes, entitlements, and the audit layout are in `docs/architecture.md`. A future sash verb is specified in `docs/sash-verb.md` and is not in the sash builtin table.

## Distro security modules

Opt-in modules now cover Debian, Red Hat, Rocky, Ubuntu, Alpine, and Arch, with
account, permissions, kernel, SSH, mount, and SELinux/AppArmor checks. Each profile
and check can be enabled or disabled through configuration. Coverage failures are
reported explicitly; failed checks retain existing findings.

- [Module configuration and behavior](docs/modules.md)
- [Per-distro and fleet examples](examples/)
- [systemd and OpenRC service templates](packaging/README.md)
- [Claude handoff for agent/backend/dashboard integration](docs/CLAUDE-HANDOFF.md)

`secsvc call modules` reads the registry; `secsvc call report` reads the versioned
local snapshot (both need `--socket` and a read `--grant`). No remote reporting
is enabled. All six profiles have fixture tests; Debian, Ubuntu, Rocky, and Alpine
also passed container smoke tests. Full host/service-manager validation remains.

## Verification

`go test -count=1 -race ./...`

`sahinit plan` accepts `units/secsvc.json` when that directory contains only the unit file.
