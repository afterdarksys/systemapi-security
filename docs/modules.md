# Distro modules and host security checks

`secsvc` now has six compiled-in, read-only distro modules. Configuration can
enable several profiles for a fleet, but only the profile matching the machine's
exact `/etc/os-release` ID runs. Unknown distributions are reported as unsupported;
`ID_LIKE` is not a claim of validated support. No package installation, shell
commands, automatic remediation, or network requests are performed by these checks.

| Config key | OS ID | Package ecosystem (metadata only) | Default MAC check |
| --- | --- | --- | --- |
| `debian` | `debian` | apt | AppArmor |
| `ubuntu` | `ubuntu` | apt | AppArmor |
| `redhat` | `rhel` | dnf | SELinux |
| `rocky` | `rocky` | dnf | SELinux |
| `alpine` | `alpine` | apk | none |
| `arch` | `arch` | pacman | none |

Each profile defaults to `accounts`, `permissions`, `kernel`, `ssh`, and `mounts`.
Debian, Ubuntu, Red Hat, and Rocky also default to `mac`. A distribution's MAC
choice is a profile policy, not proof that the feature is installed. Missing or
unreadable MAC interfaces make coverage degraded. Alpine/Arch can explicitly
select `mac`, but it reports unsupported until a policy is implemented for them.

## Configuration

Existing configurations remain valid, and modules default off. Example:

```json
{
  "modules": {
    "ubuntu": {"enabled": true, "checks": ["accounts", "permissions", "kernel", "mac"]},
    "rocky": {"enabled": true},
    "alpine": {"enabled": false}
  }
}
```

Omitted or null `checks` means the profile defaults; `checks: []` means no checks.
Unknown profiles, unknown checks, duplicates, and unknown object fields are
rejected. `PUT /v1/config` remains a **full replacement**, so retain any existing
`auth_log`, `watch`, and `listen_allow` entries you want to keep. `{}` disables
all detectors. See `examples/` for per-distro and fleet configurations.

Enabling or disabling a profile/check requires `security.config` and grant watch
coverage for its fixed input paths. Checks that do not change need no additional
coverage. Discovery paths `/etc/os-release` and `/usr/lib/os-release` are required
for changes, even when configuring a profile for a different distro. This prevents
an automatic future match from introducing unauthorized reads.

For example, using an existing signing seed and a daemon configured as `host1`:

```sh
secsvc grant --seed /etc/secsvc/seed --actor ops --host host1 \
  --purpose security:config --ttl 10m --lease module-config-0001 \
  --watch /etc --watch /usr/lib/os-release --watch /proc/sys \
  --watch /proc/1/mountinfo --watch /sys > /tmp/module-grant.json
secsvc call config-set --socket /run/secsvc/sock \
  --grant /tmp/module-grant.json --file examples/fleet.json
```

The default scan loop applies the config on its next scan. Use a separate grant
with `security.scan` to request an immediate scan. Read grants can inspect:

```sh
secsvc call modules --socket /run/secsvc/sock --grant /tmp/read-grant.json
secsvc call report --socket /run/secsvc/sock --grant /tmp/read-grant.json
secsvc call status --socket /run/secsvc/sock --grant /tmp/read-grant.json
```

`GET /v1/modules` returns the registry; `GET /v1/report` returns a coherent local
snapshot with schema `secsvc-report/1`. Both require `security.read`. GETs do not
run system checks. The existing `/v1/catalog` and `call catalog` expose routes.

## Checks and limits

| Check | Inputs and findings |
| --- | --- |
| `accounts` | `/etc/passwd`, `/etc/shadow`: non-root UID-zero accounts, duplicate UIDs, empty password fields. Findings contain counts, never usernames or password hashes. Locked password markers are not empty passwords. This covers local files, not LDAP/NSS identities or PAM's effective login policy. |
| `permissions` | Root ownership and excessive permissions on passwd, group, shadow, gshadow, sudoers, and sshd_config. Shadow group-read is allowed; group-write and other access are flagged. Missing optional files still produce degraded coverage. Symlinks are not followed. |
| `kernel` | Twelve live `/proc/sys` values: ASLR, kernel pointer/log restrictions, protected hardlinks/symlinks, IPv4 redirect/source-route settings and SYN cookies. Findings are policy observations, not proof of exploitation. Per-interface and IPv6 policy are not evaluated. |
| `ssh` | Explicit risky global declarations in `/etc/ssh/sshd_config`, with first-value semantics. Includes, Match blocks, quoting, continuations, and nontrivial syntax mark coverage incomplete. Match-specific settings are not evaluated; defaults are not inferred. This does not claim to reproduce `sshd -T` or prove the running daemon uses this file. |
| `mounts` | `/proc/1/mountinfo`: `nosuid` and `nodev` on dedicated `/tmp`, `/var/tmp`, `/dev/shm` mounts. Missing dedicated mounts are review findings. Parent/inherited protections are not guessed. A container PID 1 describes that container's namespace, not its physical host. |
| `mac` | Red Hat/Rocky: `/sys/fs/selinux/enforce`, with permissive mode flagged high. Debian/Ubuntu: AppArmor enablement and loaded enforcing/complain profile counts. Missing interfaces mean unknown coverage, not an assertion that MAC is disabled. Loaded profiles do not prove every workload is confined. |

Reads are limited to 1 MiB per fixed input; special files and final-component
symlinks are rejected without blocking on FIFOs. The only permitted final symlink
is `/etc/os-release` pointing to the fixed `/usr/lib/os-release` target. Parent
directory symlink handling follows the existing service threat model (out of
scope). Modules do not follow configurable paths, run subprocesses, or emit raw
host file contents. `security.read` still exposes finding subjects (paths) and
existing IDS summaries; do not treat the report as anonymous telemetry.

## Coverage and finding lifecycle

Module/check states: `disabled`, `pending`, `not_applicable`, `ok`, `degraded`.
Platform detection additionally uses `absent` for unsupported OS/distro.
`ok` means the check completed; a completed check may have high findings.
Reasons are fixed codes, never error strings. Empty findings with degraded,
disabled, pending, or mismatched coverage do not mean the machine is secure.

Findings use kinds `system.<profile>.<check>.<rule>`. They join the existing open
finding set, audit edges, and high-severity ntfy flow. A failed/incomplete check
retains previous findings; successful checks can resolve them. Disabling a check
removes its findings with an `ids.withdrawn` audit edge rather than
`ids.resolved`. A distro change retains the old profile's findings until that
profile is explicitly disabled. New observations update last-seen timestamps.

Reports include stable finding IDs, first/last seen times, and an observation of
`observed`, `retained`, or `stale`. A fingerprint hashes host + NUL + kind + NUL +
subject (the existing auth finding identity is just its kind). Missing historical
timestamps are empty for records written by older binaries; they are not invented.

`last_scan` is the last completed persisted scan. `generated_at` is only the
response time. `config_sha256` identifies current normalized detector config;
`scan_config_sha256` identifies what was scanned. A difference sets
`config_changed`, makes coverage pending, and marks findings stale until a scan
completes. Contact changes do not change this detector-config fingerprint.

This release does not add remote reporting, package/CVE scanning, firewall rule
evaluation, malware signatures, compliance certification, or automatic repairs.
Those need their own bounded collectors, policies, and validation. The local
module interface and report contract are the foundation for that work.

## Validation

Fixture tests exercise all six exact distro IDs, positive and negative checks,
unsupported platforms, partial failures, path authorization, redaction, symlinks,
FIFOs, read limits, finding retention/withdrawal, API access, and restart behavior.
Run `go test -count=1 -race ./...` and `go vet ./...`. Linux amd64/arm64 builds can
be produced with `CGO_ENABLED=0 GOOS=linux GOARCH=... go build ./cmd/secsvc`.
Container smoke tests also passed on Debian 12, Ubuntu 24.04, Rocky 9.8, and
Alpine 3.20.10 using the locally cached images. The Alpine root filesystem image
was ARM64 while the static test executable and Docker host were AMD64; this tests
Alpine's files/interfaces, not a native ARM64 execution environment. Each container
correctly reported degraded coverage for missing host interfaces/files.

Run `scripts/test-distros.sh debian ubuntu rocky alpine` to repeat those tests.
With no arguments the script also includes Red Hat UBI and Arch; it uses
`--pull=never`, so provision those images first. Containers have no network,
read-only roots, a temporary `/tmp`, and only the test executable mounted read-only.
Red Hat and Arch currently have fixture coverage, not container validation here.
Service-manager integration and real distro/kernel combinations still need native
host testing; container tests and cross-compilation are not that validation.

## References

- [os-release format](https://freedesktop.org/software/systemd/man/latest/os-release.html)
- [Kernel sysctl documentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [OpenSSH server configuration](https://man.openbsd.org/sshd_config)
- [AppArmor kernel documentation](https://docs.kernel.org/admin-guide/LSM/apparmor.html)
