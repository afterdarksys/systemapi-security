# Service templates

These are installable templates; no service is installed or enabled by this
repository change. Build `secsvc` for the target Linux architecture and install it
as `/usr/local/bin/secsvc`. Provision `/etc/secsvc/pub.hex` using the existing key
workflow. Set a host name matching signed grants before starting the service:
`SECSVC_HOST` in `service.env` or `secsvc_host` in `conf.d/secsvc`. Neither has
a default; `secsvc serve` refuses an empty host, a loopback name such as `localhost`, or an IP literal with `host_unset`.
The daemon does not need the signing seed.

## systemd: Debian, Ubuntu, Red Hat, Rocky, Arch

Install `systemd/secsvc.service` at `/etc/systemd/system/secsvc.service` and a
completed `systemd/service.env.example` at `/etc/secsvc/service.env` (root owned,
mode 0600). Then run `systemctl daemon-reload` and `systemctl enable --now secsvc`.
State/runtime directories are created by systemd. The template runs as root to
inspect local account and security state, restricts writes to daemon state, and
keeps host network and PID 1 views. Custom integrity watches requiring writes are
not part of this service. If narrowing privileges, verify per-check coverage.

## OpenRC: Alpine

Install `openrc/secsvc` at `/etc/init.d/secsvc` with mode 0755 and a completed
`openrc/secsvc.confd` at `/etc/conf.d/secsvc` (root owned, mode 0600). Run
`rc-update add secsvc default` and `rc-service secsvc start`. The foreground
process is managed by `supervise-daemon`; required directories are created by
`checkpath`. OpenRC variants can use this template on other supported distros.

## Configuration and verification

Start with modules off, then apply an example through the authenticated config
API; see `docs/modules.md`. Inspect `call report` and `call status` after the
first scan. Containers, missing optional tools/files, MAC policy, and supervisor
sandboxing can reduce coverage; the report exposes that explicitly. These
service templates require native service-manager smoke testing before rollout.

The existing `units/secsvc.json` remains the sahinit template. Use the supervisor
appropriate to the target system; only one process should own a state directory
and socket.

Reference: [systemd execution settings](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
