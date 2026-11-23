# security: a future sash verb

This file is the contract for a later sash builtin. The sash table in `skills/sash/reference/verbs.md` does not contain these names, and this repository does not edit that table. Fulfillment, when it exists, is one `secsvc call` against the host Unix socket. The grant on that call is `secsvc/2` from `docs/architecture.md`. A `sash/1` lease does not authorize the socket.

Columns match the sash verb table. **key** is the `secsvc/2` entitlement. **mutates** is `yes` when the call spends a lease.

| form | kind | key | mutates | what |
| --- | --- | --- | --- | --- |
| `security status` | verb | `security.read` | no | `GET /v1/status`, including `caps`. |
| `security config` | verb | `security.read` | no | `GET /v1/config`. The body has `contact_sha256`, never the contact URL. |
| `security findings` | verb | `security.read` | no | `GET /v1/findings`. |
| `security audit` | verb | `security.audit` | no | `GET /v1/audit`. |
| `security verify` | verb | `security.audit` | no | `GET /v1/audit/verify`. |
| `security scan` | verb | `security.scan` | yes | `POST /v1/scan` with an empty body. |
| `security baseline` | verb | `security.baseline` | yes | `POST /v1/baseline` with an empty body. |
| `security config set` | verb | `security.config` | yes | `PUT /v1/config`, a full replace. Paths added or removed must sit under the grant `watch` list. `listen_allow` and the auth thresholds need coverage of what they govern (`config_scope` otherwise; see `docs/architecture.md`). |
| `security contact` | verb | `security.notify` | yes | `PUT /v1/contact`. The contact file is mode `0600` and uses the `push:ntfy:https://ntfy.sh/<topic>` form. |

`security catalog` is the same key as `security status` (`GET /v1/catalog`) and is optional in the first sash cut. `caps` on `security status` is a name, a state (`ok`, `degraded`, `absent`), and a closed reason. The list does not grant.

A star entitlement, a watch of `/`, a TTL over 15 minutes, and a host other than the daemon `--host` stay refusals. The agent re-checks the key. Plan mode stops the four mutating forms. Confirm asks before them.

Until that builtin exists, the operator runs `secsvc call` directly. See the README.
