// Package caps is the read-only capability report.
//
// Threats: a detector that can no longer run being described as healthy, and
// a report carrying a path, a contact, an address, or an error string. Each
// probe returns a name from the registry, a state of ok, degraded, or absent,
// and a reason from a closed set. ok has an empty reason. Anything else is
// rewritten to probe_error or dropped. A result is advisory: it detects
// breakage, not compromise, and it never grants. Leases still decide every
// mutating call. Status never claims coverage it lacks: integrity is ok only
// when every watched path exists and is baselined, and grant_v1 is ok only
// when a public key is loaded.
package caps

import (
	"errors"
	"regexp"
	"sort"
)

const (
	StateOK       = "ok"
	StateDegraded = "degraded"
	StateAbsent   = "absent"

	ReasonFlagOff       = "flag_off"
	ReasonUnreadable    = "unreadable"
	ReasonTargetMissing = "target_missing"
	ReasonAuditBad      = "audit_bad"
	ReasonUnsupportedOS = "unsupported_os"
	ReasonBadContact    = "bad_contact"
	ReasonProbeError    = "probe_error"
	ReasonUnbaselined   = "unbaselined"
	ReasonNoKey         = "no_key"

	// maxTokens matches the systemapi capability header bound.
	maxTokens = 16
)

// ErrOff means the detector is not configured.
// ErrMissing means a configured target is absent.
// ErrUnbaselined means a watched path has no baseline record.
// ErrNoKey means no grant public key is loaded.
// ErrUnreadable means a target cannot be read as a regular file.
// ErrUnsupported means this host has no such probe surface.
// ErrAudit means the hash chain does not verify.
// ErrContact means a stored contact does not parse.
// ErrProbe is any other failure. Error text is never a report field.
var (
	ErrOff         = errors.New("off")
	ErrMissing     = errors.New("missing")
	ErrUnreadable  = errors.New("unreadable")
	ErrUnsupported = errors.New("unsupported")
	ErrAudit       = errors.New("audit")
	ErrContact     = errors.New("contact")
	ErrProbe       = errors.New("probe")
	ErrUnbaselined = errors.New("unbaselined")
	ErrNoKey       = errors.New("no_key")
)

// Check is one probe. A nil Check means the detector is off.
type Check func() error

// Env is the host view a probe is allowed to see. The functions return a
// sentinel. Their error text is discarded.
type Env struct {
	Audit     Check
	Grant     Check
	Auth      Check
	Integrity Check
	Listen    Check
	Notify    Check
}

// Result is one capability. Reason is empty exactly when State is ok.
type Result struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Reason string `json:"reason"`
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,15}$`)

var reasons = map[string]struct{}{
	ReasonFlagOff:       {},
	ReasonUnreadable:    {},
	ReasonTargetMissing: {},
	ReasonAuditBad:      {},
	ReasonUnsupportedOS: {},
	ReasonBadContact:    {},
	ReasonProbeError:    {},
	ReasonUnbaselined:   {},
	ReasonNoKey:         {},
}

var registry = map[string]func(Env) Result{
	"audit":     probeAudit,
	"auth":      func(e Env) Result { return fromCheck("auth", e.Auth) },
	"grant_v1":  probeGrant,
	"integrity": func(e Env) Result { return fromCheck("integrity", e.Integrity) },
	"listen":    func(e Env) Result { return fromCheck("listen", e.Listen) },
	"notify":    func(e Env) Result { return fromCheck("notify", e.Notify) },
}

// Probe runs every registered probe and returns the bounded report, sorted
// by name.
func Probe(env Env) []Result {
	out := make([]Result, 0, len(registry))
	for name, probe := range registry {
		r := probe(env)
		r.Name = name
		out = append(out, r)
	}
	return bound(out)
}

func probeAudit(e Env) Result {
	if e.Audit == nil {
		return degraded("audit", ReasonProbeError)
	}
	return mapErr("audit", e.Audit())
}

// probeGrant reports whether the daemon holds a key to verify grants with.
// A nil check means none is loaded.
func probeGrant(e Env) Result {
	if e.Grant == nil {
		return absent("grant_v1", ReasonNoKey)
	}
	return mapErr("grant_v1", e.Grant())
}

func fromCheck(name string, c Check) Result {
	if c == nil {
		return absent(name, ReasonFlagOff)
	}
	return mapErr(name, c())
}

func mapErr(name string, err error) Result {
	switch {
	case err == nil:
		return ok(name)
	case errors.Is(err, ErrOff):
		return absent(name, ReasonFlagOff)
	case errors.Is(err, ErrMissing):
		return degraded(name, ReasonTargetMissing)
	case errors.Is(err, ErrUnreadable):
		return degraded(name, ReasonUnreadable)
	case errors.Is(err, ErrUnsupported):
		return absent(name, ReasonUnsupportedOS)
	case errors.Is(err, ErrAudit):
		return degraded(name, ReasonAuditBad)
	case errors.Is(err, ErrContact):
		return degraded(name, ReasonBadContact)
	case errors.Is(err, ErrUnbaselined):
		return degraded(name, ReasonUnbaselined)
	case errors.Is(err, ErrNoKey):
		return absent(name, ReasonNoKey)
	default:
		return degraded(name, ReasonProbeError)
	}
}

func ok(name string) Result { return Result{Name: name, State: StateOK} }

func degraded(name, reason string) Result {
	return Result{Name: name, State: StateDegraded, Reason: reason}
}

func absent(name, reason string) Result {
	return Result{Name: name, State: StateAbsent, Reason: reason}
}

// bound is the last gate before a report leaves the process.
func bound(in []Result) []Result {
	out := make([]Result, 0, len(in))
	for _, r := range in {
		if _, known := registry[r.Name]; !known || !nameRE.MatchString(r.Name) {
			continue
		}
		switch r.State {
		case StateOK:
			r.Reason = ""
		case StateDegraded, StateAbsent:
			if _, ok := reasons[r.Reason]; !ok {
				r.Reason = ReasonProbeError
			}
		default:
			r.State = StateDegraded
			r.Reason = ReasonProbeError
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) > maxTokens {
		out = out[:maxTokens]
	}
	return out
}
