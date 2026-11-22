// Package modules implements bounded, read-only Linux posture checks. A module
// is a distro profile, not executable configuration. No shell or network is used.
package modules

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/afterdarksys/systemapi-security/internal/ids"
)

// Config explicitly enables a profile and selects checks. Nil Checks means the
// profile defaults; an empty (non-nil) list enables no checks.
type Config struct {
	Enabled bool     `json:"enabled"`
	Checks  []string `json:"checks"`
}

type Profile struct {
	ID             string   `json:"id"`
	OSIDs          []string `json:"os_ids"`
	PackageManager string   `json:"package_manager"`
	MAC            string   `json:"mac"`
	DefaultChecks  []string `json:"default_checks"`
}

type Check struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

var profiles = []Profile{
	{"alpine", []string{"alpine"}, "apk", "", []string{"accounts", "permissions", "kernel", "ssh", "mounts"}},
	{"arch", []string{"arch"}, "pacman", "", []string{"accounts", "permissions", "kernel", "ssh", "mounts"}},
	{"debian", []string{"debian"}, "apt", "apparmor", []string{"accounts", "permissions", "kernel", "ssh", "mounts", "mac"}},
	{"redhat", []string{"rhel"}, "dnf", "selinux", []string{"accounts", "permissions", "kernel", "ssh", "mounts", "mac"}},
	{"rocky", []string{"rocky"}, "dnf", "selinux", []string{"accounts", "permissions", "kernel", "ssh", "mounts", "mac"}},
	{"ubuntu", []string{"ubuntu"}, "apt", "apparmor", []string{"accounts", "permissions", "kernel", "ssh", "mounts", "mac"}},
}

var checks = []Check{
	{"accounts", "Local UID-zero accounts, duplicate UIDs, and empty password fields"},
	{"kernel", "Live kernel and network hardening sysctls"},
	{"mac", "SELinux enforcement or AppArmor activation and loaded profile modes"},
	{"mounts", "nosuid and nodev on temporary and shared-memory mounts"},
	{"permissions", "Ownership and permissions of sensitive account and security files"},
	{"ssh", "Explicit risky global SSH directives; complex configuration is reported incomplete"},
}

func Catalog() ([]Profile, []Check) {
	p := append([]Profile{}, profiles...)
	for i := range p {
		p[i].OSIDs = append([]string{}, p[i].OSIDs...)
		p[i].DefaultChecks = append([]string{}, p[i].DefaultChecks...)
	}
	return p, append([]Check{}, checks...)
}

func profile(id string) (Profile, bool) {
	for _, p := range profiles {
		if p.ID == id {
			return p, true
		}
	}
	return Profile{}, false
}

func selected(p Profile, c Config) []string {
	if c.Checks == nil {
		return p.DefaultChecks
	}
	return c.Checks
}

func Validate(cfg map[string]Config) error {
	for name, c := range cfg {
		if _, ok := profile(name); !ok {
			return fmt.Errorf("unknown module")
		}
		seen := map[string]bool{}
		for _, id := range c.Checks {
			valid := false
			for _, check := range checks {
				if check.ID == id {
					valid = true
				}
			}
			if !valid || seen[id] {
				return fmt.Errorf("unknown or duplicate check")
			}
			seen[id] = true
		}
	}
	return nil
}

func CloneConfig(in map[string]Config) map[string]Config {
	out := make(map[string]Config, len(in))
	for k, v := range in {
		if v.Checks != nil {
			v.Checks = append([]string{}, v.Checks...)
		}
		out[k] = v
	}
	return out
}

// RequiredPaths includes fixed discovery paths and all paths a selected check
// may read. It is independent of current OS so activation cannot bypass grants.
func RequiredPaths(cfg map[string]Config) []string {
	set := map[string]bool{}
	for id, c := range cfg {
		if !c.Enabled {
			continue
		}
		p, ok := profile(id)
		if !ok {
			continue
		}
		set["/etc/os-release"] = true
		set["/usr/lib/os-release"] = true
		for _, check := range selected(p, c) {
			for _, path := range checkPaths(p, check) {
				set[path] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ChangeAllowed requires coverage even when two checks share the same paths.
func ChangeAllowed(old, next map[string]Config, covers func(string) bool) bool {
	for _, p := range profiles {
		a, b := old[p.ID], next[p.ID]
		ac, bc := selected(p, a), selected(p, b)
		aset, bset := map[string]bool{}, map[string]bool{}
		if a.Enabled {
			for _, c := range ac {
				aset[c] = true
			}
		}
		if b.Enabled {
			for _, c := range bc {
				bset[c] = true
			}
		}
		changed := a.Enabled != b.Enabled
		for _, c := range checks {
			if aset[c.ID] == bset[c.ID] {
				continue
			}
			changed = true
			for _, path := range checkPaths(p, c.ID) {
				if !covers(path) {
					return false
				}
			}
		}
		if changed && (!covers("/etc/os-release") || !covers("/usr/lib/os-release")) {
			return false
		}
	}
	return true
}

type Platform struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Profile string `json:"profile"`
	State   string `json:"state"`
	Reason  string `json:"reason"`
}

type Result struct {
	ID     string        `json:"id"`
	State  string        `json:"state"`
	Reason string        `json:"reason"`
	Checks []CheckResult `json:"checks"`
}

type CheckResult struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Reason string `json:"reason"`
}

type Snapshot struct {
	Platform Platform `json:"platform"`
	Modules  []Result `json:"modules"`
}

func CloneSnapshot(s Snapshot) Snapshot {
	s.Modules = append([]Result{}, s.Modules...)
	for i := range s.Modules {
		s.Modules[i].Checks = append([]CheckResult{}, s.Modules[i].Checks...)
	}
	return s
}

// Pending exposes configured coverage without probing files during report GETs.
func Pending(cfg map[string]Config) Snapshot {
	s := Snapshot{Platform: Platform{State: "pending", Reason: "not_scanned"}, Modules: []Result{}}
	for _, p := range profiles {
		c := cfg[p.ID]
		r := Result{ID: p.ID, State: "disabled", Reason: "flag_off", Checks: []CheckResult{}}
		if c.Enabled {
			r.State = "pending"
			r.Reason = "not_scanned"
			for _, id := range selected(p, c) {
				r.Checks = append(r.Checks, CheckResult{id, "pending", "not_scanned"})
			}
		}
		s.Modules = append(s.Modules, r)
	}
	return s
}

// Scan returns coverage separately from findings: ok means inspected, not safe.
func Scan(fs Reader, cfg map[string]Config) (Snapshot, []ids.Finding) {
	s := Pending(cfg)
	any := false
	for _, c := range cfg {
		any = any || c.Enabled
	}
	if !any {
		s.Platform = Platform{State: "disabled", Reason: "flag_off"}
		return s, nil
	}
	if fs == nil {
		fs = HostFS{}
	}
	s.Platform = detect(fs)
	var findings []ids.Finding
	for i := range s.Modules {
		r := &s.Modules[i]
		if r.State == "disabled" {
			continue
		}
		if s.Platform.State != "ok" {
			r.State = "degraded"
			r.Reason = s.Platform.Reason
		} else if r.ID != s.Platform.Profile {
			r.State = "not_applicable"
			r.Reason = "different_distro"
		} else {
			r.State = "ok"
			r.Reason = ""
		}
		p, _ := profile(r.ID)
		for j := range r.Checks {
			c := &r.Checks[j]
			if r.State != "ok" && r.State != "degraded" || s.Platform.State != "ok" {
				c.State = r.State
				c.Reason = r.Reason
				continue
			}
			fsFind, err := runCheck(fs, p, c.ID)
			c.State = "ok"
			c.Reason = ""
			if err != nil {
				c.State = "degraded"
				c.Reason = reason(err)
				r.State = "degraded"
				r.Reason = "incomplete"
			}
			for _, f := range fsFind {
				f.Kind = "system." + r.ID + "." + c.ID + "." + f.Kind
				findings = append(findings, f)
			}
		}
	}
	return s, findings
}

// Disposition prevents failed probes from resolving old findings. Explicitly
// disabling a check withdraws its findings; only a complete check resolves them.
func Disposition(kind string, cfg map[string]Config, snap Snapshot) string {
	parts := strings.Split(kind, ".")
	if len(parts) != 4 || parts[0] != "system" {
		return "resolve"
	}
	p, ok := profile(parts[1])
	if !ok {
		return "retain"
	}
	c := cfg[p.ID]
	enabled := false
	if c.Enabled {
		for _, id := range selected(p, c) {
			enabled = enabled || id == parts[2]
		}
	}
	if !enabled {
		return "withdraw"
	}
	for _, r := range snap.Modules {
		if r.ID == p.ID {
			for _, check := range r.Checks {
				if check.ID == parts[2] && check.State == "ok" {
					return "resolve"
				}
			}
		}
	}
	return "retain"
}

var errMalformed = errors.New("malformed")
var errUnsupported = errors.New("unsupported")
var errIncomplete = errors.New("incomplete")
var errOversized = errors.New("oversized")

func reason(err error) string {
	switch {
	case errors.Is(err, errMalformed):
		return "malformed"
	case errors.Is(err, errUnsupported):
		return "unsupported"
	case errors.Is(err, errIncomplete):
		return "incomplete"
	case errors.Is(err, errOversized):
		return "oversized"
	default:
		return fileReason(err)
	}
}
