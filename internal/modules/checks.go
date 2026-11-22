package modules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/afterdarksys/systemapi-security/internal/ids"
)

type sysctlRule struct {
	path        string
	min, max    int
	description string
}

var sysctls = []sysctlRule{
	{"/proc/sys/kernel/randomize_va_space", 2, 2, "Full address-space randomization is not enabled"},
	{"/proc/sys/kernel/kptr_restrict", 1, 2, "Kernel pointer disclosure is not restricted"},
	{"/proc/sys/kernel/dmesg_restrict", 1, 1, "Kernel log access is not restricted"},
	{"/proc/sys/fs/protected_hardlinks", 1, 1, "Hardlink protection is disabled"},
	{"/proc/sys/fs/protected_symlinks", 1, 1, "Symlink protection is disabled"},
	{"/proc/sys/net/ipv4/conf/all/accept_redirects", 0, 0, "IPv4 ICMP redirects are accepted"},
	{"/proc/sys/net/ipv4/conf/default/accept_redirects", 0, 0, "New IPv4 interfaces accept ICMP redirects"},
	{"/proc/sys/net/ipv4/conf/all/send_redirects", 0, 0, "IPv4 ICMP redirect sending is enabled"},
	{"/proc/sys/net/ipv4/conf/default/send_redirects", 0, 0, "New IPv4 interfaces can send ICMP redirects"},
	{"/proc/sys/net/ipv4/conf/all/accept_source_route", 0, 0, "IPv4 source routing is enabled"},
	{"/proc/sys/net/ipv4/conf/default/accept_source_route", 0, 0, "New IPv4 interfaces accept source routing"},
	{"/proc/sys/net/ipv4/tcp_syncookies", 1, 2, "TCP SYN cookie protection is disabled"},
}

type permissionRule struct {
	path      string
	forbidden uint32
}

// Shadow group-read is intentional on Debian/Ubuntu; group-write never is.
var permissions = []permissionRule{
	{"/etc/passwd", 0022}, {"/etc/group", 0022},
	{"/etc/shadow", 0037}, {"/etc/gshadow", 0037},
	{"/etc/sudoers", 0027}, {"/etc/ssh/sshd_config", 0022},
}

func checkPaths(p Profile, id string) []string {
	switch id {
	case "accounts":
		return []string{"/etc/passwd", "/etc/shadow"}
	case "permissions":
		out := []string{}
		for _, r := range permissions {
			out = append(out, r.path)
		}
		return out
	case "kernel":
		out := []string{}
		for _, r := range sysctls {
			out = append(out, r.path)
		}
		return out
	case "ssh":
		return []string{"/etc/ssh/sshd_config"}
	case "mounts":
		return []string{"/proc/1/mountinfo"}
	case "mac":
		switch p.MAC {
		case "selinux":
			return []string{"/sys/fs/selinux/enforce"}
		case "apparmor":
			return []string{"/sys/module/apparmor/parameters/enabled", "/sys/kernel/security/apparmor/profiles"}
		}
	}
	return nil
}

func runCheck(f Reader, p Profile, id string) ([]ids.Finding, error) {
	switch id {
	case "accounts":
		return accounts(f)
	case "permissions":
		return filePermissions(f)
	case "kernel":
		return kernel(f)
	case "ssh":
		return ssh(f)
	case "mounts":
		return mounts(f)
	case "mac":
		return mac(f, p)
	}
	return nil, errUnsupported
}

func finding(kind, severity, subject, summary string) ids.Finding {
	return ids.Finding{Kind: kind, Severity: severity, Subject: subject, Summary: summary}
}

// Checks aggregate account violations without exposing usernames or hashes.
func accounts(f Reader) ([]ids.Finding, error) {
	var found []ids.Finding
	var incomplete error
	b, err := f.ReadFile("/etc/passwd")
	if err != nil {
		incomplete = err
	} else {
		uid0, empty, duplicates := 0, 0, 0
		uids := map[uint64]bool{}
		names := map[string]bool{}
		rows := 0
		for _, line := range strings.Split(string(b), "\n") {
			if line == "" {
				continue
			}
			parts := strings.Split(line, ":")
			if len(parts) != 7 || parts[0] == "" {
				incomplete = errMalformed
				continue
			}
			uid, e := strconv.ParseUint(parts[2], 10, 32)
			_, ge := strconv.ParseUint(parts[3], 10, 32)
			if e != nil || ge != nil || names[parts[0]] {
				incomplete = errMalformed
				continue
			}
			names[parts[0]] = true
			rows++
			if uid == 0 && parts[0] != "root" {
				uid0++
			}
			if uids[uid] {
				duplicates++
			}
			uids[uid] = true
			if parts[1] == "" {
				empty++
			}
		}
		if rows == 0 {
			incomplete = errMalformed
		}
		if uid0 > 0 {
			found = append(found, finding("extra_uid_zero", ids.SevHigh, "/etc/passwd", fmt.Sprintf("%d non-root account(s) have UID zero", uid0)))
		}
		if duplicates > 0 {
			found = append(found, finding("duplicate_uid", ids.SevMedium, "/etc/passwd", fmt.Sprintf("%d duplicate UID assignment(s)", duplicates)))
		}
		if empty > 0 {
			found = append(found, finding("empty_password", ids.SevHigh, "/etc/passwd", fmt.Sprintf("%d account(s) have empty password fields", empty)))
		}
	}
	b, err = f.ReadFile("/etc/shadow")
	if err != nil {
		incomplete = err
	} else {
		empty, rows := 0, 0
		names := map[string]bool{}
		for _, line := range strings.Split(string(b), "\n") {
			if line == "" {
				continue
			}
			parts := strings.Split(line, ":")
			if len(parts) != 9 || parts[0] == "" || names[parts[0]] {
				incomplete = errMalformed
				continue
			}
			names[parts[0]] = true
			rows++
			if parts[1] == "" {
				empty++
			}
		}
		if rows == 0 {
			incomplete = errMalformed
		}
		if empty > 0 {
			found = append(found, finding("empty_password", ids.SevHigh, "/etc/shadow", fmt.Sprintf("%d account(s) have empty password fields", empty)))
		}
	}
	return found, incomplete
}

func filePermissions(f Reader) ([]ids.Finding, error) {
	var found []ids.Finding
	var incomplete error
	for _, r := range permissions {
		m, err := f.Metadata(r.path)
		if err != nil {
			incomplete = err
			continue
		}
		if m.UID != 0 {
			found = append(found, finding("owner", ids.SevHigh, r.path, "Sensitive configuration is not owned by root"))
		}
		if uint32(m.Mode.Perm())&r.forbidden != 0 {
			found = append(found, finding("mode", ids.SevHigh, r.path, "Sensitive configuration has excessive write or disclosure permissions"))
		}
	}
	return found, incomplete
}

func kernel(f Reader) ([]ids.Finding, error) {
	var found []ids.Finding
	var incomplete error
	for _, r := range sysctls {
		b, err := f.ReadFile(r.path)
		if err != nil {
			incomplete = err
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || n < 0 {
			incomplete = errMalformed
			continue
		}
		if n < r.min || n > r.max {
			found = append(found, finding("hardening", ids.SevMedium, r.path, r.description))
		}
	}
	return found, incomplete
}

// ssh audits explicit global settings only. Include/Match, quoting, and
// continuation need sshd's evaluator; report incomplete rather than inventing
// effective defaults or silently treating another file as secure.
func ssh(f Reader) ([]ids.Finding, error) {
	b, err := f.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return nil, err
	}
	first := map[string]string{}
	var incomplete error
	inMatch := false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			incomplete = errMalformed
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "include" {
			incomplete = errIncomplete
			continue
		}
		if key == "match" {
			inMatch = true
			incomplete = errIncomplete
			continue
		}
		if inMatch {
			continue
		}
		if strings.ContainsAny(line, "\"'\\=") {
			incomplete = errIncomplete
			continue
		}
		if _, ok := first[key]; !ok {
			first[key] = strings.ToLower(fields[1])
		}
	}
	var found []ids.Finding
	rules := []struct{ key, value, sev, summary string }{
		{"permitrootlogin", "yes", ids.SevHigh, "Global SSH configuration explicitly permits root password login"},
		{"permitemptypasswords", "yes", ids.SevHigh, "Global SSH configuration explicitly permits empty passwords"},
		{"passwordauthentication", "yes", ids.SevMedium, "Global SSH configuration explicitly enables password authentication"},
		{"hostbasedauthentication", "yes", ids.SevMedium, "Global SSH configuration explicitly enables host-based authentication"},
		{"ignorerhosts", "no", ids.SevHigh, "Global SSH configuration explicitly permits rhosts trust files"},
		{"strictmodes", "no", ids.SevHigh, "Global SSH configuration disables ownership and mode checks"},
	}
	for _, r := range rules {
		if first[r.key] == r.value {
			found = append(found, finding(r.key, r.sev, "/etc/ssh/sshd_config", r.summary))
		}
	}
	return found, incomplete
}

func mac(f Reader, p Profile) ([]ids.Finding, error) {
	switch p.MAC {
	case "selinux":
		b, err := f.ReadFile("/sys/fs/selinux/enforce")
		if err != nil {
			return nil, err
		}
		switch strings.TrimSpace(string(b)) {
		case "1":
			return nil, nil
		case "0":
			return []ids.Finding{finding("permissive", ids.SevHigh, "selinux", "SELinux is in permissive mode")}, nil
		default:
			return nil, errMalformed
		}
	case "apparmor":
		b, err := f.ReadFile("/sys/module/apparmor/parameters/enabled")
		if err != nil {
			return nil, err
		}
		state := strings.TrimSpace(string(b))
		if state == "N" {
			return []ids.Finding{finding("disabled", ids.SevHigh, "apparmor", "AppArmor is disabled")}, nil
		}
		if state != "Y" {
			return nil, errMalformed
		}
		b, err = f.ReadFile("/sys/kernel/security/apparmor/profiles")
		if err != nil {
			return nil, err
		}
		enforce, complain := 0, 0
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if line == "" {
				continue
			}
			if strings.HasSuffix(line, " (enforce)") {
				enforce++
			} else if strings.HasSuffix(line, " (complain)") {
				complain++
			} else {
				return nil, errIncomplete
			}
		}
		var found []ids.Finding
		if enforce == 0 {
			found = append(found, finding("no_enforcing_profiles", ids.SevMedium, "apparmor", "No enforcing AppArmor profiles are loaded"))
		}
		if complain > 0 {
			found = append(found, finding("complain_profiles", ids.SevMedium, "apparmor", fmt.Sprintf("%d AppArmor profile(s) are in complain mode", complain)))
		}
		return found, nil
	default:
		return nil, errUnsupported
	}
}

func mounts(f Reader) ([]ids.Finding, error) {
	b, err := f.ReadFile("/proc/1/mountinfo")
	if err != nil {
		return nil, err
	}
	// PID 1's namespace is the local view. A container's PID 1 is not the host.
	targets := map[string]bool{"/tmp": true, "/var/tmp": true, "/dev/shm": true}
	seen := map[string]bool{}
	var found []ids.Finding
	rows := 0
	var incomplete error
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		a, tail, ok := strings.Cut(line, " - ")
		fields := strings.Fields(a)
		if !ok || len(fields) < 6 || len(strings.Fields(tail)) < 3 {
			incomplete = errMalformed
			continue
		}
		rows++
		target := fields[4]
		if !targets[target] {
			continue
		}
		if seen[target] {
			incomplete = errIncomplete
			continue
		}
		seen[target] = true
		opts := "," + fields[5] + ","
		for _, option := range []string{"nosuid", "nodev"} {
			if !strings.Contains(opts, ","+option+",") {
				found = append(found, finding("mount_options", ids.SevMedium, target+":"+option, "Temporary mount lacks "+option))
			}
		}
	}
	if rows == 0 {
		incomplete = errMalformed
	}
	// Absent dedicated mounts are explicit posture findings, not guessed options
	// from an arbitrary parent mount or inaccessible namespace.
	for _, target := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		if !seen[target] {
			found = append(found, finding("shared_mount", ids.SevMedium, target, "No dedicated temporary mount was observed; review inherited mount protections"))
		}
	}
	return found, incomplete
}
