package modules

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/afterdarksys/systemapi-security/internal/ids"
	"golang.org/x/sys/unix"
)

type fixture struct {
	files    map[string]string
	meta     map[string]Metadata
	failures map[string]error
	goos     string
	reads    int
}

func (f *fixture) ReadFile(p string) ([]byte, error) {
	f.reads++
	if err := f.failures[p]; err != nil {
		return nil, err
	}
	b, ok := f.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(b), nil
}
func (f *fixture) Metadata(p string) (Metadata, error) {
	f.reads++
	m, ok := f.meta[p]
	if !ok {
		return Metadata{}, fs.ErrNotExist
	}
	return m, nil
}
func (f *fixture) OS() string { return f.goos }
func healthy(id string) *fixture {
	f := &fixture{files: map[string]string{}, meta: map[string]Metadata{}, failures: map[string]error{}, goos: "linux"}
	f.files["/etc/os-release"] = "ID=" + id + "\nVERSION_ID=\"12.1\"\n"
	f.files["/etc/passwd"] = "root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000::/home/user:/bin/sh\n"
	f.files["/etc/shadow"] = "root:!:1:0:99999:7:::\nuser:$6$DO_NOT_LEAK:1:0:99999:7:::\n"
	f.files["/etc/ssh/sshd_config"] = "PermitRootLogin no\nPasswordAuthentication no\n"
	f.files["/sys/fs/selinux/enforce"] = "1\n"
	f.files["/sys/module/apparmor/parameters/enabled"] = "Y\n"
	f.files["/sys/kernel/security/apparmor/profiles"] = "/usr/sbin/example (enforce)\n"
	f.files["/proc/1/mountinfo"] = "1 0 0:1 / /tmp rw,nosuid,nodev - tmpfs tmpfs rw\n2 0 0:2 / /var/tmp rw,nosuid,nodev - tmpfs tmpfs rw\n3 0 0:3 / /dev/shm rw,nosuid,nodev - tmpfs tmpfs rw\n"
	for _, r := range permissions {
		f.meta[r.path] = Metadata{Mode: 0600, UID: 0}
	}
	for _, r := range sysctls {
		f.files[r.path] = "0"
		if r.min == 1 {
			f.files[r.path] = "1"
		}
		if r.min == 2 {
			f.files[r.path] = "2"
		}
	}
	return f
}

func TestProfilesAndSelection(t *testing.T) {
	for _, p := range profiles {
		t.Run(p.ID, func(t *testing.T) {
			f := healthy(p.OSIDs[0])
			cfg := map[string]Config{}
			for _, other := range profiles {
				cfg[other.ID] = Config{Enabled: true}
			}
			s, found := Scan(f, cfg)
			if s.Platform.Profile != p.ID || len(found) != 0 {
				t.Fatalf("%+v %+v", s, found)
			}
			for _, r := range s.Modules {
				want := "not_applicable"
				if r.ID == p.ID {
					want = "ok"
				}
				if r.State != want {
					t.Fatalf("%+v", r)
				}
			}
		})
	}
}

func TestDisabledDoesNoIOAndEmptyChecksStayEmpty(t *testing.T) {
	f := healthy("ubuntu")
	_, found := Scan(f, nil)
	if f.reads != 0 || len(found) != 0 {
		t.Fatal("disabled module read files")
	}
	cfg := map[string]Config{"ubuntu": {Enabled: true, Checks: []string{}}}
	b, _ := json.Marshal(cfg)
	var round map[string]Config
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	s, _ := Scan(f, round)
	if f.reads != 1 || len(s.Modules[5].Checks) != 0 {
		t.Fatal("empty checks became defaults")
	}
}

func TestUnknownConfigAndDefensiveCopies(t *testing.T) {
	for _, cfg := range []map[string]Config{{"centos": {Enabled: true}}, {"arch": {Checks: []string{"shell"}}}, {"arch": {Checks: []string{"accounts", "accounts"}}}} {
		if Validate(cfg) == nil {
			t.Fatal("accepted invalid config")
		}
	}
	cfg := map[string]Config{"debian": {Enabled: true, Checks: []string{"accounts"}}}
	clone := CloneConfig(cfg)
	clone["debian"].Checks[0] = "ssh"
	if cfg["debian"].Checks[0] != "accounts" {
		t.Fatal("aliased config")
	}
	p, _ := Catalog()
	p[0].DefaultChecks[0] = "mutated"
	if profiles[0].DefaultChecks[0] == "mutated" {
		t.Fatal("aliased registry")
	}
}

func TestActivationAndRemovalRequirePathCoverage(t *testing.T) {
	cfg := map[string]Config{"debian": {Enabled: true, Checks: []string{"accounts"}}}
	paths := RequiredPaths(cfg)
	if len(paths) != 4 {
		t.Fatal(paths)
	}
	for _, blocked := range paths {
		covers := func(p string) bool { return p != blocked }
		if ChangeAllowed(nil, cfg, covers) || ChangeAllowed(cfg, nil, covers) {
			t.Fatalf("did not require %s", blocked)
		}
	}
	if !ChangeAllowed(cfg, cfg, func(string) bool { return false }) {
		t.Fatal("unchanged config requires paths")
	}
}

func TestPlatformFailureIsNeverClean(t *testing.T) {
	for _, tc := range []struct{ name, os, release, reason string }{{"mac", "darwin", "ID=ubuntu", "unsupported_os"}, {"unknown", "linux", "ID=fedora", "unsupported_distro"}, {"malformed", "linux", "ID=$(evil)", "malformed"}, {"duplicate", "linux", "ID=ubuntu\nID=debian", "malformed"}} {
		t.Run(tc.name, func(t *testing.T) {
			f := healthy("ubuntu")
			f.goos = tc.os
			f.files["/etc/os-release"] = tc.release
			s, _ := Scan(f, map[string]Config{"ubuntu": {Enabled: true}})
			if s.Platform.Reason != tc.reason || s.Modules[5].State != "degraded" {
				t.Fatalf("%+v", s)
			}
		})
	}
}

func TestAccountDetectionAndRedaction(t *testing.T) {
	f := healthy("debian")
	f.files["/etc/passwd"] += "backdoor::0:0::/root:/bin/sh\n"
	f.files["/etc/shadow"] += "backdoor::1:0:99999:7:::\n"
	found, err := accounts(f)
	if err != nil || len(found) != 4 {
		t.Fatalf("%+v %v", found, err)
	}
	b, _ := json.Marshal(found)
	for _, secret := range []string{"backdoor", "DO_NOT_LEAK", "$6$"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("account secret leaked")
		}
	}
	f.files["/etc/passwd"] = "broken"
	_, err = accounts(f)
	if !errors.Is(err, errMalformed) {
		t.Fatal(err)
	}
}

func TestPermissionsAndKernel(t *testing.T) {
	f := healthy("ubuntu")
	f.meta["/etc/shadow"] = Metadata{Mode: 0640, UID: 0}
	if found, err := filePermissions(f, mustProfile(t, "ubuntu")); err != nil || len(found) != 0 {
		t.Fatalf("valid shadow group read: %+v %v", found, err)
	}
	f.meta["/etc/shadow"] = Metadata{Mode: 0666, UID: 1000}
	found, err := filePermissions(f, mustProfile(t, "ubuntu"))
	if err != nil || len(found) != 2 {
		t.Fatalf("%+v %v", found, err)
	}
	f.files[sysctls[0].path] = "0"
	delete(f.files, sysctls[1].path)
	found, err = kernel(f)
	if err == nil || len(found) != 1 {
		t.Fatalf("partial kernel check: %+v %v", found, err)
	}
}

func TestSSHFirstValueAndIncompleteCoverage(t *testing.T) {
	f := healthy("ubuntu")
	f.files["/etc/ssh/sshd_config"] = "PermitRootLogin no\nPermitRootLogin yes\nPasswordAuthentication yes\nInclude /etc/ssh/sshd_config.d/*.conf\nMatch User root\nPermitEmptyPasswords yes\n"
	found, err := ssh(f)
	if !errors.Is(err, errIncomplete) || len(found) != 1 || found[0].Kind != "passwordauthentication" {
		t.Fatalf("%+v %v", found, err)
	}
}

func TestMACAndMounts(t *testing.T) {
	f := healthy("rocky")
	p, _ := profile("rocky")
	f.files["/sys/fs/selinux/enforce"] = "0"
	found, err := mac(f, p)
	if err != nil || len(found) != 1 || found[0].Severity != ids.SevHigh {
		t.Fatalf("%+v %v", found, err)
	}
	p, _ = profile("ubuntu")
	f.files["/sys/kernel/security/apparmor/profiles"] = "example (complain)\n"
	found, err = mac(f, p)
	if err != nil || len(found) != 2 {
		t.Fatalf("%+v %v", found, err)
	}
	f.files["/proc/1/mountinfo"] = "1 0 0:1 / /tmp rw - tmpfs tmpfs rw\n"
	found, err = mounts(f)
	if err != nil || len(found) != 4 {
		t.Fatalf("%+v %v", found, err)
	}
}

func TestRetentionAndWithdrawal(t *testing.T) {
	cfg := map[string]Config{"ubuntu": {Enabled: true, Checks: []string{"accounts"}}}
	f := healthy("ubuntu")
	s, _ := Scan(f, cfg)
	kind := "system.ubuntu.accounts.extra_uid_zero"
	if Disposition(kind, cfg, s) != "resolve" {
		t.Fatal("healthy check cannot resolve")
	}
	f.failures["/etc/shadow"] = fs.ErrPermission
	s, _ = Scan(f, cfg)
	if Disposition(kind, cfg, s) != "retain" {
		t.Fatal("failed check resolved finding")
	}
	if Disposition(kind, nil, s) != "withdraw" {
		t.Fatal("disabled check did not withdraw")
	}
}

func TestHostReaderBoundedAndNoFollow(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "file")
	if err := os.WriteFile(regular, []byte("value"), 0600); err != nil {
		t.Fatal(err)
	}
	h := HostFS{}
	b, err := h.ReadFile(regular)
	if err != nil || string(b) != "value" {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReadFile(link); err == nil {
		t.Fatal("followed symlink")
	}
	if _, err := h.Metadata(link); err == nil {
		t.Fatal("followed metadata symlink")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReadFile(fifo); err == nil {
		t.Fatal("opened fifo")
	}
	if err := os.WriteFile(regular, []byte(strings.Repeat("x", ReadLimit+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReadFile(regular); !errors.Is(err, errOversized) {
		t.Fatal(err)
	}
}

func TestStableRequiredPaths(t *testing.T) {
	cfg := map[string]Config{"ubuntu": {Enabled: true}, "rocky": {Enabled: true}}
	a, b := RequiredPaths(cfg), RequiredPaths(cfg)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("unstable manifest")
	}
}

func mustProfile(t *testing.T, id string) Profile {
	t.Helper()
	p, ok := profile(id)
	if !ok {
		t.Fatal(id)
	}
	return p
}

func TestShadowGroup(t *testing.T) {
	groups := "root:x:0:\nshadow:x:42:\nusers:x:100:\n"
	cases := []struct {
		profile string
		group   string
		gid     uint32
		finding bool
		partial bool
	}{
		{"ubuntu", groups, 0, false, false},
		{"debian", groups, 42, false, false},
		{"alpine", groups, 42, false, false},
		{"debian", groups, 100, true, false},
		{"rocky", groups, 42, true, false},
		{"arch", groups, 42, true, false},
		{"debian", "root:x:0:\n", 42, true, false},
		{"debian", "", 42, false, true},
		{"debian", "shadow:x:nope:\n", 42, false, true},
	}
	for _, tc := range cases {
		f := healthy(tc.profile)
		f.meta["/etc/shadow"] = Metadata{Mode: 0640, UID: 0, GID: tc.gid}
		if tc.group != "" {
			f.files["/etc/group"] = tc.group
		}
		found, err := filePermissions(f, mustProfile(t, tc.profile))
		groupFindings := 0
		for _, x := range found {
			if x.Kind == "group" && x.Subject == "/etc/shadow" {
				groupFindings++
			}
		}
		if (groupFindings == 1) != tc.finding || (err != nil) != tc.partial || len(found) != groupFindings {
			t.Errorf("%s gid %d group %q: %+v %v", tc.profile, tc.gid, tc.group, found, err)
		}
	}
}
