package store

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"github.com/afterdarksys/systemapi-security/internal/ids"
	"golang.org/x/sys/unix"
)

func TestOpenDefaults(t *testing.T) {
	s := openDir(t)
	c := s.Config()
	if c.AuthFailLimit != 5 || c.AuthWindowS != 300 || len(c.Watch) != 0 || len(c.ListenAllow) != 0 || c.AuthLog != "" {
		t.Fatalf("%+v", c)
	}
	c.Watch = append(c.Watch, "/tmp/x")
	if got := s.Config(); len(got.Watch) != 0 {
		t.Fatal("clone")
	}
	v, err := s.View()
	if err != nil || v.ContactState != "off" || v.ContactSHA256 != "" {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := s.Contact(); err != ErrNone {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing", "child"), nil); codes.Code(err) != codes.BadDir {
		t.Fatal(err)
	}
}

func TestConfigShape(t *testing.T) {
	c, err := DecodeConfig([]byte(`{}`))
	if err != nil || c.AuthFailLimit != 5 || c.AuthWindowS != 300 {
		t.Fatal(err, c)
	}
	if _, err := DecodeConfig([]byte(`{"auth_fail_limit":-1}`)); codes.Code(err) != codes.BadPath {
		t.Fatal(err)
	}
	if _, err := DecodeConfig([]byte(`{"contact_sha256":"ab"}`)); codes.Code(err) != codes.BadPath {
		t.Fatal(err)
	}
	if _, err := DecodeConfig([]byte("{}\n{}")); codes.Code(err) != codes.BadPath {
		t.Fatal(err)
	}
	c, err = DecodeConfig([]byte(`{"listen_allow":["127.0.0.1:22","[::1]:22"]}`))
	if err != nil || c.ListenAllow[0] != "127.0.0.1:22" || c.ListenAllow[1] != "[::1]:22" {
		t.Fatal(err, c.ListenAllow)
	}
	for _, bad := range []string{`{"listen_allow":["127.0.0.1:022"]}`, `{"listen_allow":["name:22"]}`, `{"listen_allow":["127.0.0.1:22","127.0.0.1:22"]}`, `{"watch":["/tmp","/tmp"]}`, `{"auth_log":"rel"}`, `{"watch":["/"]}`} {
		if _, err := DecodeConfig([]byte(bad)); codes.Code(err) != codes.BadPath {
			t.Fatalf("%s %v", bad, err)
		}
	}
}

func TestAllowChange(t *testing.T) {
	old := Config{AuthLog: "/var/log/a", Watch: []string{"/var/lib/keep", "/var/lib/drop"}, AuthFailLimit: 5, AuthWindowS: 300}
	covers := func(p string) bool {
		return p == "/var/log/a" || p == "/var/log/b" || p == "/var/lib/drop" || p == "/var/lib/add"
	}
	want := func(t *testing.T, err error, code string) {
		t.Helper()
		if codes.Code(err) != code {
			t.Fatalf("got %q want %q", codes.Code(err), code)
		}
	}
	neu := old
	neu.AuthFailLimit = 9
	want(t, AllowChange(old, neu, covers), "")
	neu = old
	neu.AuthLog = "/var/log/b"
	want(t, AllowChange(old, neu, covers), "")
	neu.AuthLog = "/var/log/nope"
	want(t, AllowChange(old, neu, covers), codes.Forbidden)
	neu = old
	neu.Watch = []string{"/var/lib/keep", "/var/lib/add"}
	want(t, AllowChange(old, neu, covers), "")
	neu.Watch = []string{"/var/lib/keep"}
	want(t, AllowChange(old, neu, func(string) bool { return false }), codes.Forbidden)
	neu.Watch = []string{"/var/lib/keep", "/var/lib/drop", "/etc/outside"}
	want(t, AllowChange(old, neu, covers), codes.Forbidden)
	want(t, AllowChange(old, old, func(string) bool { return false }), "")
}

func TestAllowChangeGlobalScope(t *testing.T) {
	old := Config{AuthLog: "/var/log/auth.log", Watch: []string{"/etc/passwd"}, AuthFailLimit: 5, AuthWindowS: 300, ListenAllow: []string{"127.0.0.1:22"}}
	narrow := func(p string) bool { return p == "/etc/passwd" }
	authOnly := func(p string) bool { return p == "/var/log/auth.log" }
	procNet := func(p string) bool { return p == "/proc/net/tcp" || p == "/proc/net/tcp6" }
	cases := []struct {
		name   string
		edit   func(c *Config)
		covers func(string) bool
		code   string
	}{
		{"listen by narrow grant", func(c *Config) { c.ListenAllow = []string{"0.0.0.0:22"} }, narrow, codes.ConfigScope},
		{"listen cleared by narrow grant", func(c *Config) { c.ListenAllow = nil }, narrow, codes.ConfigScope},
		{"listen with one table", func(c *Config) { c.ListenAllow = []string{"0.0.0.0:22"} }, func(p string) bool { return p == "/proc/net/tcp" }, codes.ConfigScope},
		{"listen by proc grant", func(c *Config) { c.ListenAllow = []string{"0.0.0.0:22"} }, procNet, ""},
		{"listen reorder only", func(c *Config) { c.ListenAllow = []string{"127.0.0.1:22"} }, narrow, ""},
		{"limit by narrow grant", func(c *Config) { c.AuthFailLimit = 1000 }, narrow, codes.ConfigScope},
		{"window by narrow grant", func(c *Config) { c.AuthWindowS = 1 }, narrow, codes.ConfigScope},
		{"limit by auth grant", func(c *Config) { c.AuthFailLimit = 1000 }, authOnly, ""},
		{"narrow watch add", func(c *Config) { c.Watch = []string{"/etc/passwd", "/etc/passwd-"} }, func(p string) bool { return strings.HasPrefix(p, "/etc/passwd") }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			neu := old
			neu.Watch = append([]string(nil), old.Watch...)
			neu.ListenAllow = append([]string(nil), old.ListenAllow...)
			tc.edit(&neu)
			if got := codes.Code(AllowChange(old, neu, tc.covers)); got != tc.code {
				t.Fatalf("got %q want %q", got, tc.code)
			}
		})
	}
	// With no auth log before or after, a threshold change governs nothing a
	// grant can cover, so it is refused rather than pre-set by anyone.
	bare := Config{AuthFailLimit: 5, AuthWindowS: 300}
	neu := bare
	neu.AuthFailLimit = 9
	if got := codes.Code(AllowChange(bare, neu, func(string) bool { return true })); got != codes.ConfigScope {
		t.Fatalf("bare threshold %q", got)
	}
}

func TestProbeAndSpend(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "auth")
	if err := os.WriteFile(file, []byte("ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if err := ProbePaths(Config{AuthLog: link}); codes.Code(err) != codes.BadPath {
		t.Fatal(err)
	}
	if _, err := os.Readlink(link); err != nil {
		t.Fatal("followed")
	}
	if err := ProbePaths(Config{AuthLog: filepath.Join(dir, "missing")}); err != nil {
		t.Fatal(err)
	}
	if err := ProbePaths(Config{Watch: []string{dir}}); codes.Code(err) != codes.BadPath {
		t.Fatal(err)
	}

	s := openDir(t)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	id := "leaseid01"
	if err := s.Spend(id, now.Unix()+60, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Spend(id, now.Unix()+60, now); codes.Code(err) != codes.GrantSpent {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.dir, "config.json")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(s.dir, "config.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.PutConfig(Config{}); codes.Code(err) != codes.Failed {
		t.Fatal(err)
	}
	if err := s.Spend(id, now.Unix()+60, now); codes.Code(err) != codes.GrantSpent {
		t.Fatal(err)
	}
	if err := s.Spend("", now.Unix()+60, now); codes.Code(err) != codes.GrantBadShape {
		t.Fatal(err)
	}
	if err := s.Spend("otherid1", now.Unix(), now); codes.Code(err) != codes.GrantExpired {
		t.Fatal(err)
	}
}

func TestSpendSurvivesSymlinkDest(t *testing.T) {
	s := openDir(t)
	now := time.Now()
	id := "leaseid02"
	if err := s.Spend(id, now.Unix()+60, now); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(s.dir, "config.json")
	if err := os.Remove(cfg); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(s.dir, "nope"), cfg); err != nil {
		t.Fatal(err)
	}
	if err := s.PutConfig(Config{}); codes.Code(err) != codes.Failed {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(cfg); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("replaced symlink", err)
	}
	if err := s.Spend(id, now.Unix()+60, now); codes.Code(err) != codes.GrantSpent {
		t.Fatal(err)
	}
}

func TestContactModeAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	raw := "push:ntfy:https://ntfy.sh/topic-topic-topic-topic"
	if err := os.WriteFile(filepath.Join(dir, "contact"), []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, func(string) error { return nil }); codes.Code(err) != codes.Failed {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "contact"))
	if err != nil || fi.Mode().Perm()&0o077 == 0 {
		t.Fatalf("mode hidden %v", fi)
	}
	if err := os.Chmod(filepath.Join(dir, "contact"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, func(got string) error {
		if got != raw {
			t.Fatal("echo")
		}
		return codes.E(codes.BadContact)
	}); codes.Code(err) != codes.BadContact {
		t.Fatal(err)
	}
	s, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.View()
	if err != nil || v.ContactState != "set" || v.ContactSHA256 == "" || strings.Contains(v.ContactSHA256, "topic-topic-topic-topic") {
		t.Fatalf("%+v %v", v, err)
	}
	got, err := s.Contact()
	if err != nil || got != raw {
		t.Fatal(got, err)
	}
	if err := os.Chmod(filepath.Join(dir, "contact"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.View(); codes.Code(err) != codes.Failed {
		t.Fatal(err)
	}
	if _, err := s.Contact(); codes.Code(err) != codes.Failed {
		t.Fatal(err)
	}

	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "config.json"), []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bad, nil); codes.Code(err) != codes.Failed {
		t.Fatal(err)
	}
	bad = t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "ids-state.json"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bad, nil); codes.Code(err) != codes.Failed {
		t.Fatal(err)
	}
	okd := t.TempDir()
	if err := os.WriteFile(filepath.Join(okd, "ids-state.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(okd, "config.json"), []byte(`{"auth_log":"`+okd+`"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(okd, nil); codes.Code(err) != codes.BadPath {
		t.Fatal(err)
	}
	linkDir := t.TempDir()
	if err := os.Symlink(filepath.Join(linkDir, "x"), filepath.Join(linkDir, "config.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(linkDir, nil); codes.Code(err) != codes.Failed {
		t.Fatal(err)
	}
	edge := t.TempDir()
	if err := os.WriteFile(filepath.Join(edge, "findings.jsonl"), []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(edge, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(edge, "findings.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(edge, "nope"), filepath.Join(edge, "findings.jsonl")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(edge, nil); codes.Code(err) != codes.Failed {
		t.Fatal(err)
	}
}

func TestPutBaselineAndPrune(t *testing.T) {
	s := openDir(t)
	if err := s.PutBaseline(nil); err != nil {
		t.Fatal(err)
	}
	if err := s.PutBaseline(map[string]ids.Record{"/": {SHA256: hexOK(), Size: 1}}); codes.Code(err) != codes.BadPath {
		t.Fatal(err)
	}
	rec := ids.Record{SHA256: hexOK(), Mode: 0o600, Size: 1}
	if err := s.PutBaseline(map[string]ids.Record{"/var/lib/a": rec}); err != nil {
		t.Fatal(err)
	}
	if s.Baseline()["/var/lib/a"] != rec {
		t.Fatal(s.Baseline())
	}
	past := time.Now().Add(-time.Hour).Unix()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "spent.json"), []byte(`{"leases":{"leaseid01":`+itoa(past)+`}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.Spend("leaseid01", now.Unix()+30, now); err != nil {
		t.Fatal(err)
	}
}

func TestDirSymlink(t *testing.T) {
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, nil); codes.Code(err) != codes.BadDir {
		t.Fatal(err)
	}
}

func openDir(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func hexOK() string {
	return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func TestBaselineVersions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	v1 := `{"/var/lib/a":{"sha256":"` + hexOK() + `","mode":420,"size":1}}` + "\n"
	if err := os.WriteFile(path, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Baseline()) != 0 {
		t.Fatalf("v1 records used: %+v", s.Baseline())
	}
	rec := ids.Record{SHA256: hexOK(), Mode: 0o100644, Size: 1}
	if err := s.PutBaseline(map[string]ids.Record{"/var/lib/a": rec}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.HasPrefix(raw, []byte(`{"v":2,"records":{`)) {
		t.Fatalf("%s %v", raw, err)
	}
	s, err = Open(dir, nil)
	if err != nil || s.Baseline()["/var/lib/a"] != rec {
		t.Fatalf("reopen %v %+v", err, s.Baseline())
	}
	for name, body := range map[string]string{
		"v3":        `{"v":3,"records":{}}`,
		"v1 tagged": `{"v":1,"records":{}}`,
		"extra":     `{"v":2,"records":{},"x":1}`,
		"not json":  `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(dir, nil); err == nil {
				t.Fatal("opened")
			}
		})
	}
}

func TestStateReadDoesNotBlockOnFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "config.json")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readUpTo(fifo, fileMax)
		done <- err
	}()
	select {
	case err := <-done:
		if codes.Code(err) != codes.NotRegular {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked on a FIFO")
	}
}
