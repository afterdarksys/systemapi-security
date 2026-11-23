package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/api"
	"github.com/afterdarksys/systemapi-security/internal/audit"
	"github.com/afterdarksys/systemapi-security/internal/codes"
	"github.com/afterdarksys/systemapi-security/internal/grant"
	"github.com/afterdarksys/systemapi-security/internal/notify"
	"github.com/afterdarksys/systemapi-security/internal/store"
)

func capture(t *testing.T) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, errb bytes.Buffer
	oldOut, oldErr, oldNow := stdout, stderr, now
	stdout, stderr = &out, &errb
	t.Cleanup(func() {
		stdout, stderr, now = oldOut, oldErr, oldNow
	})
	return &out, &errb
}

func want(t *testing.T, out, errb *bytes.Buffer, args []string, code int, stderr string) {
	t.Helper()
	out.Reset()
	errb.Reset()
	if c := Main(args); c != code || errb.String() != stderr || out.Len() != 0 {
		t.Fatalf("args %v got %d %q %q want %d %q", args, c, errb.String(), out.String(), code, stderr)
	}
}

func TestKeygenAndGrantPolicy(t *testing.T) {
	out, errb := capture(t)
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed")
	if c := Main([]string{"keygen", "--seed-out", seedPath}); c != 0 || errb.Len() != 0 {
		t.Fatal(c, errb.String())
	}
	pubHex := strings.TrimSuffix(out.String(), "\n")
	if out.String() != pubHex+"\n" || len(pubHex) != 64 || strings.Contains(pubHex, "\n") {
		t.Fatalf("pub %q", out.String())
	}
	raw, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 || bytes.Contains(out.Bytes(), raw) || strings.Contains(out.String(), hex.EncodeToString(raw)) {
		t.Fatal("seed reached stdout")
	}
	fi, err := os.Lstat(seedPath)
	if err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Fatal(fi, err)
	}
	want(t, out, errb, []string{"keygen", "--seed-out", seedPath}, 2, "failed\n")
	want(t, out, errb, []string{"keygen"}, 2, "usage\n")

	if err := os.Chmod(seedPath, 0o644); err != nil {
		t.Fatal(err)
	}
	want(t, out, errb, []string{"grant", "--seed", seedPath, "--actor", "ops", "--host", "host1", "--purpose", "security:read", "--ttl", "10m"}, 2, "seed_perms\n")
	if err := os.Chmod(seedPath, 0o600); err != nil {
		t.Fatal(err)
	}

	frozen := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	now = func() time.Time { return frozen }
	base := []string{"grant", "--seed", seedPath, "--actor", "ops", "--host", "host1", "--purpose", "security:operate", "--ttl", "10m"}
	want(t, out, errb, []string{"grant", "--seed", seedPath, "--actor", "ops", "--host", "host1", "--purpose", "nope", "--ttl", "10m"}, 2, "grant_bad_shape\n")
	want(t, out, errb, []string{"grant", "--seed", seedPath, "--actor", "ops", "--host", "host1", "--purpose", "security:operate", "--ttl", "15m1s"}, 2, "grant_ttl\n")
	want(t, out, errb, []string{"grant", "--seed", seedPath, "--actor", "ops", "--host", "host1", "--purpose", "security:operate", "--ttl", "901s"}, 2, "grant_ttl\n")
	want(t, out, errb, []string{"grant", "--seed", seedPath, "--actor", "ops", "--host", "host1", "--purpose", "security:operate", "--ttl", "0s"}, 2, "grant_ttl\n")
	want(t, out, errb, []string{"grant", "--seed", seedPath, "--actor", "ops", "--host", "host1", "--purpose", "security:operate", "--ttl", "nope"}, 2, "usage\n")
	want(t, out, errb, []string{"grant", "--seed", seedPath, "--actor", "bad actor", "--host", "host1", "--purpose", "security:read", "--ttl", "10m"}, 2, "grant_bad_shape\n")
	want(t, out, errb, []string{"grant", "--seed", seedPath, "--actor", "ops", "--host", "BAD", "--purpose", "security:read", "--ttl", "10m"}, 2, "grant_bad_shape\n")
	want(t, out, errb, append(base, "--lease", "short"), 2, "grant_bad_shape\n")
	want(t, out, errb, append(base, "--watch", "tmp"), 2, "grant_bad_shape\n")
	want(t, out, errb, append(base, "--watch", "/"), 2, "grant_root_slash\n")
	want(t, out, errb, append(base, "--watch", "//"), 2, "grant_root_slash\n")
	want(t, out, errb, append(base, "--watch", "/", "--watch", "/"), 2, "grant_bad_shape\n")
	want(t, out, errb, append(base, "--watch", "*", "--watch", "tmp"), 2, "grant_bad_shape\n")
	want(t, out, errb, append(base, "--watch", "*"), 2, "grant_star\n")
	want(t, out, errb, append(base, "--entitlement", "*"), 2, "grant_star\n")
	want(t, out, errb, append(base, "--entitlement", "*", "--entitlement", "*"), 2, "grant_bad_shape\n")
	want(t, out, errb, append(base, "--entitlement", "security.pwn"), 2, "grant_purpose\n")
	want(t, out, errb, append(base, "--entitlement", "Bad_Name"), 2, "grant_bad_shape\n")
	want(t, out, errb, []string{"grant", "--seed", filepath.Join(dir, "missing"), "--actor", "ops", "--host", "host1", "--purpose", "security:read", "--ttl", "10m"}, 2, "bad_pub\n")

	out.Reset()
	errb.Reset()
	args := append(base, "--ttl", "15m", "--lease", "lease-cliok", "--watch", "/var/lib")
	// base already has --ttl 10m. Passing --ttl twice keeps the last value.
	if c := Main(args); c != 0 || errb.Len() != 0 {
		t.Fatal(c, errb.String(), out.String())
	}
	doc := strings.TrimSuffix(out.String(), "\n")
	if out.String() != doc+"\n" || strings.Contains(doc, "\n") || strings.Contains(doc, hex.EncodeToString(raw)) {
		t.Fatal(out.String())
	}
	pubRaw, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatal(err)
	}
	g, err := grant.Verify(doc, ed25519.PublicKey(pubRaw), "host1", frozen)
	if err != nil {
		t.Fatal(err)
	}
	if g.Iat != frozen.Unix() || g.Exp != frozen.Unix()+900 || g.LeaseID != "lease-cliok" || !reflect.DeepEqual(g.Entitlements, grant.Fill(grant.PurposeOperate)) || !reflect.DeepEqual(g.Watch, []string{"/var/lib"}) {
		t.Fatalf("%+v", g)
	}

	out.Reset()
	errb.Reset()
	if c := Main([]string{"grant", "--seed", seedPath, "--actor", "ops", "--host", "host1", "--purpose", "security:read", "--ttl", "900s", "--lease", "lease-read1", "--entitlement", "security.read"}); c != 0 {
		t.Fatal(c, errb.String())
	}
	g, err = grant.Verify(strings.TrimSuffix(out.String(), "\n"), ed25519.PublicKey(pubRaw), "host1", frozen)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(g.Entitlements, []string{"security.read"}) || g.Exp != frozen.Unix()+900 {
		t.Fatalf("%+v", g)
	}
}

func TestServeRejectsShortInterval(t *testing.T) {
	out, errb := capture(t)
	parent := t.TempDir()
	dir := filepath.Join(parent, "state")
	want(t, out, errb, []string{"serve", "--dir", dir, "--pub", filepath.Join(parent, "pub"), "--host", "host1", "--socket", "/tmp/secsvc-not-used", "--interval", "1s"}, 2, "usage\n")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestAuditVerify(t *testing.T) {
	out, errb := capture(t)
	dir := t.TempDir()
	if c := Main([]string{"audit", "verify", "--dir", dir}); c != 0 || errb.Len() != 0 || out.String() != `{"ok":true,"rows":0}`+"\n" {
		t.Fatalf("%d %q %q", c, errb.String(), out.String())
	}
	if err := os.Mkdir(filepath.Join(dir, audit.SegDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, audit.SegDir, "000001.jsonl"), []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want(t, out, errb, []string{"audit", "verify", "--dir", dir}, 1, "audit_bad\n")
	want(t, out, errb, []string{"audit", "verify", "--dir", filepath.Join(dir, "missing")}, 2, "bad_dir\n")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	want(t, out, errb, []string{"audit", "verify", "--dir", link}, 2, "bad_dir\n")
}

func TestCallLocalRejects(t *testing.T) {
	out, errb := capture(t)
	dir := t.TempDir()
	sock := filepath.Join(dir, "no-sock")
	grantPath := filepath.Join(dir, "grant")
	if err := os.WriteFile(grantPath, []byte("{}\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want(t, out, errb, []string{"call", "status", "--socket", sock, "--grant", grantPath}, 1, "grant_bad_shape\n")
	want(t, out, errb, []string{"call", "status", "--socket", sock, "--grant", filepath.Join(dir, "missing")}, 2, "usage\n")
	link := filepath.Join(dir, "glink")
	if err := os.Symlink(grantPath, link); err != nil {
		t.Fatal(err)
	}
	want(t, out, errb, []string{"call", "status", "--socket", sock, "--grant", link}, 1, "grant_bad_shape\n")

	contact := notify.Prefix + notify.Base + "topic-topic-topic-topic"
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte(contact), 0o644); err != nil {
		t.Fatal(err)
	}
	want(t, out, errb, []string{"call", "contact", "--socket", sock, "--grant", grantPath, "--contact-file", loose}, 2, "bad_contact\n")
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	want(t, out, errb, []string{"call", "contact", "--socket", sock, "--grant", grantPath, "--contact-file", empty}, 2, "bad_contact\n")
	nl := filepath.Join(dir, "nl")
	if err := os.WriteFile(nl, []byte(contact+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want(t, out, errb, []string{"call", "contact", "--socket", sock, "--grant", grantPath, "--contact-file", nl}, 2, "bad_contact\n")
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, bytes.Repeat([]byte("a"), notify.ContactMax+1), 0o600); err != nil {
		t.Fatal(err)
	}
	want(t, out, errb, []string{"call", "contact", "--socket", sock, "--grant", grantPath, "--contact-file", big}, 2, "bad_contact\n")
	clink := filepath.Join(dir, "clink")
	if err := os.Symlink(loose, clink); err != nil {
		t.Fatal(err)
	}
	want(t, out, errb, []string{"call", "contact", "--socket", sock, "--grant", grantPath, "--contact-file", clink}, 2, "bad_contact\n")
	want(t, out, errb, []string{"call", "contact", "--socket", sock, "--grant", grantPath, "--contact-file", filepath.Join(dir, "nope")}, 2, "usage\n")

	wide := filepath.Join(dir, "wide")
	if err := os.WriteFile(wide, bytes.Repeat([]byte(" "), api.BodyMax+1), 0o600); err != nil {
		t.Fatal(err)
	}
	want(t, out, errb, []string{"call", "config-set", "--socket", sock, "--grant", grantPath, "--file", wide}, 1, "oversized\n")
	want(t, out, errb, []string{"call", "config-set", "--socket", sock, "--grant", grantPath, "--file", filepath.Join(dir, "nope")}, 2, "usage\n")

	good := filepath.Join(dir, "good-contact")
	if err := os.WriteFile(good, []byte(contact), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grantPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if c := Main([]string{"call", "contact", "--socket", sock, "--grant", grantPath, "--contact-file", good}); c != 1 || errb.String() != "failed\n" || out.Len() != 0 || bytes.Contains(errb.Bytes(), []byte("topic-topic-topic-topic")) {
		t.Fatalf("%d %q %q", c, errb.String(), out.String())
	}
}

func TestCallAgainstServe(t *testing.T) {
	out, errb := capture(t)
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed")
	if c := Main([]string{"keygen", "--seed-out", seedPath}); c != 0 {
		t.Fatal(c, errb.String())
	}
	pubPath := filepath.Join(dir, "pub")
	if err := os.WriteFile(pubPath, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if c := Main([]string{"grant", "--seed", seedPath, "--actor", "ops", "--host", "host1", "--purpose", "security:operate", "--ttl", "10m", "--lease", "lease-call1"}); c != 0 {
		t.Fatal(c, errb.String(), out.String())
	}
	grantPath := filepath.Join(dir, "grant")
	if err := os.WriteFile(grantPath, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if c := Main([]string{"grant", "--seed", seedPath, "--actor", "ops", "--host", "host1", "--purpose", "security:operate", "--ttl", "10m", "--lease", "lease-call2", "--watch", "/proc/net"}); c != 0 {
		t.Fatal(c, errb.String())
	}
	grant2 := filepath.Join(dir, "grant2")
	if err := os.WriteFile(grant2, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	sockDir, err := os.MkdirTemp("/tmp", "ss")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "sock")
	state := filepath.Join(dir, "state")
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- api.Serve(ctx, api.Options{
			Dir: state, PubPath: pubPath, Host: "host1", Socket: sock, Interval: 30 * time.Second,
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errc:
			if err != nil {
				t.Errorf("serve %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("serve hung")
		}
	})
	waitReady(t, sock)

	out.Reset()
	errb.Reset()
	if c := Main([]string{"call", "status", "--socket", sock, "--grant", grantPath}); c != 0 || errb.Len() != 0 || !bytes.Contains(out.Bytes(), []byte(`"host":"host1"`)) || !bytes.Contains(out.Bytes(), []byte(`{"name":"grant_v1","state":"ok","reason":""}`)) {
		t.Fatalf("%d %q %q", c, errb.String(), out.String())
	}
	empty := filepath.Join(dir, "empty-grant")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	want(t, out, errb, []string{"call", "status", "--socket", sock, "--grant", empty}, 1, "grant_missing\n")

	// Change a signed field deterministically. Replacing a random base64
	// character sometimes left the original document untouched.
	tampered := bytes.Replace(mustRead(t, grantPath), []byte(`"actor":"ops"`), []byte(`"actor":"tampered"`), 1)
	if bytes.Equal(tampered, mustRead(t, grantPath)) {
		t.Fatal("grant was not tampered")
	}
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	want(t, out, errb, []string{"call", "status", "--socket", sock, "--grant", bad}, 1, codes.GrantBadSig+"\n")

	out.Reset()
	errb.Reset()
	if c := Main([]string{"call", "scan", "--socket", sock, "--grant", grantPath}); c != 0 || !bytes.Contains(out.Bytes(), []byte(`"findings":[]`)) {
		t.Fatalf("%d %q %q", c, errb.String(), out.String())
	}
	cfg := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfg, []byte(`{"listen_allow":["127.0.0.1:22"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if c := Main([]string{"call", "config-set", "--socket", sock, "--grant", grant2, "--file", cfg}); c != 0 || !bytes.Contains(out.Bytes(), []byte(`"ok":true`)) {
		t.Fatalf("%d %q %q", c, errb.String(), out.String())
	}
	out.Reset()
	errb.Reset()
	if c := Main([]string{"call", "config", "--socket", sock, "--grant", grantPath}); c != 0 || !bytes.Contains(out.Bytes(), []byte(`"listen_allow":["127.0.0.1:22"]`)) {
		t.Fatalf("%d %q %q", c, errb.String(), out.String())
	}
	out.Reset()
	errb.Reset()
	if c := Main([]string{"audit", "verify", "--dir", state}); c != 0 || errb.Len() != 0 {
		t.Fatal(c, errb.String(), out.String())
	}
	var env struct {
		OK   bool `json:"ok"`
		Rows int  `json:"rows"`
	}
	if err := json.Unmarshal(out.Bytes(), &env); err != nil || !env.OK || env.Rows < 1 {
		t.Fatalf("%s", out.String())
	}
}

func waitReady(t *testing.T, sock string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	client := api.NewClient(sock)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, "http://secsvc/v1/status", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err == nil {
			cerr := resp.Body.Close()
			if cerr != nil {
				t.Fatal(cerr)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("socket")
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestServeRefusesPlaceholderHost(t *testing.T) {
	out, errb := capture(t)
	parent := t.TempDir()
	dir := filepath.Join(parent, "state")
	base := []string{"serve", "--dir", dir, "--pub", filepath.Join(parent, "pub"), "--socket", "/tmp/secsvc-not-used"}
	want(t, out, errb, append(append([]string{}, base...), "--host", "localhost"), 2, "host_unset\n")
	want(t, out, errb, append(append([]string{}, base...), "--host", ""), 2, "host_unset\n")
	want(t, out, errb, base, 2, "host_unset\n")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

// The shipped unit and service templates carry no host value, so a service
// started without configuration refuses with host_unset.
func TestShippedTemplatesHaveNoHost(t *testing.T) {
	root := filepath.Join("..", "..")
	var unit struct {
		Exec []string `json:"exec"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(root, "units", "secsvc.json")), &unit); err != nil {
		t.Fatal(err)
	}
	host := -1
	for i, a := range unit.Exec {
		if a == "--host" && i+1 < len(unit.Exec) {
			host = i + 1
		}
	}
	if host < 0 || unit.Exec[host] != "" {
		t.Fatalf("unit host %v", unit.Exec)
	}
	for file, line := range map[string]string{
		filepath.Join("packaging", "systemd", "service.env.example"): "SECSVC_HOST=",
		filepath.Join("packaging", "openrc", "secsvc.confd"):         `secsvc_host=""`,
	} {
		found := false
		for _, l := range strings.Split(string(mustRead(t, filepath.Join(root, file))), "\n") {
			if strings.HasPrefix(l, "SECSVC_HOST=") || strings.HasPrefix(l, "secsvc_host=") {
				if l != line {
					t.Fatalf("%s: %q has a default", file, l)
				}
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: no host line", file)
		}
	}
	svc := string(mustRead(t, filepath.Join(root, "packaging", "systemd", "secsvc.service")))
	if !strings.Contains(svc, "--host ${SECSVC_HOST} ") {
		t.Fatal("systemd unit does not take the host from SECSVC_HOST")
	}
	rc := string(mustRead(t, filepath.Join(root, "packaging", "openrc", "secsvc")))
	if !strings.Contains(rc, "--host ${secsvc_host} ") || !strings.Contains(rc, `""|localhost|`) {
		t.Fatal("openrc script does not refuse an unset or localhost host")
	}
}

// TestHelperHoldStore is not a test: TestAuditAnchor runs it in a child
// process to hold the store lock the way a daemon does.
func TestHelperHoldStore(t *testing.T) {
	dir := os.Getenv("SECSVC_HOLD_STORE")
	if dir == "" {
		t.Skip("helper")
	}
	// The unanchored chain would make Open itself refuse, so that case takes
	// only the lock; a fresh directory is held through store.Open.
	if os.Getenv("SECSVC_HOLD_OPEN") != "" {
		if _, err := store.Open(dir, nil); err != nil {
			t.Fatal(err)
		}
	} else if _, err := store.Lock(dir); err != nil {
		t.Fatal(err)
	}
	os.Stdout.WriteString("held\n")
	io.Copy(io.Discard, os.Stdin)
}

// legacyChain leaves a single-file chain of n rows with no anchor in dir,
// the layout from before segments and anchors.
func legacyChain(t *testing.T, dir string, n int) {
	t.Helper()
	tmp := t.TempDir()
	c, err := audit.Open(tmp, audit.Options{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := c.Append("a", "lease-0001", "config.set", nil, time.Unix(1_700_000_000, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Rename(filepath.Join(tmp, audit.SegDir, "000001.jsonl"), filepath.Join(dir, audit.LegacyName)); err != nil {
		t.Fatal(err)
	}
}

func TestAuditAnchorAndMigrate(t *testing.T) {
	out, errb := capture(t)
	dir := t.TempDir()
	legacyChain(t, dir, 2)
	want(t, out, errb, []string{"audit", "verify", "--dir", dir}, 1, codes.AuditLayout+"\n")
	// No anchor: migrate refuses rather than bless a truncated chain.
	want(t, out, errb, []string{"audit", "migrate", "--dir", dir}, 1, codes.AuditTruncated+"\n")

	// Another process holds the store: anchor and migrate refuse.
	release := holdStore(t, dir, false)
	want(t, out, errb, []string{"audit", "anchor", "--dir", dir}, 1, codes.StoreBusy+"\n")
	want(t, out, errb, []string{"audit", "migrate", "--dir", dir}, 1, codes.StoreBusy+"\n")
	release()
	// store.Open takes the same lock, so a running daemon blocks both.
	fresh := t.TempDir()
	release = holdStore(t, fresh, true)
	want(t, out, errb, []string{"audit", "anchor", "--dir", fresh}, 1, codes.StoreBusy+"\n")
	want(t, out, errb, []string{"audit", "migrate", "--dir", fresh}, 1, codes.StoreBusy+"\n")
	release()

	out.Reset()
	errb.Reset()
	if c := Main([]string{"audit", "anchor", "--dir", dir}); c != 0 || out.String() != `{"ok":true,"rows":3}`+"\n" {
		t.Fatalf("%d %q %q", c, out.String(), errb.String())
	}
	want(t, out, errb, []string{"audit", "anchor", "--dir", dir}, 1, codes.AnchorExists+"\n")
	out.Reset()
	errb.Reset()
	if c := Main([]string{"audit", "migrate", "--dir", dir}); c != 0 || out.String() != `{"ok":true,"rows":4}`+"\n" {
		t.Fatalf("%d %q %q", c, out.String(), errb.String())
	}
	out.Reset()
	if c := Main([]string{"audit", "verify", "--dir", dir}); c != 0 || out.String() != `{"ok":true,"rows":4}`+"\n" {
		t.Fatalf("%d %q %q", c, out.String(), errb.String())
	}
	want(t, out, errb, []string{"audit", "migrate", "--dir", dir}, 1, codes.AuditLayout+"\n")
	want(t, out, errb, []string{"audit", "anchor", "--dir", dir}, 1, codes.AuditLayout+"\n")
	// The migrated directory opens as a store.
	st, err := store.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := st.AuditVerify(); err != nil || n != 4 {
		t.Fatalf("store verify %d %v", n, err)
	}
}

func holdStore(t *testing.T, dir string, open bool) func() {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldStore$")
	cmd.Env = append(os.Environ(), "SECSVC_HOLD_STORE="+dir)
	if open {
		cmd.Env = append(cmd.Env, "SECSVC_HOLD_OPEN=1")
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "held\n" {
		stdin.Close()
		cmd.Wait()
		t.Fatalf("helper %q %v", line, err)
	}
	return func() {
		stdin.Close()
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
}

// audit verify names the stored witness the chain no longer holds.
func TestAuditVerifyNamesWitness(t *testing.T) {
	out, errb := capture(t)
	dir := t.TempDir()
	c, err := audit.Open(dir, audit.Options{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := c.Append("a", "lease-0001", "config.set", nil, time.Unix(1_700_000_000, 0)); err != nil {
			t.Fatal(err)
		}
	}
	seq, hash, _, err := c.Head()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AddWitness(audit.Witness{Seq: seq, Hash: hash, Witness: "cp-1", Time: "2026-11-23T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, audit.WitnessName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), hash, strings.Repeat("f", 64), 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	want(t, out, errb, []string{"audit", "verify", "--dir", dir}, 1, codes.AuditTruncated+"\nwitness seq 2\n")
}
