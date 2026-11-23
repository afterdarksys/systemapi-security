package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/caps"
	"github.com/afterdarksys/systemapi-security/internal/codes"
	"github.com/afterdarksys/systemapi-security/internal/ids"
	"github.com/afterdarksys/systemapi-security/internal/notify"
	"github.com/afterdarksys/systemapi-security/internal/store"
)

const topic = "topic-topic-topic-topic"

var frozen = time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)

func expAt() int64 { return frozen.Unix() + 600 }

func newEng(t *testing.T) (*Engine, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Engine{Store: st, Host: "localhost", Now: func() time.Time { return frozen }}, dir
}

func coverAll(string) bool { return true }

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if codes.Code(err) != code {
		t.Fatalf("code %q, want %s (%v)", codes.Code(err), code, err)
	}
}

func putJSON(t *testing.T, e *Engine, lease string, v any, covers func(string) bool) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.PutConfig("actor", lease, expAt(), b, covers); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func actions(t *testing.T, e *Engine) []string {
	t.Helper()
	rows, err := e.Audit(0)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Action
	}
	return out
}

func countAction(ss []string, want string) int {
	n := 0
	for _, s := range ss {
		if s == want {
			n++
		}
	}
	return n
}

func sha12(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])[:12]
}

type capture struct {
	posts  int
	bodies []string
	log    []string
	lookup int
}

func (c *capture) sender(ips []net.IP, postErr error, status int) *notify.Sender {
	return &notify.Sender{
		Lookup: func(context.Context, string, string) ([]net.IP, error) {
			c.lookup++
			return ips, nil
		},
		Post: func(_ context.Context, req *http.Request, _ []string) (*http.Response, error) {
			b, _ := io.ReadAll(req.Body)
			c.posts++
			c.bodies = append(c.bodies, string(b))
			if postErr != nil {
				return nil, postErr
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("x"))}, nil
		},
		Log: func(code string) { c.log = append(c.log, code) },
	}
}

func publicIP() []net.IP { return []net.IP{net.ParseIP("1.1.1.1")} }

func TestIntegrityEdgesAndQuietRepeat(t *testing.T) {
	e, dir := newEng(t)
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	writeFile(t, a, "one")
	writeFile(t, b, "one")
	putJSON(t, e, "lease-cfg1", map[string]any{"watch": []string{a, b}}, coverAll)
	if err := e.Baseline("actor", "lease-base1", expAt(), coverAll); err != nil {
		t.Fatal(err)
	}
	writeFile(t, a, "two")
	writeFile(t, b, "two")
	cap := &capture{}
	e.Sender = cap.sender(publicIP(), nil, 200)
	e.Log = func(code string) { cap.log = append(cap.log, code) }
	if err := e.PutContact("actor", "lease-ntfy1", expAt(), notify.Prefix+notify.Base+topic); err != nil {
		t.Fatal(err)
	}
	found, err := e.Scan("actor", "lease-scan")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || found[0].Kind != ids.KindChange || found[1].Subject != b {
		t.Fatalf("findings %+v", found)
	}
	if cap.posts != 1 {
		t.Fatalf("posts %d", cap.posts)
	}
	if !strings.Contains(cap.bodies[0], "secsvc integrity_changed on localhost: "+a) {
		t.Fatalf("body %q", cap.bodies[0])
	}
	acts := actions(t, e)
	if countAction(acts, "ids.finding") != 2 || countAction(acts, "notify.sent") != 1 || countAction(acts, "notify.coalesced") != 1 {
		t.Fatalf("actions %v", acts)
	}
	writeFile(t, a, "three!!")
	if _, err := e.Scan("secsvc", ""); err != nil {
		t.Fatal(err)
	}
	acts = actions(t, e)
	if countAction(acts, "ids.finding") != 2 {
		t.Fatalf("repeat finding rows %v", acts)
	}
	open, err := e.Findings()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(open[0].Summary, sha12("three!!")) {
		t.Fatalf("summary %q", open[0].Summary)
	}
	writeFile(t, a, "one")
	writeFile(t, b, "one")
	if _, err := e.Scan("secsvc", ""); err != nil {
		t.Fatal(err)
	}
	acts = actions(t, e)
	if countAction(acts, "ids.resolved") != 2 {
		t.Fatalf("resolved %v", acts)
	}
	if _, err := e.Scan("secsvc", ""); err != nil {
		t.Fatal(err)
	}
	if got := actions(t, e); len(got) != len(acts) {
		t.Fatalf("quiet scan grew audit %v", got)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(topic)) {
		t.Fatal("audit contains topic")
	}
	for _, line := range cap.log {
		if strings.Contains(line, topic) {
			t.Fatal("log contains topic")
		}
	}
	view, err := e.Config()
	if err != nil {
		t.Fatal(err)
	}
	vb, _ := json.Marshal(view)
	if bytes.Contains(vb, []byte(topic)) || view.ContactState != "set" || view.ContactSHA256 == "" {
		t.Fatalf("view %s", vb)
	}
}

func TestNoContactSkipsNotify(t *testing.T) {
	e, dir := newEng(t)
	p := filepath.Join(dir, "f")
	writeFile(t, p, "one")
	putJSON(t, e, "lease-cfg2", map[string]any{"watch": []string{p}}, coverAll)
	if err := e.Baseline("actor", "lease-base2", expAt(), coverAll); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, "two")
	cap := &capture{}
	e.Sender = cap.sender(publicIP(), nil, 200)
	if _, err := e.Scan("secsvc", ""); err != nil {
		t.Fatal(err)
	}
	acts := actions(t, e)
	if countAction(acts, "notify.sent") != 0 || countAction(acts, "notify.failed") != 0 || countAction(acts, "ids.finding") != 1 {
		t.Fatalf("actions %v", acts)
	}
	if cap.posts != 0 {
		t.Fatalf("posted %d", cap.posts)
	}
}

func TestCoverageAndBaselineSpend(t *testing.T) {
	e, dir := newEng(t)
	kept := filepath.Join(dir, "kept")
	writeFile(t, kept, "k")
	putJSON(t, e, "lease-cfg3", map[string]any{"watch": []string{kept}, "auth_fail_limit": 5}, coverAll)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(kept, link); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"watch": []string{link}, "auth_fail_limit": 9})
	err := e.PutConfig("actor", "lease-bad", expAt(), body, func(string) bool { return false })
	wantCode(t, err, codes.Forbidden)
	body, _ = json.Marshal(map[string]any{"watch": []string{kept}, "auth_fail_limit": 9})
	if err := e.PutConfig("actor", "lease-ok", expAt(), body, func(string) bool { return false }); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "out")
	writeFile(t, outside, "o")
	body, _ = json.Marshal(map[string]any{"watch": []string{kept, outside}})
	err = e.PutConfig("actor", "lease-out", expAt(), body, func(p string) bool { return p == kept })
	wantCode(t, err, codes.Forbidden)
	inside := filepath.Join(dir, "in")
	writeFile(t, inside, "i")
	body, _ = json.Marshal(map[string]any{"watch": []string{kept, inside}})
	if err := e.PutConfig("actor", "lease-in", expAt(), body, func(p string) bool {
		return p == kept || p == inside
	}); err != nil {
		t.Fatal(err)
	}

	miss := filepath.Join(dir, "missing")
	body, _ = json.Marshal(map[string]any{"watch": []string{miss}})
	if err := e.PutConfig("actor", "lease-miss", expAt(), body, coverAll); err != nil {
		t.Fatal(err)
	}
	err = e.Baseline("actor", "lease-nobase", expAt(), coverAll)
	wantCode(t, err, codes.BadPath)
	writeFile(t, miss, "m")
	if err := e.Baseline("actor", "lease-nobase", expAt(), coverAll); err != nil {
		t.Fatal(err)
	}

	sl := filepath.Join(dir, "became-link")
	writeFile(t, sl, "s")
	body, _ = json.Marshal(map[string]any{"watch": []string{sl}})
	if err := e.PutConfig("actor", "lease-sl", expAt(), body, coverAll); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sl); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(kept, sl); err != nil {
		t.Fatal(err)
	}
	err = e.Baseline("actor", "lease-slbase", expAt(), coverAll)
	wantCode(t, err, codes.BadPath)
	err = e.Baseline("actor", "lease-slbase", expAt(), coverAll)
	wantCode(t, err, codes.BadPath)
	if err := os.Remove(sl); err != nil {
		t.Fatal(err)
	}
	writeFile(t, sl, "s")
	if err := e.Baseline("actor", "lease-slbase", expAt(), coverAll); err != nil {
		t.Fatal(err)
	}

	big := filepath.Join(dir, "big")
	writeFile(t, big, "b")
	body, _ = json.Marshal(map[string]any{"watch": []string{big}})
	if err := e.PutConfig("actor", "lease-big", expAt(), body, coverAll); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(big, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(ids.FileMax + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	err = e.Baseline("actor", "lease-bigbase", expAt(), coverAll)
	wantCode(t, err, codes.BadPath)

	body, _ = json.Marshal(map[string]any{})
	if err := e.PutConfig("actor", "lease-empty", expAt(), body, coverAll); err != nil {
		t.Fatal(err)
	}
	if err := e.Baseline("actor", "lease-emptyb", expAt(), coverAll); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "baseline.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != "{}" {
		t.Fatalf("baseline %s", raw)
	}
	err = e.Baseline("actor", "lease-emptyb", expAt(), coverAll)
	wantCode(t, err, codes.GrantSpent)
}

func TestSymlinkWatchIsNotFollowed(t *testing.T) {
	e, dir := newEng(t)
	secret := filepath.Join(dir, "secret")
	writeFile(t, secret, "SECRETSECRET")
	link := filepath.Join(dir, "watch-link")
	body, _ := json.Marshal(map[string]any{"watch": []string{link}})
	if err := e.PutConfig("actor", "lease-w", expAt(), body, coverAll); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	found, err := e.Scan("secsvc", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].Kind != ids.KindLink || found[0].Summary != "symlink" {
		t.Fatalf("finding %+v", found)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if bytes.Contains(raw, []byte("SECRETSECRET")) {
		t.Fatal("followed symlink")
	}
}

func TestListenProc(t *testing.T) {
	e, _ := newEng(t)
	calls := 0
	e.Proc = func() (string, string, bool, error) {
		calls++
		return "", "", true, nil
	}
	if _, err := e.Scan("secsvc", ""); err != nil {
		t.Fatal(err)
	}
	st, err := e.Status()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 || st.Listen != ids.StateOff || st.Armed.Listen {
		t.Fatalf("off scan calls=%d %+v", calls, st)
	}
	e2, _ := newEng(t)
	body, _ := json.Marshal(map[string]any{"listen_allow": []string{"127.0.0.1:22"}})
	if err := e2.PutConfig("actor", "lease-ls", expAt(), body, coverAll); err != nil {
		t.Fatal(err)
	}
	st, err = e2.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Listen != ids.StateWait || !st.Armed.Listen {
		t.Fatalf("pending %+v", st)
	}
	e2.Proc = func() (string, string, bool, error) {
		calls++
		return "", "", true, nil
	}
	if _, err := e2.Scan("secsvc", ""); err != nil {
		t.Fatal(err)
	}
	st, err = e2.Status()
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || st.Listen != ids.StateBad || st.OpenFindings != 0 {
		t.Fatalf("unsupported calls=%d %+v", calls, st)
	}
	if c := capBy(st, "listen"); c.State != caps.StateDegraded || c.Reason != caps.ReasonUnreadable {
		t.Fatalf("listen cap %+v", c)
	}
	e = e2
	e.Proc = func() (string, string, bool, error) {
		calls++
		return listenFixture("0100007F:0016"), "", false, nil
	}
	found, err := e.Scan("secsvc", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("allowlisted %+v", found)
	}
	st, _ = e.Status()
	if st.Listen != ids.StateOK {
		t.Fatalf("state %s", st.Listen)
	}
	if c := capBy(st, "listen"); c.State != caps.StateOK || c.Reason != "" {
		t.Fatalf("listen cap %+v", c)
	}
	e.Proc = func() (string, string, bool, error) {
		return listenFixture("0100007F:0050"), "", false, nil
	}
	found, err = e.Scan("secsvc", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].Kind != ids.KindListen || found[0].Subject != "127.0.0.1:80" {
		t.Fatalf("unexpected %+v", found)
	}
	st, err = e.Status()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("127.0.0.1")) || capBy(st, "listen").State != caps.StateOK {
		t.Fatalf("status leaked or degraded %s", raw)
	}
}

func TestCapabilityReport(t *testing.T) {
	e, dir := newEng(t)
	st, err := e.Status()
	if err != nil {
		t.Fatal(err)
	}
	if capBy(st, "grant_v1").State != caps.StateOK || capBy(st, "audit").State != caps.StateOK {
		t.Fatalf("%+v", st.Caps)
	}
	for _, name := range []string{"auth", "integrity", "listen", "notify"} {
		if c := capBy(st, name); c.State != caps.StateAbsent || c.Reason != caps.ReasonFlagOff {
			t.Fatalf("%s %+v", name, c)
		}
	}

	secret := "SECRETSECRET"
	logPath := filepath.Join(dir, "auth.log")
	writeFile(t, logPath, "ok\n")
	putJSON(t, e, "lease-cap1", map[string]any{"auth_log": logPath}, coverAll)
	st, err = e.Status()
	if err != nil {
		t.Fatal(err)
	}
	if capBy(st, "auth").State != caps.StateOK {
		t.Fatalf("%+v", capBy(st, "auth"))
	}
	assertNo(t, st, dir, logPath, secret)

	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, secret), logPath); err != nil {
		t.Fatal(err)
	}
	st, err = e.Status()
	if err != nil {
		t.Fatal(err)
	}
	if c := capBy(st, "auth"); c.State != caps.StateDegraded || c.Reason != caps.ReasonUnreadable {
		t.Fatalf("symlink %+v", c)
	}
	assertNo(t, st, secret, logPath)

	if err := os.Remove(logPath); err != nil {
		t.Fatal(err)
	}
	st, err = e.Status()
	if err != nil {
		t.Fatal(err)
	}
	if c := capBy(st, "auth"); c.State != caps.StateDegraded || c.Reason != caps.ReasonTargetMissing {
		t.Fatalf("missing %+v", c)
	}
	assertNo(t, st, logPath)

	missing := filepath.Join(dir, "no-such-watch")
	good := filepath.Join(dir, "watched")
	writeFile(t, good, "a\n")
	putJSON(t, e, "lease-cap2", map[string]any{"watch": []string{good, missing}}, coverAll)
	st, err = e.Status()
	if err != nil {
		t.Fatal(err)
	}
	if capBy(st, "integrity").State != caps.StateOK || capBy(st, "auth").State != caps.StateAbsent {
		t.Fatalf("%+v", st.Caps)
	}
	assertNo(t, st, good, missing)

	putJSON(t, e, "lease-cap3", map[string]any{"watch": []string{missing}}, coverAll)
	st, err = e.Status()
	if err != nil {
		t.Fatal(err)
	}
	if c := capBy(st, "integrity"); c.State != caps.StateDegraded || c.Reason != caps.ReasonTargetMissing {
		t.Fatalf("watch %+v", c)
	}

	rawContact := notify.Prefix + notify.Base + topic
	if err := e.Store.PutContact(rawContact); err != nil {
		t.Fatal(err)
	}
	st, err = e.Status()
	if err != nil {
		t.Fatal(err)
	}
	if capBy(st, "notify").State != caps.StateOK {
		t.Fatalf("notify %+v", capBy(st, "notify"))
	}
	assertNo(t, st, rawContact, topic, "ntfy.sh")

	if err := os.WriteFile(filepath.Join(dir, "contact"), []byte("nope-"+secret), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err = e.Status()
	if err != nil {
		t.Fatal(err)
	}
	if c := capBy(st, "notify"); c.State != caps.StateDegraded || c.Reason != caps.ReasonBadContact {
		t.Fatalf("bad contact %+v", c)
	}
	assertNo(t, st, secret, "nope-")

	if err := e.Store.AppendAudit("secsvc", "lease-cap4", "scan", nil, frozen); err != nil {
		t.Fatal(err)
	}
	chain := filepath.Join(dir, "audit.jsonl")
	b, err := os.ReadFile(chain)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		t.Fatal("empty chain")
	}
	b[len(b)-2] ^= 0x01
	if err := os.WriteFile(chain, b, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err = e.Status()
	if err != nil {
		t.Fatal(err)
	}
	if c := capBy(st, "audit"); c.State != caps.StateDegraded || c.Reason != caps.ReasonAuditBad {
		t.Fatalf("audit %+v", c)
	}
	if capBy(st, "grant_v1").State != caps.StateOK {
		t.Fatal("grant_v1 moved")
	}
	assertNo(t, st, string(b))
}

func capBy(st Status, name string) caps.Result {
	for _, c := range st.Caps {
		if c.Name == name {
			return c
		}
	}
	return caps.Result{}
}

func assertNo(t *testing.T, st Status, banned ...string) {
	t.Helper()
	raw, err := json.Marshal(st.Caps)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range banned {
		if s != "" && bytes.Contains(raw, []byte(s)) {
			t.Fatalf("caps contain %q in %s", s, raw)
		}
	}
}

func listenFixture(addr string) string {
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	line := "   0: " + addr + " 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0 1 0000000000000000 100 0 0 10 0\n"
	return hdr + line
}

func TestContactEgressDoesNotSpend(t *testing.T) {
	e, _ := newEng(t)
	cap := &capture{}
	e.Sender = cap.sender([]net.IP{net.ParseIP("10.1.2.3")}, nil, 200)
	err := e.PutContact("actor", "lease-block", expAt(), notify.Prefix+notify.Base+topic)
	wantCode(t, err, codes.BlockedAddress)
	if cap.lookup != 1 {
		t.Fatalf("lookup %d", cap.lookup)
	}
	e.Sender = cap.sender(publicIP(), nil, 200)
	if err := e.PutContact("actor", "lease-block", expAt(), notify.Prefix+notify.Base+topic); err != nil {
		t.Fatal(err)
	}
	acts := actions(t, e)
	if countAction(acts, "notify.failed") != 0 || countAction(acts, "notify.set") != 1 {
		t.Fatalf("actions %v", acts)
	}
}

func TestCommitFailureStaysSpent(t *testing.T) {
	e, dir := newEng(t)
	body, _ := json.Marshal(map[string]any{"auth_fail_limit": 7})
	if err := e.PutConfig("actor", "lease-setup", expAt(), body, coverAll); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.json")
	if err := os.Remove(cfg); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cfg, 0o700); err != nil {
		t.Fatal(err)
	}
	body, _ = json.Marshal(map[string]any{"auth_fail_limit": 8})
	err := e.PutConfig("actor", "lease-fail", expAt(), body, coverAll)
	wantCode(t, err, codes.Failed)
	err = e.PutConfig("actor", "lease-fail", expAt(), body, coverAll)
	wantCode(t, err, codes.GrantSpent)
	rows, err := e.Audit(0)
	if err != nil {
		t.Fatal(err)
	}
	failed := 0
	for _, r := range rows {
		if r.Action == "config.set" && bytes.Contains(r.Detail, []byte(`"error":"failed"`)) {
			failed++
		}
	}
	if failed != 1 {
		t.Fatalf("failure rows %d in %v", failed, rows)
	}
}

func TestAuthEdge(t *testing.T) {
	e, dir := newEng(t)
	logp := filepath.Join(dir, "auth.log")
	var b strings.Builder
	for i := 0; i < 4; i++ {
		b.WriteString("Failed password for root from 9.9.9.9 port 22 ssh2\n")
	}
	b.WriteString("Accepted password for root from 9.9.9.9 port 22 ssh2\n")
	writeFile(t, logp, b.String())
	body, _ := json.Marshal(map[string]any{"auth_log": logp, "auth_fail_limit": 5})
	if err := e.PutConfig("actor", "lease-auth", expAt(), body, coverAll); err != nil {
		t.Fatal(err)
	}
	found, err := e.Scan("secsvc", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("under threshold %+v", found)
	}
	f, err := os.OpenFile(logp, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("Failed password for root from 9.9.9.9 port 22 ssh2\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	found, err = e.Scan("secsvc", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].Kind != ids.KindAuth || !strings.Contains(found[0].Summary, "9.9.9.9") {
		t.Fatalf("auth %+v", found)
	}
	if _, err := e.Scan("secsvc", ""); err != nil {
		t.Fatal(err)
	}
	if countAction(actions(t, e), "ids.finding") != 1 {
		t.Fatal(actions(t, e))
	}
}

func TestDropWatchResolves(t *testing.T) {
	e, dir := newEng(t)
	p := filepath.Join(dir, "u")
	writeFile(t, p, "u")
	putJSON(t, e, "lease-u", map[string]any{"watch": []string{p}}, coverAll)
	if _, err := e.Scan("secsvc", ""); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"watch": []string{}})
	if err := e.PutConfig("actor", "lease-drop", expAt(), body, coverAll); err != nil {
		t.Fatal(err)
	}
	found, err := e.Scan("secsvc", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 || countAction(actions(t, e), "ids.resolved") != 1 {
		t.Fatalf("found %v actions %v", found, actions(t, e))
	}
}

func TestAuditCapTruncated(t *testing.T) {
	e, dir := newEng(t)
	if err := e.Store.AppendAudit("secsvc", "lease-trunc", "scan", nil, frozen); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "audit.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := e.Status()
	if err != nil {
		t.Fatal(err)
	}
	if c := capBy(st, "audit"); c.State != caps.StateDegraded || c.Reason != caps.ReasonAuditBad {
		t.Fatalf("audit %+v", c)
	}
}
