package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"golang.org/x/sys/unix"
)

func TestChainAppendAndVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	n, err := VerifyFile(path)
	if err != nil || n != 0 {
		t.Fatalf("missing: %d %v", n, err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(path); err != nil {
		t.Fatal(err)
	}
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 5).UTC()
	if err := c.Append("ops", "lease-0001", "config.set", []byte(`{"b":1,"a":"<x>"}`), now); err != nil {
		t.Fatal(err)
	}
	if err := c.Append("ops", "lease-0001", "ids.finding", nil, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	rows, err := c.ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatalf("%d %v", len(rows), err)
	}
	if rows[0].Seq != 1 || rows[1].Seq != 2 || rows[1].Prev != rows[0].Hash || rows[0].Prev != Genesis {
		t.Fatalf("link %+v %+v", rows[0], rows[1])
	}
	if rows[0].Time != now.Format(time.RFC3339Nano) {
		t.Fatal(rows[0].Time)
	}
	if string(rows[0].Detail) != `{"a":"<x>","b":1}` {
		t.Fatalf("detail %s", rows[0].Detail)
	}
	raw, err := os.ReadFile(path)
	if err != nil || bytes.Contains(raw, []byte(`\u003c`)) || !bytes.Contains(raw, []byte("<x>")) {
		t.Fatalf("escape %s", raw)
	}
	tail, err := c.Tail(1)
	if err != nil || len(tail) != 1 || tail[0].Seq != 2 {
		t.Fatalf("tail %+v %v", tail, err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}

func TestChainTamper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	if err := c.Append("a", "lease-0001", "config.set", nil, now); err != nil {
		t.Fatal(err)
	}
	if err := c.Append("a", "lease-0001", "config.set", nil, now); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")

	cases := map[string]func() []byte{
		"hash": func() []byte {
			return bytes.Replace(raw, []byte(lines[0]), []byte(flipHash(lines[0])), 1)
		},
		"gap": func() []byte {
			return []byte(strings.Replace(string(raw), `"seq":2`, `"seq":3`, 1))
		},
		"prev": func() []byte {
			return []byte(strings.Replace(string(raw), `"prev":"`+Genesis+`"`, `"prev":"`+strings.Repeat("a", 64)+`"`, 1))
		},
		"extra": func() []byte {
			return []byte(strings.Replace(lines[0], `{`, `{"x":1,`, 1) + "\n" + lines[1] + "\n")
		},
		"partial": func() []byte {
			return bytes.TrimSuffix(raw, []byte("\n"))
		},
		"blank": func() []byte {
			return []byte(lines[0] + "\n\n" + lines[1] + "\n")
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, fn(), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyFile(path); codes.Code(err) != codes.AuditBad {
				t.Fatalf("got %v", err)
			}
		})
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(path); err != nil {
		t.Fatal(err)
	}
	// Uppercase hash is audit_bad even when the digest bytes match.
	bad := []byte(upperHash(string(raw)))
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	c2, err := Open(path)
	if err == nil {
		t.Fatal("opened tampered chain")
	}
	if codes.Code(err) != codes.AuditBad {
		t.Fatal(err)
	}
	_ = c2
	ok, err := Open(filepath.Join(dir, "fresh.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ok.path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ok.ReadAll(); codes.Code(err) != codes.AuditBad {
		t.Fatal(err)
	}
	if err := ok.Append("a", "lease-0001", "config.set", nil, now); codes.Code(err) != codes.AuditBad {
		t.Fatal(err)
	}
}

func TestSymlinkChain(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); codes.Code(err) != codes.AuditBad {
		t.Fatal(err)
	}
}

func flipHash(line string) string {
	const key = `"hash":"`
	i := strings.Index(line, key)
	if i < 0 {
		return line
	}
	p := i + len(key)
	b := []byte(line)
	if b[p] == '0' {
		b[p] = '1'
	} else {
		b[p] = '0'
	}
	return string(b)
}

func upperHash(s string) string {
	const key = `"hash":"`
	i := strings.Index(s, key)
	if i < 0 {
		return s
	}
	start := i + len(key)
	for j := start; j < start+64 && j < len(s); j++ {
		if s[j] >= 'a' && s[j] <= 'f' {
			return s[:j] + strings.ToUpper(s[j:j+1]) + s[j+1:]
		}
	}
	return s
}

func threeRows(t *testing.T, path string) []byte {
	t.Helper()
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	for i := 0; i < 3; i++ {
		if err := c.Append("a", "lease-0001", "config.set", nil, now); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAnchorDetectsTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	raw := threeRows(t, path)
	if _, err := os.Stat(filepath.Join(dir, "audit.head")); err != nil {
		t.Fatalf("anchor not written: %v", err)
	}
	lines := strings.SplitAfter(string(raw), "\n")
	// A valid chain of the same length, signed by nobody: only the anchor tells.
	forged := filepath.Join(t.TempDir(), "audit.jsonl")
	c, err := Open(forged)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := c.Append("someone-else", "lease-0002", "config.set", nil, time.Unix(1, 0)); err != nil {
			t.Fatal(err)
		}
	}
	forgedRaw, err := os.ReadFile(forged)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func() error{
		"drop_last": func() error { return os.WriteFile(path, []byte(lines[0]+lines[1]), 0o600) },
		"empty":     func() error { return os.WriteFile(path, nil, 0o600) },
		"deleted":   func() error { return os.Remove(path) },
		"rewritten": func() error { return os.WriteFile(path, forgedRaw, 0o600) },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			if err := fn(); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyFile(path); codes.Code(err) != codes.AuditTruncated {
				t.Fatalf("verify: %v", err)
			}
			if _, err := Open(path); codes.Code(err) != codes.AuditTruncated {
				t.Fatalf("open: %v", err)
			}
		})
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	c2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(lines[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.ReadAll(); codes.Code(err) != codes.AuditTruncated {
		t.Fatalf("readall: %v", err)
	}
	if err := c2.Append("a", "lease-0001", "config.set", nil, time.Unix(1, 0)); codes.Code(err) != codes.AuditBad {
		t.Fatalf("append after truncation: %v", err)
	}
}

func TestAnchorFreshAndCrash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	head := filepath.Join(dir, "audit.head")
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(head); !os.IsNotExist(err) {
		t.Fatalf("fresh store wrote an anchor: %v", err)
	}
	if err := c.Append("a", "lease-0001", "config.set", nil, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(head)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("anchor %v %v", st, err)
	}

	// A crash between the row and the anchor leaves the anchor one behind.
	old, err := os.ReadFile(head)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Append("a", "lease-0001", "config.set", nil, time.Unix(2, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(head, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := VerifyFile(path); err != nil || n != 2 {
		t.Fatalf("behind %d %v", n, err)
	}
	c, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now, err := os.ReadFile(head)
	if err != nil || !bytes.Contains(now, []byte(`"seq":2`)) {
		t.Fatalf("anchor not moved up: %s %v", now, err)
	}
	// Two or more rows past the anchor is not a crash state.
	if err := c.Append("a", "lease-0001", "config.set", nil, time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(head, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(path); codes.Code(err) != codes.AuditTruncated {
		t.Fatalf("gap 2 verify: %v", err)
	}
	if _, err := Open(path); codes.Code(err) != codes.AuditTruncated {
		t.Fatalf("gap 2 open: %v", err)
	}
}

// A chain with no anchor is truncated, not upgraded, at open and at runtime.
func TestMissingAnchorIsTruncated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	head := filepath.Join(dir, "audit.head")
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := c.Append("a", "lease-0001", "config.set", nil, time.Unix(int64(i), 0)); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(head); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(path); codes.Code(err) != codes.AuditTruncated {
		t.Fatalf("verify: %v", err)
	}
	if _, err := Open(path); codes.Code(err) != codes.AuditTruncated {
		t.Fatalf("open: %v", err)
	}
	lines := strings.SplitAfter(string(raw), "\n")
	if err := os.WriteFile(path, []byte(lines[0]+lines[1]), 0o600); err != nil {
		t.Fatal(err)
	}
	if rows, err := c.ReadAll(); codes.Code(err) != codes.AuditTruncated {
		t.Fatalf("runtime: %d rows %v", len(rows), err)
	}
	if err := c.Append("a", "lease-0001", "config.set", nil, time.Unix(9, 0)); codes.Code(err) != codes.AuditBad {
		t.Fatalf("append after truncation: %v", err)
	}

	// Both files gone under a running chain is truncated too.
	dir2 := t.TempDir()
	path2 := filepath.Join(dir2, "audit.jsonl")
	c2, err := Open(path2)
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.Append("a", "lease-0001", "config.set", nil, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path2); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir2, "audit.head")); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.ReadAll(); codes.Code(err) != codes.AuditTruncated {
		t.Fatalf("both gone: %v", err)
	}
}

func TestAnchorCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	head := filepath.Join(dir, "audit.head")
	if n, err := Anchor(path, time.Unix(1, 0)); err != nil || n != 0 {
		t.Fatalf("empty %d %v", n, err)
	}
	if _, err := os.Lstat(head); !os.IsNotExist(err) {
		t.Fatal("empty chain anchored")
	}
	raw := threeRows(t, path)
	if err := os.Remove(head); err != nil {
		t.Fatal(err)
	}
	n, err := Anchor(path, time.Unix(5, 0))
	if err != nil || n != 4 {
		t.Fatalf("anchor %d %v", n, err)
	}
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := c.ReadAll()
	if err != nil || len(rows) != 4 || rows[3].Action != "audit.anchor_init" {
		t.Fatalf("%+v %v", rows, err)
	}
	want := `{"hash":"` + rows[2].Hash + `","seq":3}`
	if string(rows[3].Detail) != want {
		t.Fatalf("detail %s want %s", rows[3].Detail, want)
	}
	if _, err := Anchor(path, time.Unix(6, 0)); codes.Code(err) != codes.AnchorExists {
		t.Fatalf("second anchor: %v", err)
	}
	// A broken chain is not anchored.
	if err := os.Remove(head); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(flipHash(strings.SplitAfter(string(raw), "\n")[0])), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Anchor(path, time.Unix(7, 0)); codes.Code(err) != codes.AuditBad {
		t.Fatalf("broken: %v", err)
	}
	if _, err := os.Lstat(head); !os.IsNotExist(err) {
		t.Fatal("broken chain anchored")
	}
}

func TestStateOpenDoesNotBlockOnFIFO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readAll(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if codes.Code(err) != codes.AuditBad {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked on a FIFO")
	}
}

func TestAnchorBadShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	threeRows(t, path)
	head := filepath.Join(dir, "audit.head")
	good, err := os.ReadFile(head)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"garbage": "nope",
		"extra":   strings.Replace(string(good), "{", `{"x":1,`, 1),
		"zero":    `{"seq":0,"hash":"` + Genesis + `"}`,
		"upper":   `{"seq":1,"hash":"` + strings.Repeat("A", 64) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(head, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyFile(path); codes.Code(err) != codes.AuditBad {
				t.Fatalf("got %v", err)
			}
		})
	}
	if err := os.Remove(head); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "real.head")
	if err := os.WriteFile(real, good, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, head); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(path); codes.Code(err) != codes.AuditBad {
		t.Fatalf("symlink anchor: %v", err)
	}
}

// forgeRow appends a row with a correctly recomputed hash, as a forger would.
func forgeRow(t *testing.T, path string, seq int64, prev string) string {
	t.Helper()
	b := body{Seq: seq, Prev: prev, Time: "2026-01-01T00:00:00Z", Actor: "evil", Action: "config.set", Detail: json.RawMessage(`{}`)}
	raw, err := codes.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	line, err := codes.Marshal(stored{body: b, Hash: hash})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	return hash
}

// Inside a running chain the daemon is the only writer: a forged row past
// what it wrote is not adopted, even within load's one-row crash allowance.
func TestReadAllRefusesForeignTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := c.Append("a", "lease-0001", "config.set", nil, time.Unix(int64(i), 0)); err != nil {
			t.Fatal(err)
		}
	}
	forgeRow(t, path, 4, c.prev)
	if rows, err := c.ReadAll(); codes.Code(err) != codes.AuditTruncated {
		t.Fatalf("adopted forged tail: %d rows %v", len(rows), err)
	}
}

// A tail row rewritten in place (same seq, new hash, anchor rewritten to
// match) is caught by the hash half of the runtime check.
func TestReadAllRefusesRewrittenTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := c.Append("a", "lease-0001", "config.set", nil, time.Unix(int64(i), 0)); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := c.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(raw), "\n")
	if err := os.WriteFile(path, []byte(lines[0]+lines[1]), 0o600); err != nil {
		t.Fatal(err)
	}
	hash := forgeRow(t, path, 3, rows[1].Hash)
	if err := writeHead(HeadPath(path), anchor{Seq: 3, Hash: hash}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFile(path); err != nil {
		t.Fatalf("forgery should verify on disk: %v", err)
	}
	if _, err := c.ReadAll(); codes.Code(err) != codes.AuditTruncated {
		t.Fatalf("rewritten tail: %v", err)
	}
}

// The daemon writes the first row before the anchor; verify retries over
// that window, and still reports a lag that does not resolve.
func TestVerifyRetriesAnchorLag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Append("a", "lease-0001", "config.set", nil, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	head := HeadPath(path)
	good, err := os.ReadFile(head)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(head); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { verifyRetry = nil })
	calls := 0
	verifyRetry = func(int) {
		calls++
		if err := os.WriteFile(head, good, 0o600); err != nil {
			t.Error(err)
		}
	}
	if n, err := VerifyFile(path); err != nil || n != 1 || calls != 1 {
		t.Fatalf("lag that resolves: %d %v calls=%d", n, err, calls)
	}
	if err := os.Remove(head); err != nil {
		t.Fatal(err)
	}
	calls = 0
	verifyRetry = func(int) { calls++ }
	if _, err := VerifyFile(path); codes.Code(err) != codes.AuditTruncated || calls != 2 {
		t.Fatalf("lag that persists: %v calls=%d", err, calls)
	}
}
