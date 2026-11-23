package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"golang.org/x/sys/unix"
)

func wantCode(t *testing.T, err error, code, what string) {
	t.Helper()
	if codes.Code(err) != code {
		t.Fatalf("%s: got %v want %s", what, err, code)
	}
}

func openChain(t *testing.T, dir string, opt Options, keep int) *Chain {
	t.Helper()
	c, err := Open(dir, opt, keep)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func appendN(t *testing.T, c *Chain, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := c.Append("a", "lease-0001", "config.set", nil, time.Unix(int64(i), 0)); err != nil {
			t.Fatal(err)
		}
	}
}

func seg(dir string, n int) string { return segPath(dir, n) }

func headOf(dir string) string { return filepath.Join(dir, HeadName) }

func TestChainAppendAndVerify(t *testing.T) {
	dir := t.TempDir()
	if n, err := VerifyDir(dir); err != nil || n != 0 {
		t.Fatalf("missing: %d %v", n, err)
	}
	c := openChain(t, dir, Options{}, 0)
	if n, err := VerifyDir(dir); err != nil || n != 0 {
		t.Fatalf("empty: %d %v", n, err)
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
	raw, err := os.ReadFile(seg(dir, 1))
	if err != nil || bytes.Contains(raw, []byte(`\u003c`)) || !bytes.Contains(raw, []byte("<x>")) {
		t.Fatalf("escape %s", raw)
	}
	tail, err := c.Tail(1)
	if err != nil || len(tail) != 1 || tail[0].Seq != 2 {
		t.Fatalf("tail %+v %v", tail, err)
	}
	for _, p := range []string{seg(dir, 1), headOf(dir)} {
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %s %v", p, st.Mode())
		}
	}
	if st, err := os.Stat(filepath.Join(dir, SegDir)); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", err)
	}
	if n, err := VerifyDir(dir); err != nil || n != 2 {
		t.Fatalf("verify %d %v", n, err)
	}
}

func TestChainTamper(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, Options{}, 0)
	appendN(t, c, 2)
	path := seg(dir, 1)
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
			_, err := VerifyDir(dir)
			wantCode(t, err, codes.AuditBad, "verify")
			_, err = Open(dir, Options{}, 0)
			wantCode(t, err, codes.AuditBad, "open")
		})
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDir(dir); err != nil {
		t.Fatal(err)
	}
	// Uppercase hash is audit_bad even when the digest bytes match.
	if err := os.WriteFile(path, []byte(upperHash(string(raw))), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = c.ReadAll()
	wantCode(t, err, codes.AuditBad, "runtime")
	err = c.Append("a", "lease-0001", "config.set", nil, time.Unix(9, 0))
	wantCode(t, err, codes.AuditBad, "append after")
}

func TestSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := t.TempDir()
	if err := os.Symlink(real, filepath.Join(dir, SegDir)); err != nil {
		t.Fatal(err)
	}
	_, err := Open(dir, Options{}, 0)
	wantCode(t, err, codes.AuditBad, "segment dir symlink")

	dir2 := t.TempDir()
	c := openChain(t, dir2, Options{}, 0)
	appendN(t, c, 1)
	other := filepath.Join(t.TempDir(), "x.jsonl")
	if err := os.Rename(seg(dir2, 1), other); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, seg(dir2, 1)); err != nil {
		t.Fatal(err)
	}
	_, err = Open(dir2, Options{}, 0)
	wantCode(t, err, codes.AuditBad, "segment symlink")
	_, err = VerifyDir(dir2)
	wantCode(t, err, codes.AuditBad, "verify segment symlink")
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

func TestAnchorDetectsTruncation(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, Options{}, 0)
	appendN(t, c, 3)
	raw, err := os.ReadFile(seg(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(raw), "\n")
	// A valid chain of the same length, signed by nobody: only the anchor tells.
	other := t.TempDir()
	f := openChain(t, other, Options{}, 0)
	for i := 0; i < 3; i++ {
		if err := f.Append("someone-else", "lease-0002", "config.set", nil, time.Unix(1, 0)); err != nil {
			t.Fatal(err)
		}
	}
	forgedRaw, err := os.ReadFile(seg(other, 1))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() error{
		"drop_last": func() error { return os.WriteFile(seg(dir, 1), []byte(lines[0]+lines[1]), 0o600) },
		"empty":     func() error { return os.WriteFile(seg(dir, 1), nil, 0o600) },
		"deleted":   func() error { return os.Remove(seg(dir, 1)) },
		"rewritten": func() error { return os.WriteFile(seg(dir, 1), forgedRaw, 0o600) },
		"dir_gone":  func() error { return os.RemoveAll(filepath.Join(dir, SegDir)) },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			if err := os.MkdirAll(filepath.Join(dir, SegDir), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := fn(); err != nil {
				t.Fatal(err)
			}
			_, err := VerifyDir(dir)
			wantCode(t, err, codes.AuditTruncated, "verify")
			_, err = Open(dir, Options{}, 0)
			wantCode(t, err, codes.AuditTruncated, "open")
		})
	}
	if err := os.WriteFile(seg(dir, 1), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	c2 := openChain(t, dir, Options{}, 0)
	if err := os.WriteFile(seg(dir, 1), []byte(lines[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = c2.ReadAll()
	wantCode(t, err, codes.AuditTruncated, "readall")
	err = c2.Append("a", "lease-0001", "config.set", nil, time.Unix(1, 0))
	wantCode(t, err, codes.AuditBad, "append after truncation")
}

func TestAnchorFreshAndCrash(t *testing.T) {
	dir := t.TempDir()
	head := headOf(dir)
	c := openChain(t, dir, Options{}, 0)
	if _, err := os.Lstat(head); !os.IsNotExist(err) {
		t.Fatalf("fresh store wrote an anchor: %v", err)
	}
	appendN(t, c, 1)
	old, err := os.ReadFile(head)
	if err != nil {
		t.Fatal(err)
	}
	// A crash between the row and the anchor leaves the anchor one behind.
	appendN(t, c, 1)
	if err := os.WriteFile(head, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := VerifyDir(dir); err != nil || n != 2 {
		t.Fatalf("behind %d %v", n, err)
	}
	c = openChain(t, dir, Options{}, 0)
	if now, err := os.ReadFile(head); err != nil || !bytes.Contains(now, []byte(`"seq":2`)) {
		t.Fatalf("anchor not moved up: %s %v", now, err)
	}
	// Two or more rows past the anchor is not a crash state.
	appendN(t, c, 1)
	if err := os.WriteFile(head, old, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = VerifyDir(dir)
	wantCode(t, err, codes.AuditTruncated, "gap 2 verify")
	_, err = Open(dir, Options{}, 0)
	wantCode(t, err, codes.AuditTruncated, "gap 2 open")
}

// A chain with no anchor is truncated, not upgraded, at open and at runtime.
func TestMissingAnchorIsTruncated(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, Options{}, 0)
	appendN(t, c, 5)
	raw, err := os.ReadFile(seg(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(headOf(dir)); err != nil {
		t.Fatal(err)
	}
	_, err = VerifyDir(dir)
	wantCode(t, err, codes.AuditTruncated, "verify")
	_, err = Open(dir, Options{}, 0)
	wantCode(t, err, codes.AuditTruncated, "open")
	lines := strings.SplitAfter(string(raw), "\n")
	if err := os.WriteFile(seg(dir, 1), []byte(lines[0]+lines[1]), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = c.ReadAll()
	wantCode(t, err, codes.AuditTruncated, "runtime")
	err = c.Append("a", "lease-0001", "config.set", nil, time.Unix(9, 0))
	wantCode(t, err, codes.AuditBad, "append after truncation")

	// Everything gone under a running chain is truncated too.
	dir2 := t.TempDir()
	c2 := openChain(t, dir2, Options{}, 0)
	appendN(t, c2, 1)
	if err := os.RemoveAll(filepath.Join(dir2, SegDir)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(headOf(dir2)); err != nil {
		t.Fatal(err)
	}
	_, err = c2.ReadAll()
	wantCode(t, err, codes.AuditTruncated, "all gone")
}

func TestStateOpenDoesNotBlockOnFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan error, 2)
	go func() {
		_, err := readCapped(fifo, 1<<10)
		done <- err
	}()
	go func() {
		_, _, _, err := walk(fifo, 1, Genesis, func(Row, []byte) error { return nil })
		done <- err
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			wantCode(t, err, codes.AuditBad, "fifo")
		case <-time.After(3 * time.Second):
			t.Fatal("blocked on a FIFO")
		}
	}
}

func TestAnchorBadShape(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, Options{}, 0)
	appendN(t, c, 3)
	head := headOf(dir)
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
			_, err := VerifyDir(dir)
			wantCode(t, err, codes.AuditBad, "verify")
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
	_, err = VerifyDir(dir)
	wantCode(t, err, codes.AuditBad, "symlink anchor")
}

// forgeRow appends a row with a correctly recomputed hash, as a forger would.
func forgeRow(t *testing.T, path string, seq int64, prev string) string {
	t.Helper()
	line, hash, err := encode(body{Seq: seq, Prev: prev, Time: "2026-01-01T00:00:00Z", Actor: "evil", Action: "config.set", Detail: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
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
// what it wrote is not adopted, even within the one-row crash allowance.
func TestReadAllRefusesForeignTail(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, Options{}, 0)
	appendN(t, c, 3)
	forgeRow(t, seg(dir, 1), 4, c.prev)
	rows, err := c.ReadAll()
	wantCode(t, err, codes.AuditTruncated, "adopted forged tail")
	_ = rows
}

// A tail row rewritten in place (same seq, new hash, anchor rewritten to
// match) is caught by the hash half of the runtime check.
func TestReadAllRefusesRewrittenTail(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, Options{}, 0)
	appendN(t, c, 3)
	rows, err := c.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(seg(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(raw), "\n")
	if err := os.WriteFile(seg(dir, 1), []byte(lines[0]+lines[1]), 0o600); err != nil {
		t.Fatal(err)
	}
	hash := forgeRow(t, seg(dir, 1), 3, rows[1].Hash)
	if err := writeAtomic(headOf(dir), anchor{Seq: 3, Hash: hash}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDir(dir); err != nil {
		t.Fatalf("forgery should verify on disk: %v", err)
	}
	_, err = c.ReadAll()
	wantCode(t, err, codes.AuditTruncated, "rewritten tail")
}

// The daemon writes the first row before the anchor; verify retries over
// that window, and still reports a lag that does not resolve.
func TestVerifyRetriesAnchorLag(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, Options{}, 0)
	appendN(t, c, 1)
	head := headOf(dir)
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
	if n, err := VerifyDir(dir); err != nil || n != 1 || calls != 1 {
		t.Fatalf("lag that resolves: %d %v calls=%d", n, err, calls)
	}
	if err := os.Remove(head); err != nil {
		t.Fatal(err)
	}
	calls = 0
	verifyRetry = func(int) { calls++ }
	if _, err := VerifyDir(dir); codes.Code(err) != codes.AuditTruncated || calls != 2 {
		t.Fatalf("lag that persists: %v calls=%d", err, calls)
	}
}
