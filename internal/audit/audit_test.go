package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
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
