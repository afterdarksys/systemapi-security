package ids

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"golang.org/x/sys/unix"
)

func TestScanAuth(t *testing.T) {
	dir := t.TempDir()
	logp := filepath.Join(dir, "auth.log")
	now := time.Unix(1_700_000_000, 0).UTC()
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(logp, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("Accepted password for root from 1.2.3.4 port 22\nFailed password for root from 9.9.9.9 port 22\n")
	off, ev, f := ScanAuth(logp, 0, nil, 5, 300, now)
	if f != nil || len(ev) != 1 || off == 0 {
		t.Fatalf("under %+v %d %d", f, len(ev), off)
	}
	// Four more failures cross the limit of 5. Accepted is not a failure.
	more := "Accepted publickey for root\n"
	for i := 0; i < 4; i++ {
		more += "Failed password for root from 1.2.3.4 port 22\n"
	}
	write("Accepted password for root from 1.2.3.4 port 22\nFailed password for root from 9.9.9.9 port 22\n" + more)
	off, ev, f = ScanAuth(logp, 0, nil, 5, 300, now)
	if f == nil || f.Kind != KindAuth || f.Severity != SevHigh || f.Subject != KindAuth {
		t.Fatalf("%+v", f)
	}
	if f.Summary != "5 failures from 9.9.9.9" {
		t.Fatal(f.Summary)
	}
	if strings.Contains(f.Summary, "Failed password") {
		t.Fatal(f.Summary)
	}
	// Second scan from the new offset adds nothing.
	_, ev2, f2 := ScanAuth(logp, off, ev, 5, 300, now)
	if f2 == nil || len(ev2) != len(ev) {
		t.Fatalf("still %d %+v", len(ev2), f2)
	}
	// Lowercase does not match. rhost= supplies the IP.
	write("failed password for root\nauthentication failure; rhost=8.8.8.8\nInvalid user bob\nFailed publickey for root from 8.8.4.4 port 22\n")
	_, _, f = ScanAuth(logp, 0, nil, 3, 300, now)
	if f == nil || f.Summary != "3 failures from 8.8.8.8" {
		t.Fatalf("%+v", f)
	}
	// No IP in this scan.
	write("Failed password for nobody\n")
	_, _, f = ScanAuth(logp, 0, nil, 1, 300, now)
	if f == nil || f.Summary != "1 failures" {
		t.Fatalf("%+v", f)
	}
	// Window drops old events and keeps an equal age.
	old := []int64{now.Unix() - 301, now.Unix() - 300}
	_, ev, f = ScanAuth(logp, 0, old, 2, 300, now.Add(time.Hour))
	// file still has 1 line but now is an hour later, so the line's event is "now" of this call.
	// Use the same now as the timestamps' base by passing now, and a log with no new lines.
	write("")
	_, ev, f = ScanAuth(logp, 0, old, 2, 300, now)
	if f != nil || len(ev) != 1 || ev[0] != now.Unix()-300 {
		t.Fatalf("window %+v %v", f, ev)
	}
	// No newline: advance over the window and match nothing.
	raw := []byte("Failed password for root from 1.1.1.1 port 1")
	if err := os.WriteFile(logp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	off, ev, f = ScanAuth(logp, 0, nil, 1, 300, now)
	if f != nil || len(ev) != 0 || off != int64(len(raw)) {
		t.Fatalf("partial %d %v %+v", off, ev, f)
	}
	// A later complete line is read. The skipped partial stays skipped.
	if err := os.WriteFile(logp, append(raw, []byte("\nFailed password for root from 1.1.1.1 port 1\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	_, ev, f = ScanAuth(logp, off, nil, 1, 300, now)
	if f == nil || f.Summary != "1 failures from 1.1.1.1" {
		t.Fatalf("%+v %v", f, ev)
	}
	// Over-long line is skipped.
	long := strings.Repeat("A", LineMax+1) + " Failed password for root from 1.2.3.4 port 1\n"
	if err := os.WriteFile(logp, []byte(long), 0o600); err != nil {
		t.Fatal(err)
	}
	_, ev, f = ScanAuth(logp, 0, nil, 1, 300, now)
	if f != nil || len(ev) != 0 {
		t.Fatalf("long %+v %d", f, len(ev))
	}
	// Symlink is unavailable and the target is not read.
	target := filepath.Join(dir, "target")
	body := strings.Repeat("Failed password for root from 1.2.3.4 port 1\n", 10)
	if err := os.WriteFile(target, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	off, ev, f = ScanAuth(link, 7, []int64{now.Unix()}, 1, 300, now)
	if f == nil || f.Kind != KindAuthNA || f.Summary != "auth log unavailable" || f.Subject != KindAuthNA {
		t.Fatalf("%+v", f)
	}
	if off != 7 || len(ev) != 1 || strings.Contains(f.Summary, target) {
		t.Fatalf("kept %d %v %s", off, ev, f.Summary)
	}
	// Directory and missing are unavailable.
	if _, _, f = ScanAuth(dir, 0, nil, 1, 300, now); f == nil || f.Kind != KindAuthNA {
		t.Fatal(f)
	}
	if _, _, f = ScanAuth(filepath.Join(dir, "missing"), 0, nil, 1, 300, now); f == nil || f.Kind != KindAuthNA {
		t.Fatal(f)
	}
	// Cap keeps newest and still fires.
	var many []int64
	for i := 0; i < EventsMax+10; i++ {
		many = append(many, now.Unix())
	}
	write("")
	_, ev, f = ScanAuth(logp, 0, many, EventsMax, 300, now)
	if f == nil || len(ev) != EventsMax {
		t.Fatalf("cap %d %+v", len(ev), f)
	}
}

func TestIntegrity(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("one"), 0o640); err != nil {
		t.Fatal(err)
	}
	if f := Check(p, nil); f.Kind != KindBase || f.Severity != SevMedium {
		t.Fatal(f)
	}
	rec, err := Measure(p)
	if err != nil || rec.Size != 3 || rec.Mode != unix.S_IFREG|0o640 || rec.UID != uint32(os.Getuid()) || rec.GID != uint32(os.Getgid()) || len(rec.SHA256) != 64 {
		t.Fatalf("%+v %v", rec, err)
	}
	if f := Check(p, &rec); f.Kind != "" {
		t.Fatal(f)
	}
	if err := os.WriteFile(p, []byte("two"), 0o640); err != nil {
		t.Fatal(err)
	}
	f := Check(p, &rec)
	if f.Kind != KindChange || f.Severity != SevHigh || f.Subject != p {
		t.Fatal(f)
	}
	if err := os.WriteFile(p, []byte("one"), 0o640); err != nil {
		t.Fatal(err)
	}
	if f := Check(p, &rec); f.Kind != "" {
		t.Fatal(f)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if f := Check(p, &rec); f.Kind != KindChange {
		t.Fatal(f)
	}
	missing := filepath.Join(dir, "nope")
	if f := Check(missing, nil); f.Kind != KindBase || f.Severity != SevMedium {
		t.Fatal(f)
	}
	if f := Check(missing, &rec); f.Kind != KindMiss || f.Severity != SevHigh {
		t.Fatal(f)
	}
	if _, err := Measure(missing); codes.Code(err) != codes.BadPath {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if f := Check(sub, nil); f.Kind != KindNotReg || f.Severity != SevMedium {
		t.Fatal(f)
	}
	if f := Check(sub, &rec); f.Kind != KindNotReg || f.Severity != SevHigh {
		t.Fatal(f)
	}
	if _, err := Measure(sub); codes.Code(err) != codes.BadPath {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "tgt")
	if err := os.WriteFile(target, []byte("one"), 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	f = Check(link, &rec)
	if f.Kind != KindLink || f.Severity != SevHigh || f.Summary == rec.SHA256 {
		t.Fatal(f)
	}
	if _, err := Measure(link); codes.Code(err) != codes.BadPath {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, FileMax+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if f := Check(big, nil); f.Kind != KindBig || f.Severity != SevMedium {
		t.Fatal(f)
	}
	if f := Check(big, &rec); f.Kind != KindBig || f.Severity != SevHigh {
		t.Fatal(f)
	}
	if _, err := Measure(big); codes.Code(err) != codes.BadPath {
		t.Fatal(err)
	}
}

func TestListen(t *testing.T) {
	v4 := func(ip string, port int) string {
		t.Helper()
		b := net.ParseIP(ip).To4()
		return fmt.Sprintf("%02X%02X%02X%02X:%04X", b[3], b[2], b[1], b[0], port)
	}
	line := func(addr, st string) string {
		return fmt.Sprintf("   0: %s 00000000:0000 %s 00000000:00000000 00:00000000 00000000 0 0 0 1 0000000000000000 100 0 0 10 0", addr, st)
	}
	hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	tcp := hdr + line(v4("127.0.0.1", 22), "0A") + "\n" + line(v4("0.0.0.0", 22), "01") + "\n" + line(v4("0.0.0.0", 22), "0A") + "\n"
	tcp6 := "   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0 1 0000000000000000 100 0 0 10 0\n"
	tcp6 += "   1: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0 1 0000000000000000 100 0 0 10 0\n"
	if st, _ := Detect(nil, "not-proc", "", false, nil); st != StateOff {
		t.Fatal(st)
	}
	if st, _ := Detect(nil, "", "", true, codes.E(codes.Failed)); st != StateOff {
		t.Fatal(st)
	}
	st, got := Detect([]string{"127.0.0.1:22"}, tcp, tcp6, false, nil)
	if st != StateOK {
		t.Fatal(st)
	}
	var subs []string
	for _, f := range got {
		subs = append(subs, f.Subject)
		if f.Kind != KindListen || f.Severity != SevHigh {
			t.Fatal(f)
		}
	}
	if strings.Join(subs, ",") != "0.0.0.0:22,[::1]:22,[::]:22" {
		t.Fatalf("%v", subs)
	}
	// 127.0.0.1:22 is allowlisted and state 01 is ignored.
	for _, s := range subs {
		if s == "127.0.0.1:22" {
			t.Fatal("allowlisted")
		}
	}
	st, got = Detect([]string{"0.0.0.0:22"}, tcp, "", false, nil)
	if st != StateOK || len(got) != 1 || got[0].Subject != "127.0.0.1:22" {
		t.Fatalf("%s %+v", st, got)
	}
	if st, _ := Detect([]string{"127.0.0.1:22"}, "", "", true, nil); st != StateBad {
		t.Fatal(st)
	}
	if st, _ := Detect([]string{"127.0.0.1:22"}, "", "", false, codes.E(codes.Failed)); st != StateBad {
		t.Fatal(st)
	}
	// Z is not hex, so the line would be skipped. A short host still matches
	// the address pattern and must fail decode.
	bad := hdr + line("ABCDEF:0016", "0A") + "\n"
	if st, got := Detect([]string{"127.0.0.1:22"}, bad, "", false, nil); st != StateBad || got != nil {
		t.Fatalf("%s %+v", st, got)
	}
	// tcp6 empty while tcp is readable is ok.
	st, got = Detect([]string{"127.0.0.1:22", "0.0.0.0:22"}, tcp, "", false, nil)
	if st != StateOK || len(got) != 0 {
		t.Fatalf("%s %+v", st, got)
	}
	var b strings.Builder
	b.WriteString(hdr)
	for port := 1; port <= 20; port++ {
		b.WriteString(line(v4("10.0.0.1", port), "0A"))
		b.WriteByte('\n')
	}
	st, got = Detect([]string{"127.0.0.1:1"}, b.String(), "", false, nil)
	if st != StateOK || len(got) != ListenCap+1 {
		t.Fatalf("%s %d", st, len(got))
	}
	if got[len(got)-1].Kind != KindTrunc || got[len(got)-1].Severity != SevMedium || got[len(got)-1].Subject != KindTrunc {
		t.Fatal(got[len(got)-1])
	}
	// Subject sort is lexical, so :1,:10..:19,:2,:20,:3,:4,:5 are the first 16.
	if got[0].Subject != "10.0.0.1:1" || got[15].Subject != "10.0.0.1:5" {
		t.Fatalf("%s %s", got[0].Subject, got[15].Subject)
	}
}

// withDeadline fails the test instead of hanging when fn blocks.
func withDeadline(t *testing.T, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked on a special file")
	}
}

func TestFIFODoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	// The opens are what must not block: call them past the Lstat guard.
	withDeadline(t, func() {
		if _, err := hashOpen(fifo); codes.Code(err) != codes.NotRegular {
			t.Errorf("hashOpen: %v", err)
		}
		if _, _, err := openRegular(fifo); codes.Code(err) != codes.NotRegular {
			t.Errorf("openRegular: %v", err)
		}
		if f := Check(fifo, &Record{SHA256: strings.Repeat("a", 64)}); f.Kind != KindNotReg || f.Severity != SevHigh {
			t.Errorf("check: %+v", f)
		}
		_, _, f := ScanAuth(fifo, 0, nil, 5, 300, time.Unix(1_700_000_000, 0))
		if f == nil || f.Kind != KindAuthNA {
			t.Errorf("auth: %+v", f)
		}
	})
}

func TestIntegrityFullMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("one"), 0o750); err != nil {
		t.Fatal(err)
	}
	rec, err := Measure(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o750 | os.ModeSetuid, 0o750 | os.ModeSetgid, 0o750 | os.ModeSticky} {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if f := Check(p, &rec); f.Kind != KindChange || f.Severity != SevHigh || f.Summary != "mode or owner changed" {
			t.Fatalf("%v: %+v", mode, f)
		}
	}
	if err := os.Chmod(p, 0o750); err != nil {
		t.Fatal(err)
	}
	if f := Check(p, &rec); f.Kind != "" {
		t.Fatal(f)
	}
	for name, edit := range map[string]func(r *Record){
		"uid":  func(r *Record) { r.UID++ },
		"gid":  func(r *Record) { r.GID++ },
		"type": func(r *Record) { r.Mode = r.Mode&^unix.S_IFMT | unix.S_IFIFO },
	} {
		r := rec
		edit(&r)
		if f := Check(p, &r); f.Kind != KindChange {
			t.Fatalf("%s: %+v", name, f)
		}
	}
}

func TestUpgradeKeepsV1Fields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := os.WriteFile(p, []byte("one"), 0o640|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o640|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	cur, err := Measure(p)
	if err != nil {
		t.Fatal(err)
	}
	v1 := Record{SHA256: cur.SHA256, Mode: 0o640, Size: cur.Size}
	up := Upgrade(p, v1)
	if up != cur {
		t.Fatalf("upgrade %+v want %+v", up, cur)
	}
	if f := Check(p, &up); f.Kind != "" {
		t.Fatal(f)
	}
	// A content change made before the upgrade still shows after it.
	stale := Record{SHA256: strings.Repeat("a", 64), Mode: 0o640, Size: cur.Size}
	if f := Check(p, ptr(Upgrade(p, stale))); f.Kind != KindChange {
		t.Fatal(f)
	}
	// So does a permission change.
	if f := Check(p, ptr(Upgrade(p, Record{SHA256: cur.SHA256, Mode: 0o600, Size: cur.Size}))); f.Kind != KindChange {
		t.Fatal(f)
	}
	// An unreadable path keeps a regular type with uid and gid 0.
	gone := Upgrade(filepath.Join(dir, "nope"), v1)
	if gone.Mode != unix.S_IFREG|0o640 || gone.UID != 0 || gone.GID != 0 || gone.SHA256 != v1.SHA256 {
		t.Fatalf("%+v", gone)
	}
}

func ptr(r Record) *Record { return &r }
