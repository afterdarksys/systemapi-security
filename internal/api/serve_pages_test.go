package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/engine"
	"github.com/afterdarksys/systemapi-security/internal/ids"
	"github.com/afterdarksys/systemapi-security/internal/notify"
	"github.com/afterdarksys/systemapi-security/internal/store"
)

type recorder struct {
	mu    sync.Mutex
	posts int
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.posts
}

func (r *recorder) sender() *notify.Sender {
	return &notify.Sender{
		Lookup: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		},
		Post: func(context.Context, *http.Request, []string) (*http.Response, error) {
			r.mu.Lock()
			r.posts++
			r.mu.Unlock()
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("x"))}, nil
		},
	}
}

// pagesDir is a state directory with a contact and a baselined watched file
// that has changed, so the first scan finds one high finding to page.
func pagesDir(t *testing.T, listen bool) (base, dir string) {
	t.Helper()
	base = t.TempDir()
	dir = filepath.Join(base, "state")
	st, err := store.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(base, "watched")
	if err := os.WriteFile(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := store.Config{Watch: []string{p}}
	if listen {
		cfg.ListenAllow = []string{"127.0.0.1:22"}
	}
	if err := st.PutConfig(cfg); err != nil {
		t.Fatal(err)
	}
	rec, err := ids.Measure(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutBaseline(map[string]ids.Record{p: rec}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutContact(notify.Prefix + notify.Base + topic); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	return base, dir
}

// serveWith runs Serve on dir with hook applied to its engine and returns a
// stop function that waits for Serve to return.
func serveWith(t *testing.T, base, dir string, hook func(*engine.Engine)) (stop func()) {
	t.Helper()
	sockDir, err := os.MkdirTemp("/tmp", "ss")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	pub := filepath.Join(base, "pub.hex")
	if _, err := os.Stat(pub); err != nil {
		writePub(t, pub)
	}
	engineHook = hook
	t.Cleanup(func() { engineHook = nil })
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- Serve(ctx, Options{Dir: dir, PubPath: pub, Host: "host1", Socket: filepath.Join(sockDir, "s"), Interval: time.Hour})
	}()
	return func() {
		cancel()
		select {
		case err := <-errc:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("serve did not stop")
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// highState reports the one high finding's pending and paged flags.
func highState(t *testing.T, dir string) (pending, paged bool) {
	t.Helper()
	st, err := store.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, rec := range st.IDS().Open {
		if rec.Severity == ids.SevHigh {
			n++
			pending, paged = rec.Pending, rec.Paged
		}
	}
	if n != 1 {
		t.Fatalf("high findings %d", n)
	}
	return pending, paged
}

// A page committed as pending by an earlier run is sent when Serve starts.
func TestServeResendsPendingPages(t *testing.T) {
	base, dir := pagesDir(t, false)
	st, err := store.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := &recorder{}
	eng := &engine.Engine{Store: st, Host: "host1", Sender: first.sender()}
	if _, err := eng.Scan("secsvc", "", 0); err != nil {
		t.Fatal(err)
	}
	// The crash: the scan committed, no pager ever ran.
	if pending, paged := highState(t, dir); !pending || paged {
		t.Fatalf("pending=%v paged=%v", pending, paged)
	}
	sent := &recorder{}
	stop := serveWith(t, base, dir, func(e *engine.Engine) { e.Sender = sent.sender() })
	waitFor(t, "pending page never sent after restart", func() bool { return sent.count() == 1 })
	stop()
	if pending, paged := highState(t, dir); pending || !paged || first.count() != 0 || sent.count() != 1 {
		t.Fatalf("pending=%v paged=%v posts %d %d", pending, paged, first.count(), sent.count())
	}
}

// SIGTERM while a scan runs: the scan finishes, its page is not lost, and
// the next start sends it.
func TestServeShutdownMidScanKeepsPages(t *testing.T) {
	base, dir := pagesDir(t, true)
	inScan := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	sent := &recorder{}
	stop := serveWith(t, base, dir, func(e *engine.Engine) {
		e.Sender = sent.sender()
		e.Proc = func() (string, string, bool, error) {
			once.Do(func() { close(inScan) })
			<-release
			hdr := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
			return hdr + "   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 0 1 0000000000000000 100 0 0 10 0\n", "", false, nil
		}
	})
	select {
	case <-inScan:
	case <-time.After(5 * time.Second):
		t.Fatal("first scan never started")
	}
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()
	time.Sleep(100 * time.Millisecond) // shutdown is under way, the scan is not done
	close(release)
	<-done
	pending, paged := highState(t, dir)
	if !pending && !paged {
		t.Fatal("page lost at shutdown")
	}
	if !paged {
		again := &recorder{}
		stop = serveWith(t, base, dir, func(e *engine.Engine) {
			e.Sender = again.sender()
			e.Proc = func() (string, string, bool, error) { return "", "", false, nil }
		})
		waitFor(t, "kept page never sent", func() bool { return again.count() == 1 })
		stop()
	}
	if pending, paged := highState(t, dir); pending || !paged {
		t.Fatalf("pending=%v paged=%v", pending, paged)
	}
}
