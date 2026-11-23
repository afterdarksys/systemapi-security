package engine

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"github.com/afterdarksys/systemapi-security/internal/ids"
	"github.com/afterdarksys/systemapi-security/internal/notify"
	"github.com/afterdarksys/systemapi-security/internal/store"
)

const pageHost = "web-07.example.net"

// changedWatch configures a watched file, a contact, and a listener outside
// the allow list, then changes the file, so the next scan has two high
// findings of different kinds.
func changedWatch(t *testing.T, detail bool, c *capture, status int) (*Engine, string) {
	t.Helper()
	e, dir := newEng(t)
	e.Host = pageHost
	p := filepath.Join(dir, "shadow-copy")
	writeFile(t, p, "one")
	putJSON(t, e, "lease-cfgp", map[string]any{"watch": []string{p}, "listen_allow": []string{"127.0.0.1:22"}, "page_detail": detail}, coverAll)
	if err := e.Baseline("actor", "lease-basep", expAt(), coverAll); err != nil {
		t.Fatal(err)
	}
	e.Proc = func() (string, string, bool, error) { return listenFixture("0100007F:1F90"), "", false, nil }
	e.Sender = c.sender(publicIP(), nil, status)
	if err := e.PutContact("actor", "lease-ntfyp", expAt(), notify.Prefix+notify.Base+topic); err != nil {
		t.Fatal(err)
	}
	writeFile(t, p, "two")
	return e, p
}

// R3: by default a page names a kind, a count and an opaque reference only.
func TestDefaultPageHasNoHostDetail(t *testing.T) {
	c := &capture{}
	e, p := changedWatch(t, false, c, 200)
	found, err := e.Scan("secsvc", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	drainPages(e)
	if c.posts != 2 {
		t.Fatalf("posts %d", c.posts)
	}
	refs := map[string]bool{}
	for _, f := range found {
		if f.Severity == ids.SevHigh {
			refs[f.PageID] = true
		}
	}
	for _, body := range c.bodies {
		for _, banned := range []string{pageHost, "web-07", "example", p, filepath.Dir(p), "shadow-copy", "127.0.0.1", "8080", "localhost"} {
			if strings.Contains(body, banned) {
				t.Fatalf("page %q contains %q", body, banned)
			}
		}
		i := strings.LastIndex(body, "ref ")
		if i < 0 || !refs[body[i+4:]] || !strings.HasPrefix(body, "secsvc high ") || !strings.Contains(body, ": 2 high finding(s) open") {
			t.Fatalf("page %q refs %v", body, refs)
		}
	}
	// The reference stays with the finding locally.
	open, err := e.Findings()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range open {
		if f.Severity == ids.SevHigh && !refs[f.PageID] {
			t.Fatalf("finding %+v", f)
		}
	}
	b, _ := json.Marshal(open)
	if !strings.Contains(string(b), `"page_id"`) {
		t.Fatal(string(b))
	}
}

func TestPageDetailRestoresHost(t *testing.T) {
	c := &capture{}
	e, p := changedWatch(t, true, c, 200)
	if _, err := e.Scan("secsvc", "", 0); err != nil {
		t.Fatal(err)
	}
	drainPages(e)
	joined := strings.Join(c.bodies, "\n")
	if !strings.Contains(joined, "secsvc integrity_changed on "+pageHost+": "+p) || !strings.Contains(joined, "127.0.0.1:8080") {
		t.Fatalf("bodies %q", c.bodies)
	}
}

// R4: a failed send is audited page.failed and unpaged, so the next scan
// pages again.
func TestFailedPageRetries(t *testing.T) {
	c := &capture{}
	e, _ := changedWatch(t, false, c, 500)
	if _, err := e.Scan("secsvc", "", 0); err != nil {
		t.Fatal(err)
	}
	drainPages(e)
	if c.posts != 2 || countAction(actions(t, e), "page.failed") != 2 || countAction(actions(t, e), "page.sent") != 0 {
		t.Fatalf("posts %d actions %v", c.posts, actions(t, e))
	}
	st := e.Store.IDS()
	for _, rec := range st.Open {
		if rec.Severity == ids.SevHigh && rec.Paged {
			t.Fatalf("still paged %+v", rec)
		}
	}
	if len(st.Coalesce) != 0 {
		t.Fatalf("coalesce kept %v", st.Coalesce)
	}
	ok := &capture{}
	e.Sender = ok.sender(publicIP(), nil, 200)
	if _, err := e.Scan("secsvc", "", 0); err != nil {
		t.Fatal(err)
	}
	drainPages(e)
	if ok.posts != 2 || countAction(actions(t, e), "page.sent") != 2 {
		t.Fatalf("retry posts %d actions %v", ok.posts, actions(t, e))
	}
}

func TestPageQueueFull(t *testing.T) {
	c := &capture{}
	e, _ := changedWatch(t, false, c, 200)
	for i := 0; i < pageQueueMax; i++ {
		e.queue() <- pageJob{kind: "filler"}
	}
	if _, err := e.Scan("secsvc", "", 0); err != nil {
		t.Fatal(err)
	}
	rows, err := e.Audit(0)
	if err != nil {
		t.Fatal(err)
	}
	full := 0
	for _, r := range rows {
		if r.Action == "page.failed" && strings.Contains(string(r.Detail), codes.QueueFull) {
			full++
		}
	}
	if full != 2 {
		t.Fatalf("queue_full rows %d", full)
	}
	for _, rec := range e.Store.IDS().Open {
		if rec.Severity == ids.SevHigh && rec.Paged {
			t.Fatalf("paged with a full queue %+v", rec)
		}
	}
}

// restart opens a second engine on the same state directory, as a new
// process would after a stop or a crash.
func restart(t *testing.T, e *Engine, c *capture) *Engine {
	t.Helper()
	st, err := store.Open(e.Store.Dir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Engine{Store: st, Host: e.Host, Now: e.Now, Proc: e.Proc, Sender: c.sender(publicIP(), nil, 200)}
}

func assertPending(t *testing.T, e *Engine, pending bool) {
	t.Helper()
	n := 0
	for _, rec := range e.Store.IDS().Open {
		if rec.Severity != ids.SevHigh {
			continue
		}
		n++
		if rec.Pending != pending || rec.Paged == pending {
			t.Fatalf("pending=%v want %v paged=%v", rec.Pending, pending, rec.Paged)
		}
	}
	if n != 2 {
		t.Fatalf("high findings %d", n)
	}
}

// A crash after the scan commits and before the pager sends: the pages are
// pending on disk, not paged, and the next start sends them.
func TestCrashAfterCommitResendsPages(t *testing.T) {
	c := &capture{}
	e, _ := changedWatch(t, false, c, 200)
	if _, err := e.Scan("secsvc", "", 0); err != nil {
		t.Fatal(err)
	}
	assertPending(t, e, true)
	sent := &capture{}
	e2 := restart(t, e, sent)
	if err := e2.Resume(); err != nil {
		t.Fatal(err)
	}
	drainPages(e2)
	if sent.posts != 2 || c.posts != 0 {
		t.Fatalf("resent %d first %d", sent.posts, c.posts)
	}
	assertPending(t, e2, false)
	// Sent pages are not sent again.
	if err := e2.Resume(); err != nil {
		t.Fatal(err)
	}
	drainPages(e2)
	if sent.posts != 2 {
		t.Fatalf("posts %d", sent.posts)
	}
}

// Shutdown during a scan: the pager is stopped after the scan returns and
// leaves what is queued pending, not failed; the next start sends it.
func TestShutdownMidScanKeepsPages(t *testing.T) {
	c := &capture{}
	e, _ := changedWatch(t, false, c, 200)
	if _, err := e.Scan("secsvc", "", 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		e.Pager(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pager did not stop")
	}
	if c.posts != 0 || countAction(actions(t, e), "page.failed") != 0 {
		t.Fatalf("posts %d actions %v", c.posts, actions(t, e))
	}
	assertPending(t, e, true)
	sent := &capture{}
	e2 := restart(t, e, sent)
	if err := e2.Resume(); err != nil {
		t.Fatal(err)
	}
	drainPages(e2)
	if sent.posts != 2 || countAction(actions(t, e2), "page.sent") != 2 {
		t.Fatalf("posts %d actions %v", sent.posts, actions(t, e2))
	}
	assertPending(t, e2, false)
}
