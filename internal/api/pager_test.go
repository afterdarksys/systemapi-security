package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/grant"
	"github.com/afterdarksys/systemapi-security/internal/notify"
)

func TestWriteTimeoutIsTenSeconds(t *testing.T) {
	if srv := newHTTPServer(nil); srv.WriteTimeout != 10*time.Second || srv.ReadTimeout != 10*time.Second {
		t.Fatalf("timeouts %v %v", srv.WriteTimeout, srv.ReadTimeout)
	}
}

// R4: a scan answers once its findings are committed. A page stuck at ntfy
// does not hold the response, so it arrives inside the write timeout.
func TestSlowPageDoesNotDelayScan(t *testing.T) {
	defer func(d time.Duration) { writeTimeout = d }(writeTimeout)
	// Long enough for a scan's own fsyncs on a slow or busy disk, and
	// shorter than the 5s send timeout a synchronous page would wait out.
	writeTimeout = 3 * time.Second

	f := newFix(t)
	eng := f.srv.Eng
	release := make(chan struct{})
	eng.Sender = &notify.Sender{
		Lookup: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		},
		Post: func(ctx context.Context, _ *http.Request, _ []string) (*http.Response, error) {
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("x"))}, nil
		},
	}
	watched := filepath.Join(f.dir, "watched")
	if err := os.WriteFile(watched, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	all := func(string) bool { return true }
	exp := f.now.Unix() + 600
	if err := eng.PutConfig("ops", "lease-cfg001", exp, []byte(`{"watch":["`+watched+`"]}`), all); err != nil {
		t.Fatal(err)
	}
	if err := eng.Baseline("ops", "lease-base01", exp, all); err != nil {
		t.Fatal(err)
	}
	if err := eng.PutContact("ops", "lease-ntfy01", exp, notify.Prefix+notify.Base+topic); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(watched, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	pagerDone := make(chan struct{})
	go func() {
		eng.Pager(ctx)
		close(pagerDone)
	}()
	// The pager writes to the state directory; it must be gone before the
	// test's temporary directories are removed.
	defer func() {
		cancel()
		<-pagerDone
	}()
	sockDir, err := os.MkdirTemp("", "secsvc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "s")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer(f.srv)
	go srv.Serve(ln)
	defer srv.Close()

	doc := f.sign(t, grant.Grant{Purpose: grant.PurposeOperate, Entitlements: []string{grant.EntScan}, LeaseID: "lease-scan01"})
	req, err := http.NewRequest(http.MethodPost, "http://secsvc/v1/scan", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(HeaderGrant, doc)
	start := time.Now()
	resp, err := NewClient(sock).Do(req)
	if err != nil {
		t.Fatalf("scan cut off: %v", err)
	}
	body, rerr := io.ReadAll(resp.Body)
	resp.Body.Close()
	elapsed := time.Since(start)
	if rerr != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "integrity_changed") {
		t.Fatalf("scan %d %q %v", resp.StatusCode, body, rerr)
	}
	if elapsed >= writeTimeout {
		t.Fatalf("scan took %v, write timeout %v", elapsed, writeTimeout)
	}

	// The page is still pending, then goes out and is audited.
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows, err := eng.Audit(0)
		if err != nil {
			t.Fatal(err)
		}
		if n := len(rows); n > 0 && rows[n-1].Action == "page.sent" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("page.sent never audited")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
