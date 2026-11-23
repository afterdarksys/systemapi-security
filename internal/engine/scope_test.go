package engine

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"github.com/afterdarksys/systemapi-security/internal/store"
)

// audit_keep_segments and page_detail govern the state directory: a grant
// that covers only a watched path cannot change them.
func TestStateFieldsNeedStateDirCoverage(t *testing.T) {
	e, dir := newEng(t)
	narrow := func(p string) bool { return p == "/etc/passwd" }
	state := func(p string) bool { return p == dir }
	for i, c := range []store.Config{{AuditKeepSegments: 3}, {PageDetail: true}} {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		lease := "lease-scope" + string(rune('a'+i))
		wantCode(t, e.PutConfig("actor", lease, expAt(), b, narrow), codes.ConfigScope)
		if err := e.PutConfig("actor", lease, expAt(), b, state); err != nil {
			t.Fatal(err)
		}
		if err := e.PutConfig("actor", lease+"x", expAt(), []byte(`{}`), state); err != nil {
			t.Fatal(err)
		}
	}
	if got := e.Store.Config(); got.AuditKeepSegments != 0 || got.PageDetail {
		t.Fatalf("%+v", got)
	}
}

// The full verify does not take the engine lock, so a walk cannot stall
// scans and the API.
func TestVerifyAuditWithoutEngineLock(t *testing.T) {
	e, _ := newEng(t)
	if err := e.Store.AppendAudit("a", "", "config.set", nil, frozen); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := e.VerifyAudit()
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("verify waited for the engine lock")
	}
}
