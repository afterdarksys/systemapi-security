package engine

import (
	"encoding/json"
	"testing"

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
