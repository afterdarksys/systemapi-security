package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/afterdarksys/systemapi-security/internal/grant"
)

func TestModuleAndReportRoutes(t *testing.T) {
	f := newFix(t)
	read := f.sign(t, grant.Grant{Purpose: grant.PurposeRead, Entitlements: []string{grant.EntRead}})
	auditOnly := f.sign(t, grant.Grant{Purpose: grant.PurposeRead, Entitlements: []string{grant.EntAudit}})
	for _, path := range []string{"/v1/modules", "/v1/report"} {
		if got := call(f.srv, http.MethodGet, path, "", ""); got.Code != http.StatusUnauthorized {
			t.Fatal(got.Code)
		}
		if got := call(f.srv, http.MethodGet, path, auditOnly, ""); got.Code != http.StatusForbidden {
			t.Fatal(got.Code)
		}
		got := call(f.srv, http.MethodGet, path, read, "")
		if got.Code != http.StatusOK {
			t.Fatalf("%s: %s", path, got.Body.String())
		}
		var v map[string]json.RawMessage
		if err := json.Unmarshal(got.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		if path == "/v1/report" && string(v["schema"]) != `"secsvc-report/1"` {
			t.Fatal(v)
		}
		if path == "/v1/modules" {
			var profiles []any
			if err := json.Unmarshal(v["profiles"], &profiles); err != nil || len(profiles) != 6 {
				t.Fatalf("%s", got.Body.String())
			}
		}
		if got := call(f.srv, http.MethodPut, path, read, ""); got.Code != http.StatusMethodNotAllowed {
			t.Fatal(got.Code)
		}
	}
}
