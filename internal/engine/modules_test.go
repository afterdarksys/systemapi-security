package engine

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"github.com/afterdarksys/systemapi-security/internal/modules"
	"github.com/afterdarksys/systemapi-security/internal/store"
)

type moduleFS struct {
	files map[string]string
	fail  bool
}

func (f *moduleFS) OS() string { return "linux" }
func (f *moduleFS) ReadFile(p string) ([]byte, error) {
	if f.fail && p == "/etc/shadow" {
		return nil, fs.ErrPermission
	}
	s, ok := f.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return []byte(s), nil
}
func (f *moduleFS) Metadata(string) (modules.Metadata, error) {
	return modules.Metadata{}, fs.ErrNotExist
}

func TestModuleLifecycleReportAndRestart(t *testing.T) {
	e, dir := newEng(t)
	fixture := &moduleFS{files: map[string]string{"/etc/os-release": "ID=ubuntu\nVERSION_ID=24.04", "/etc/passwd": "root:x:0:0::/root:/bin/sh\nevil:x:0:0::/root:/bin/sh\n", "/etc/shadow": "root:!:1:0:99999:7:::\n"}}
	e.SystemFS = fixture
	cfg := store.Config{Modules: map[string]modules.Config{"ubuntu": {Enabled: true, Checks: []string{"accounts"}}}}
	putJSON(t, e, "module-enable", cfg, coverAll)
	r, err := e.Report()
	if err != nil || !r.ConfigChanged || r.System.Platform.State != "pending" {
		t.Fatalf("%+v %v", r, err)
	}
	found, err := e.Scan("ops", "")
	if err != nil || len(found) != 2 {
		t.Fatalf("%+v %v", found, err)
	}
	r, _ = e.Report()
	if r.ConfigChanged || len(r.Findings) != 2 || r.Schema != "secsvc-report/1" {
		t.Fatalf("%+v", r)
	}
	id := r.Findings[0].ID
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "evil") || strings.Contains(string(b), "root:!") {
		t.Fatal("account data leaked")
	}
	// A failed check retains previous positives even when its readable files look fixed.
	fixture.files["/etc/passwd"] = "root:x:0:0::/root:/bin/sh\n"
	fixture.fail = true
	if _, err = e.Scan("ops", ""); err != nil {
		t.Fatal(err)
	}
	r, _ = e.Report()
	if len(r.Findings) != 2 || r.Findings[0].Observation != "retained" || r.Findings[0].ID != id {
		t.Fatalf("%+v", r)
	}
	reopened, err := store.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.Store = reopened
	r, _ = e.Report()
	if len(r.Findings) != 2 || r.Findings[0].Observation != "retained" {
		t.Fatal("lost report across restart")
	}
	// Complete healthy scan resolves positives.
	fixture.fail = false
	if _, err = e.Scan("ops", ""); err != nil {
		t.Fatal(err)
	}
	r, _ = e.Report()
	if len(r.Findings) != 0 {
		t.Fatal(r.Findings)
	}
	if countAction(actions(t, e), "ids.resolved") != 2 {
		t.Fatal("missing resolution audit")
	}
	// Reintroduce a finding, then explicitly disable: this is withdrawal, not repair.
	fixture.files["/etc/passwd"] += "evil:x:0:0::/root:/bin/sh\n"
	if _, err = e.Scan("ops", ""); err != nil {
		t.Fatal(err)
	}
	putJSON(t, e, "module-disable", store.Config{}, coverAll)
	r, _ = e.Report()
	if !r.ConfigChanged || r.Findings[0].Observation != "stale" {
		t.Fatal("config change not visible")
	}
	if _, err = e.Scan("ops", ""); err != nil {
		t.Fatal(err)
	}
	if countAction(actions(t, e), "ids.withdrawn") != 2 {
		t.Fatal("disabled findings treated as remediation")
	}
}

func TestModuleConfigAuthorizationAndCopies(t *testing.T) {
	e, _ := newEng(t)
	body := []byte(`{"modules":{"debian":{"enabled":true,"checks":["accounts"]}}}`)
	err := e.PutConfig("ops", "denied-enable", expAt(), body, func(string) bool { return false })
	wantCode(t, err, codes.Forbidden)
	if err = e.PutConfig("ops", "denied-enable", expAt(), body, coverAll); err != nil {
		t.Fatalf("refusal spent lease: %v", err)
	}
	got := e.Store.Config()
	got.Modules["debian"].Checks[0] = "kernel"
	if e.Store.Config().Modules["debian"].Checks[0] != "accounts" {
		t.Fatal("config alias")
	}
	if err = e.PutConfig("ops", "denied-disable", expAt(), []byte(`{}`), func(string) bool { return false }); codes.Code(err) != codes.Forbidden {
		t.Fatal("uncovered disable permitted")
	}
	// Unknown profile rejected before spending or probing.
	err = e.PutConfig("ops", "invalid-module", expAt(), []byte(`{"modules":{"unknown":{"enabled":true}}}`), coverAll)
	wantCode(t, err, codes.BadPath)
}
