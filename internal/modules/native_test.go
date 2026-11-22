package modules

import (
	"os"
	"runtime"
	"testing"
)

// Opt-in native/container smoke test. Containers are not full host validation:
// securityfs, MAC policy and PID namespaces commonly differ from a booted host.
func TestNativeContainerSmoke(t *testing.T) {
	expected := os.Getenv("SECSVC_SMOKE_PROFILE")
	if expected == "" {
		t.Skip("set SECSVC_SMOKE_PROFILE on a matching Linux distro")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("native smoke test requires Linux")
	}
	s, found := Scan(HostFS{}, map[string]Config{expected: {Enabled: true}})
	if s.Platform.State != "ok" || s.Platform.Profile != expected {
		t.Fatalf("platform: %+v", s.Platform)
	}
	for _, r := range s.Modules {
		if r.ID != expected {
			if r.State != "disabled" {
				t.Fatalf("unexpected profile activation: %+v", r)
			}
			continue
		}
		if len(r.Checks) == 0 {
			t.Fatal("checks did not run")
		}
		for _, c := range r.Checks {
			if c.State != "ok" && c.State != "degraded" {
				t.Fatalf("check did not run: %+v", c)
			}
		}
		t.Logf("%s %s: %d checks, state=%s, findings=%d", s.Platform.ID, s.Platform.Version, len(r.Checks), r.State, len(found))
	}
}
