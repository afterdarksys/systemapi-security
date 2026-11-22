package caps

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestProbeFreshAndClosed(t *testing.T) {
	got := Probe(Env{})
	if len(got) != len(registry) || len(registry) > maxTokens {
		t.Fatalf("len %d registry %d", len(got), len(registry))
	}
	prev := ""
	for _, r := range got {
		if r.Name <= prev || !nameRE.MatchString(r.Name) || strings.Contains(r.Name, ".") {
			t.Fatalf("name %q", r.Name)
		}
		prev = r.Name
		switch r.Name {
		case "grant_v1":
			if r.State != StateOK || r.Reason != "" {
				t.Fatalf("%+v", r)
			}
		case "audit":
			if r.State != StateDegraded || r.Reason != ReasonProbeError {
				t.Fatalf("%+v", r)
			}
		default:
			if r.State != StateAbsent || r.Reason != ReasonFlagOff {
				t.Fatalf("%+v", r)
			}
		}
	}
	if nameRE.MatchString("security.read") || nameRE.MatchString("grant/1") {
		t.Fatal("grammar accepted an entitlement")
	}
}

func TestProbeMapsSentinels(t *testing.T) {
	env := Env{
		Audit:     func() error { return ErrAudit },
		Auth:      func() error { return ErrMissing },
		Integrity: func() error { return ErrUnreadable },
		Listen:    func() error { return ErrUnsupported },
		Notify:    func() error { return ErrContact },
	}
	by := index(t, Probe(env))
	want(t, by["audit"], StateDegraded, ReasonAuditBad)
	want(t, by["auth"], StateDegraded, ReasonTargetMissing)
	want(t, by["integrity"], StateDegraded, ReasonUnreadable)
	want(t, by["listen"], StateAbsent, ReasonUnsupportedOS)
	want(t, by["notify"], StateDegraded, ReasonBadContact)
	want(t, by["grant_v1"], StateOK, "")

	env.Notify = func() error { return ErrOff }
	by = index(t, Probe(env))
	want(t, by["notify"], StateAbsent, ReasonFlagOff)

	env.Auth = func() error { return nil }
	by = index(t, Probe(env))
	want(t, by["auth"], StateOK, "")
}

func TestProbeDropsHostText(t *testing.T) {
	secret := "/var/log/auth.log"
	contact := "push:ntfy:https://ntfy.sh/topic-topic-topic-topic"
	addr := "127.0.0.1:80"
	env := Env{
		Auth:   func() error { return errors.New(secret) },
		Notify: func() error { return errors.New(contact) },
		Listen: func() error { return errors.New(addr) },
	}
	raw := mustJSON(t, Probe(env))
	for _, s := range []string{secret, contact, addr, "ntfy.sh", "topic-topic"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Fatalf("leaked %s in %s", s, raw)
		}
	}
	by := index(t, Probe(env))
	want(t, by["auth"], StateDegraded, ReasonProbeError)
	want(t, by["notify"], StateDegraded, ReasonProbeError)
	want(t, by["listen"], StateDegraded, ReasonProbeError)
}

func TestBoundStripsForgedResults(t *testing.T) {
	in := []Result{
		{Name: "auth", State: StateOK, Reason: "/var/log/auth.log"},
		{Name: "notify", State: StateDegraded, Reason: "push:ntfy:https://ntfy.sh/topic-topic-topic-topic"},
		{Name: "listen", State: "owned", Reason: "127.0.0.1:22"},
		{Name: "not_a_cap", State: StateOK, Reason: "flag_off"},
		{Name: "grant/1", State: StateOK},
	}
	raw := mustJSON(t, bound(in))
	for _, s := range []string{"/var/log", "ntfy.sh", "127.0.0.1", "owned", "not_a_cap", "grant/1"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Fatalf("kept %s in %s", s, raw)
		}
	}
	by := index(t, bound(in))
	want(t, by["auth"], StateOK, "")
	want(t, by["notify"], StateDegraded, ReasonProbeError)
	want(t, by["listen"], StateDegraded, ReasonProbeError)
	if len(by) != 3 {
		t.Fatalf("%d results", len(by))
	}
}

func TestBoundTruncates(t *testing.T) {
	in := make([]Result, 20)
	for i := range in {
		in[i] = Result{Name: "auth", State: StateOK}
	}
	if got := bound(in); len(got) != maxTokens {
		t.Fatalf("len %d", len(got))
	}
}

func index(t *testing.T, rows []Result) map[string]Result {
	t.Helper()
	out := make(map[string]Result, len(rows))
	for _, r := range rows {
		out[r.Name] = r
	}
	return out
}

func want(t *testing.T, r Result, state, reason string) {
	t.Helper()
	if r.State != state || r.Reason != reason {
		t.Fatalf("%s state %q reason %q, want %s %s", r.Name, r.State, r.Reason, state, reason)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
