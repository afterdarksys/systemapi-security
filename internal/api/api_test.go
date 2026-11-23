package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"github.com/afterdarksys/systemapi-security/internal/engine"
	"github.com/afterdarksys/systemapi-security/internal/grant"
	"github.com/afterdarksys/systemapi-security/internal/notify"
	"github.com/afterdarksys/systemapi-security/internal/store"
)

const topic = "topic-topic-topic-topic"

func frozen() time.Time { return time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC) }

type fix struct {
	srv  *Server
	seed []byte
	dir  string
	now  time.Time
}

func newFix(t *testing.T) *fix {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := frozen()
	seed, pub, err := grant.Generate()
	if err != nil {
		t.Fatal(err)
	}
	eng := &engine.Engine{
		Store: st, Host: "host1", Now: func() time.Time { return now },
		Sender: &notify.Sender{},
	}
	return &fix{
		dir: dir, seed: seed, now: now,
		srv: &Server{Host: "host1", Pub: pub, Eng: eng, Now: func() time.Time { return now }},
	}
}

func (f *fix) sign(t *testing.T, g grant.Grant) string {
	t.Helper()
	if g.V == "" {
		g.V = grant.Version
	}
	if g.Actor == "" {
		g.Actor = "ops"
	}
	if g.Host == "" {
		g.Host = "host1"
	}
	if g.Iat == 0 {
		g.Iat = f.now.Unix()
	}
	if g.Exp == 0 {
		g.Exp = f.now.Unix() + 600
	}
	if g.LeaseID == "" {
		g.LeaseID = "lease-default"
	}
	b, err := grant.Sign(f.seed, g)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func call(s *Server, method, target, doc, body string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "http://secsvc"+target, rdr)
	if doc != "" {
		req.Header.Set(HeaderGrant, doc)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func shell(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.Bytes())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache %q", rec.Header().Get("Cache-Control"))
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("type %q", rec.Header().Get("Content-Type"))
	}
	b := rec.Body.Bytes()
	if len(b) == 0 || b[len(b)-1] != '\n' || strings.Count(string(b), "\n") != 1 {
		t.Fatalf("body %q", b)
	}
}

func errOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json %s: %v", rec.Body.Bytes(), err)
	}
	return body.Error
}

func tamper(doc string) string {
	const key = `"sig":"`
	i := strings.Index(doc, key)
	j := i + len(key)
	c := doc[j]
	n := byte('A')
	if c == 'A' {
		n = 'B'
	}
	return doc[:j] + string(n) + doc[j+1:]
}

func TestRoutingAndGrant(t *testing.T) {
	f := newFix(t)
	read := f.sign(t, grant.Grant{Purpose: grant.PurposeRead, Entitlements: grant.Fill(grant.PurposeRead), LeaseID: "lease-read1"})
	cases := []struct {
		method, target, doc, want string
		status                    int
	}{
		{http.MethodGet, "/missing", "", codes.BadPath, http.StatusNotFound},
		{http.MethodPost, "/missing", "", codes.BadPath, http.StatusNotFound},
		{http.MethodGet, "/v1/status", "", codes.GrantMissing, http.StatusUnauthorized},
		{http.MethodGet, "/v1/status", tamper(read), codes.GrantBadSig, http.StatusUnauthorized},
		{http.MethodPost, "/v1/status", "", codes.Method, http.StatusMethodNotAllowed},
		{http.MethodGet, "/v1/audit?limit=050", "", codes.BadPath, http.StatusBadRequest},
		{http.MethodGet, "/v1/audit?limit=10&x=1", "", codes.BadPath, http.StatusBadRequest},
		{http.MethodGet, "/v1/status?x=1", "", codes.BadPath, http.StatusBadRequest},
		{http.MethodGet, "/v1/audit?limit=201", "", codes.BadPath, http.StatusBadRequest},
	}
	for _, tc := range cases {
		rec := call(f.srv, tc.method, tc.target, tc.doc, "")
		shell(t, rec, tc.status)
		if got := errOf(t, rec); got != tc.want {
			t.Fatalf("%s %s: %s", tc.method, tc.target, got)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "http://secsvc/v1/status", nil)
	req.Header.Set(HeaderGrant, "")
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	shell(t, rec, http.StatusUnauthorized)
	if errOf(t, rec) != codes.GrantMissing {
		t.Fatal(errOf(t, rec))
	}
	req = httptest.NewRequest(http.MethodGet, "http://secsvc/v1/status", nil)
	req.Header.Add(HeaderGrant, read)
	req.Header.Add(HeaderGrant, read)
	rec = httptest.NewRecorder()
	f.srv.ServeHTTP(rec, req)
	shell(t, rec, http.StatusBadRequest)
	if errOf(t, rec) != codes.GrantBadShape {
		t.Fatal(errOf(t, rec))
	}

	rec = call(f.srv, http.MethodGet, "/v1/status", read, "")
	shell(t, rec, http.StatusOK)
	var st engine.Status
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Host != "host1" || st.Listen != "off" || st.OpenFindings != 0 || st.Armed.Auth || st.Armed.Listen {
		t.Fatalf("%+v", st)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"name":"grant_v1"`)) || bytes.Contains(rec.Body.Bytes(), []byte(f.dir)) {
		t.Fatal(rec.Body.String())
	}

	scanOnly := f.sign(t, grant.Grant{Purpose: grant.PurposeOperate, Entitlements: []string{grant.EntScan}, LeaseID: "lease-scan1"})
	rec = call(f.srv, http.MethodGet, "/v1/status", scanOnly, "")
	shell(t, rec, http.StatusForbidden)
	if errOf(t, rec) != codes.Forbidden {
		t.Fatal(errOf(t, rec))
	}
	over := f.sign(t, grant.Grant{Purpose: grant.PurposeRead, Entitlements: []string{grant.EntRead, grant.EntScan}, LeaseID: "lease-over1"})
	rec = call(f.srv, http.MethodGet, "/v1/status", over, "")
	shell(t, rec, http.StatusBadRequest)
	if errOf(t, rec) != codes.GrantPurpose {
		t.Fatal(errOf(t, rec))
	}
	star := f.sign(t, grant.Grant{Purpose: grant.PurposeOperate, Entitlements: []string{"*"}, LeaseID: "lease-star1"})
	rec = call(f.srv, http.MethodGet, "/v1/status", star, "")
	shell(t, rec, http.StatusBadRequest)
	if errOf(t, rec) != codes.GrantStar {
		t.Fatal(errOf(t, rec))
	}
	root := f.sign(t, grant.Grant{Purpose: grant.PurposeRead, Entitlements: grant.Fill(grant.PurposeRead), Watch: []string{"/"}, LeaseID: "lease-root1"})
	rec = call(f.srv, http.MethodGet, "/v1/status", root, "")
	shell(t, rec, http.StatusBadRequest)
	if errOf(t, rec) != codes.GrantRootSlash {
		t.Fatal(errOf(t, rec))
	}
	far := f.sign(t, grant.Grant{Purpose: grant.PurposeRead, Entitlements: grant.Fill(grant.PurposeRead), Exp: f.now.Unix() + 901, LeaseID: "lease-ttl01"})
	rec = call(f.srv, http.MethodGet, "/v1/status", far, "")
	shell(t, rec, http.StatusBadRequest)
	if errOf(t, rec) != codes.GrantTTL {
		t.Fatal(errOf(t, rec))
	}
	old := f.sign(t, grant.Grant{Purpose: grant.PurposeRead, Entitlements: grant.Fill(grant.PurposeRead), Exp: f.now.Unix(), LeaseID: "lease-exp01"})
	rec = call(f.srv, http.MethodGet, "/v1/status", old, "")
	shell(t, rec, http.StatusUnauthorized)
	if errOf(t, rec) != codes.GrantExpired {
		t.Fatal(errOf(t, rec))
	}
	other := f.sign(t, grant.Grant{Host: "otherhost", Purpose: grant.PurposeRead, Entitlements: grant.Fill(grant.PurposeRead), LeaseID: "lease-host1"})
	rec = call(f.srv, http.MethodGet, "/v1/status", other, "")
	shell(t, rec, http.StatusForbidden)
	if errOf(t, rec) != codes.GrantHost {
		t.Fatal(errOf(t, rec))
	}

	rec = call(f.srv, http.MethodGet, "/v1/audit", read, "")
	shell(t, rec, http.StatusOK)
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"rows":[]`)) {
		t.Fatal(rec.Body.String())
	}
	rec = call(f.srv, http.MethodGet, "/v1/audit?limit=1", read, "")
	shell(t, rec, http.StatusOK)
	rec = call(f.srv, http.MethodGet, "/v1/audit/verify", read, "")
	shell(t, rec, http.StatusOK)
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"ok":true`)) || !bytes.Contains(rec.Body.Bytes(), []byte(`"rows":0`)) {
		t.Fatal(rec.Body.String())
	}

	rec = call(f.srv, http.MethodGet, "/v1/catalog", read, "")
	shell(t, rec, http.StatusOK)
	var cat struct {
		Service       string   `json:"service"`
		Grant         string   `json:"grant"`
		NotifyContact string   `json:"notify_contact"`
		Entitlements  []string `json:"entitlements"`
		Routes        []route  `json:"routes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cat); err != nil {
		t.Fatal(err)
	}
	if cat.Service != "secsvc" || cat.Grant != grant.Version || cat.NotifyContact != "push:ntfy" {
		t.Fatalf("%+v", cat)
	}
	if strings.Contains(rec.Body.String(), "ntfy.sh") || strings.Contains(rec.Body.String(), "https://") || strings.Contains(rec.Body.String(), topic) {
		t.Fatal(rec.Body.String())
	}
	if !reflect.DeepEqual(cat.Entitlements, grant.Ceiling(grant.PurposeOperate)) {
		t.Fatalf("ents %v", cat.Entitlements)
	}
	if !reflect.DeepEqual(cat.Routes, routeTable()) {
		t.Fatalf("routes %+v", cat.Routes)
	}
	for i := 1; i < len(cat.Routes); i++ {
		a, b := cat.Routes[i-1], cat.Routes[i]
		if a.Path > b.Path || (a.Path == b.Path && a.Method > b.Method) {
			t.Fatalf("unsorted %s %s then %s %s", a.Method, a.Path, b.Method, b.Path)
		}
	}
}

func TestConfigContactAndAudit(t *testing.T) {
	f := newFix(t)
	allowed := filepath.Join(f.dir, "allowed")
	if err := os.Mkdir(allowed, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(f.dir, "secret")
	if err := os.WriteFile(secret, []byte("secret-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.dir, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(allowed, "auth.log")
	if err := os.WriteFile(logPath, []byte("ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	op := f.sign(t, grant.Grant{
		Purpose: grant.PurposeOperate, Entitlements: grant.Fill(grant.PurposeOperate),
		Watch: []string{allowed}, LeaseID: "lease-op001",
	})
	ro := f.sign(t, grant.Grant{Purpose: grant.PurposeRead, Entitlements: grant.Fill(grant.PurposeRead), LeaseID: "lease-ro0001"})
	rec := call(f.srv, http.MethodPut, "/v1/contact", ro, "not-json")
	shell(t, rec, http.StatusForbidden)
	if errOf(t, rec) != codes.Forbidden {
		t.Fatal(errOf(t, rec))
	}
	rec = call(f.srv, http.MethodPut, "/v1/config", ro, `{"auth_fail_limit":9}`)
	shell(t, rec, http.StatusForbidden)
	if errOf(t, rec) != codes.Forbidden {
		t.Fatal(errOf(t, rec))
	}
	rec = call(f.srv, http.MethodGet, "/v1/config", ro, "")
	shell(t, rec, http.StatusOK)
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"auth_fail_limit":5`)) {
		t.Fatal(rec.Body.String())
	}

	raw, err := json.Marshal(map[string]string{"auth_log": link})
	if err != nil {
		t.Fatal(err)
	}
	rec = call(f.srv, http.MethodPut, "/v1/config", op, string(raw))
	shell(t, rec, http.StatusForbidden)
	if errOf(t, rec) != codes.Forbidden || bytes.Contains(rec.Body.Bytes(), []byte("secret-bytes")) || bytes.Contains(rec.Body.Bytes(), []byte(link)) {
		t.Fatal(rec.Body.String())
	}
	raw, err = json.Marshal(map[string]string{"auth_log": logPath})
	if err != nil {
		t.Fatal(err)
	}
	rec = call(f.srv, http.MethodPut, "/v1/config", op, string(raw))
	shell(t, rec, http.StatusOK)
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"ok":true`)) {
		t.Fatal(rec.Body.String())
	}
	rec = call(f.srv, http.MethodGet, "/v1/config", ro, "")
	shell(t, rec, http.StatusOK)
	if !bytes.Contains(rec.Body.Bytes(), []byte(logPath)) {
		t.Fatal(rec.Body.String())
	}
	rec = call(f.srv, http.MethodPut, "/v1/config", op, `{}`)
	shell(t, rec, http.StatusForbidden)
	if errOf(t, rec) != codes.GrantSpent {
		t.Fatal(errOf(t, rec))
	}

	exact := append([]byte("{}"), bytes.Repeat([]byte(" "), BodyMax-2)...)
	if len(exact) != BodyMax {
		t.Fatal(len(exact))
	}
	wide := f.sign(t, grant.Grant{
		Purpose: grant.PurposeOperate, Entitlements: []string{grant.EntConfig},
		Watch: []string{allowed}, LeaseID: "lease-size1",
	})
	rec = call(f.srv, http.MethodPut, "/v1/config", wide, string(append(exact, ' ')))
	shell(t, rec, http.StatusBadRequest)
	if errOf(t, rec) != codes.Oversized {
		t.Fatal(errOf(t, rec))
	}
	rec = call(f.srv, http.MethodPut, "/v1/config", wide, string(exact))
	shell(t, rec, http.StatusOK)

	rec = call(f.srv, http.MethodPut, "/v1/contact", op, "not-json")
	shell(t, rec, http.StatusBadRequest)
	if errOf(t, rec) != codes.BadPath {
		t.Fatal(errOf(t, rec))
	}
	rec = call(f.srv, http.MethodPut, "/v1/contact", op, `{"contact":""}`)
	shell(t, rec, http.StatusBadRequest)
	if errOf(t, rec) != codes.BadContact {
		t.Fatal(errOf(t, rec))
	}
	var lookups int
	var mu sync.Mutex
	ip := net.ParseIP("10.1.2.3")
	f.srv.Eng.Sender = &notify.Sender{Lookup: func(ctx context.Context, network, host string) ([]net.IP, error) {
		if host != "ntfy.sh" {
			t.Errorf("lookup host %s", host)
		}
		mu.Lock()
		lookups++
		cur := append(net.IP(nil), ip...)
		mu.Unlock()
		return []net.IP{cur}, nil
	}}
	contact := notify.Prefix + notify.Base + topic
	body, err := json.Marshal(map[string]string{"contact": contact})
	if err != nil {
		t.Fatal(err)
	}
	nt := f.sign(t, grant.Grant{
		Purpose: grant.PurposeOperate, Entitlements: grant.Fill(grant.PurposeOperate),
		Watch: []string{allowed}, LeaseID: "lease-ntfy01",
	})
	rec = call(f.srv, http.MethodPut, "/v1/contact", nt, string(body))
	shell(t, rec, http.StatusBadRequest)
	if errOf(t, rec) != codes.BlockedAddress {
		t.Fatal(errOf(t, rec))
	}
	ip = net.ParseIP("1.1.1.1")
	rec = call(f.srv, http.MethodPut, "/v1/contact", nt, string(body))
	shell(t, rec, http.StatusOK)
	mu.Lock()
	n := lookups
	mu.Unlock()
	if n != 2 {
		t.Fatalf("lookups %d", n)
	}
	rec = call(f.srv, http.MethodGet, "/v1/config", op, "")
	shell(t, rec, http.StatusOK)
	if bytes.Contains(rec.Body.Bytes(), []byte(topic)) || bytes.Contains(rec.Body.Bytes(), []byte("ntfy.sh")) {
		t.Fatal(rec.Body.String())
	}
	var view store.ConfigView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.ContactState != "set" || view.ContactSHA256 != notify.Fingerprint(contact) {
		t.Fatalf("%+v", view)
	}
	rec = call(f.srv, http.MethodGet, "/v1/audit?limit=50", op, "")
	shell(t, rec, http.StatusOK)
	if bytes.Contains(rec.Body.Bytes(), []byte(topic)) || bytes.Contains(rec.Body.Bytes(), []byte("ntfy.sh")) || bytes.Contains(rec.Body.Bytes(), []byte("secret-bytes")) {
		t.Fatal(rec.Body.String())
	}
	var auditBody struct {
		Rows []auditRow `json:"rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &auditBody); err != nil {
		t.Fatal(err)
	}
	var sets int
	for _, row := range auditBody.Rows {
		if row.Action == "notify.set" {
			sets++
			if row.LeaseID != "lease-ntfy01" || !bytes.Contains(row.Detail, []byte(view.ContactSHA256)) {
				t.Fatalf("%+v", row)
			}
		}
	}
	if sets != 1 {
		t.Fatalf("notify.set %d", sets)
	}
	disk, err := os.ReadFile(filepath.Join(f.dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disk, []byte(topic)) || bytes.Contains(disk, []byte("ntfy.sh")) {
		t.Fatal("topic in audit")
	}
	if err := os.WriteFile(filepath.Join(f.dir, "audit.jsonl"), []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec = call(f.srv, http.MethodGet, "/v1/audit", op, "")
	shell(t, rec, http.StatusInternalServerError)
	if errOf(t, rec) != codes.AuditBad || bytes.Contains(rec.Body.Bytes(), []byte("tampered")) {
		t.Fatal(rec.Body.String())
	}
}

func TestScanAndBaseline(t *testing.T) {
	f := newFix(t)
	g := f.sign(t, grant.Grant{
		Purpose: grant.PurposeOperate, Entitlements: grant.Fill(grant.PurposeOperate), LeaseID: "lease-base1",
	})
	rec := call(f.srv, http.MethodPost, "/v1/baseline", g, "x")
	shell(t, rec, http.StatusBadRequest)
	if errOf(t, rec) != codes.BadPath {
		t.Fatal(errOf(t, rec))
	}
	rec = call(f.srv, http.MethodPost, "/v1/baseline", g, "")
	shell(t, rec, http.StatusOK)
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"ok":true`)) {
		t.Fatal(rec.Body.String())
	}
	rec = call(f.srv, http.MethodPost, "/v1/baseline", g, "")
	shell(t, rec, http.StatusForbidden)
	if errOf(t, rec) != codes.GrantSpent {
		t.Fatal(errOf(t, rec))
	}
	rec = call(f.srv, http.MethodPost, "/v1/scan", g, "z")
	shell(t, rec, http.StatusBadRequest)
	if errOf(t, rec) != codes.BadPath {
		t.Fatal(errOf(t, rec))
	}
	// The baseline spent lease-base1, so a scan on the same grant is refused.
	rec = call(f.srv, http.MethodPost, "/v1/scan", g, "")
	shell(t, rec, http.StatusForbidden)
	if errOf(t, rec) != codes.GrantSpent {
		t.Fatal(errOf(t, rec))
	}
	sg := f.sign(t, grant.Grant{
		Purpose: grant.PurposeOperate, Entitlements: []string{grant.EntScan}, LeaseID: "lease-scan1",
	})
	rec = call(f.srv, http.MethodPost, "/v1/scan", sg, "")
	shell(t, rec, http.StatusOK)
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"findings":[]`)) {
		t.Fatal(rec.Body.String())
	}
	rec = call(f.srv, http.MethodPost, "/v1/scan", sg, "")
	shell(t, rec, http.StatusForbidden)
	if errOf(t, rec) != codes.GrantSpent {
		t.Fatal(errOf(t, rec))
	}
	rec = call(f.srv, http.MethodGet, "/v1/findings", g, "")
	shell(t, rec, http.StatusOK)
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"findings":[]`)) {
		t.Fatal(rec.Body.String())
	}
}

func TestClientIgnoresProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	c := NewClient("/tmp/secsvc-no-such")
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Fatal("proxy func")
	}
	u, err := tr.Proxy(&http.Request{URL: &url.URL{Scheme: "http", Host: "secsvc"}})
	if err != nil || u != nil {
		t.Fatalf("proxy %v %v", u, err)
	}
	if c.Timeout != clientTimeout {
		t.Fatal(c.Timeout)
	}
}

func writePub(t *testing.T, path string) {
	t.Helper()
	_, pub, err := grant.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(grant.PubHex(pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestServeRefusesEarly(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		r.Close()
		w.Close()
		setOrderHook(nil)
	})
	t.Setenv(readyEnv, strconv.Itoa(int(w.Fd())))
	dir := filepath.Join(t.TempDir(), "state")
	err = Serve(context.Background(), Options{Dir: dir, Interval: time.Second, Host: "host1", PubPath: filepath.Join(dir, "missing"), Socket: "/tmp/not-used"})
	if codes.Code(err) != codes.Usage {
		t.Fatal(codes.Code(err))
	}
	if _, statErr := os.Lstat(dir); !os.IsNotExist(statErr) {
		t.Fatal("dir created")
	}
	if err := r.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, readErr := r.Read(make([]byte, 4))
	if n != 0 || !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatalf("ready byte %d %v", n, readErr)
	}

	base := t.TempDir()
	pub := filepath.Join(base, "pub.hex")
	writePub(t, pub)
	state := filepath.Join(base, "state")
	sockDir, err := os.MkdirTemp("/tmp", "ss")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "sock")
	if err := os.WriteFile(sock, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = Serve(context.Background(), Options{Dir: state, PubPath: pub, Host: "host1", Socket: sock, Interval: DefaultInterval})
	if codes.Code(err) != codes.BadSocket {
		t.Fatal(codes.Code(err))
	}
	if err := r.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, readErr = r.Read(make([]byte, 4))
	if n != 0 || !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatalf("ready after bad socket %d %v", n, readErr)
	}

	link := filepath.Join(sockDir, "link")
	if err := os.Symlink(sock, link); err != nil {
		t.Fatal(err)
	}
	err = Serve(context.Background(), Options{Dir: state, PubPath: pub, Host: "host1", Socket: link, Interval: DefaultInterval})
	if codes.Code(err) != codes.BadSocket {
		t.Fatal(codes.Code(err))
	}
	if fi, statErr := os.Lstat(link); statErr != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink removed")
	}

	okSock := filepath.Join(sockDir, "ok")
	t.Setenv(readyEnv, "nope")
	err = Serve(context.Background(), Options{Dir: state, PubPath: pub, Host: "host1", Socket: okSock, Interval: DefaultInterval})
	if codes.Code(err) != codes.ReadyFailed {
		t.Fatal(codes.Code(err))
	}
	if _, statErr := os.Lstat(okSock); !os.IsNotExist(statErr) {
		t.Fatal("socket left after ready failure")
	}
}

func TestServeReadyAndStale(t *testing.T) {
	sockDir, err := os.MkdirTemp("/tmp", "ss")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	parent := filepath.Join(sockDir, "run")
	sock := filepath.Join(parent, "sock")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(parent)
	if err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		r.Close()
		w.Close()
		setOrderHook(nil)
	})
	t.Setenv(readyEnv, strconv.Itoa(int(w.Fd())))
	heard := make(chan struct{})
	bad := make(chan string, 1)
	var mu sync.Mutex
	var steps []string
	setOrderHook(func(step string) {
		mu.Lock()
		steps = append(steps, step)
		mu.Unlock()
		if step != "listen" {
			return
		}
		if err := r.SetReadDeadline(time.Now().Add(40 * time.Millisecond)); err != nil {
			bad <- err.Error()
			close(heard)
			return
		}
		buf := make([]byte, 8)
		n, err := r.Read(buf)
		if n > 0 || (err != nil && !errors.Is(err, os.ErrDeadlineExceeded)) {
			bad <- fmt.Sprintf("early %d %v %q", n, err, buf[:n])
		}
		if err := r.SetReadDeadline(time.Time{}); err != nil {
			bad <- err.Error()
		}
		close(heard)
	})

	base := t.TempDir()
	pub := filepath.Join(base, "pub.hex")
	writePub(t, pub)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errc := make(chan error, 1)
	go func() {
		errc <- Serve(ctx, Options{
			Dir: filepath.Join(base, "state"), PubPath: pub, Host: "host1",
			Socket: sock, Interval: DefaultInterval,
		})
	}()
	select {
	case <-heard:
	case <-time.After(3 * time.Second):
		t.Fatal("listen hook")
	}
	select {
	case msg := <-bad:
		t.Fatal(msg)
	default:
	}
	if err := r.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, err := r.Read(buf)
	if err != nil || n != 1 || buf[0] != '\n' {
		t.Fatalf("ready %d %v %q", n, err, buf[:n])
	}
	c := NewClient(sock)
	resp, err := c.Get("http://secsvc/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized || !bytes.Contains(body, []byte(`"error":"grant_missing"`)) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal(resp.Header.Get("Cache-Control"))
	}
	fi, err := os.Lstat(sock)
	if err != nil || fi.Mode().Perm() != 0o660 || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("sock mode %v %v", fi, err)
	}
	after, err := os.Lstat(parent)
	if err != nil || after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("parent mode %v -> %v", before.Mode().Perm(), after.Mode().Perm())
	}
	mu.Lock()
	got := strings.Join(steps, ",")
	mu.Unlock()
	if got != "validate,store,listen,ready" {
		t.Fatal(got)
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown")
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Fatal("socket remains", err)
	}
}

func TestServeCreatesParent(t *testing.T) {
	sockDir, err := os.MkdirTemp("/tmp", "ss")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	parent := filepath.Join(sockDir, "run")
	sock := filepath.Join(parent, "sock")
	base := t.TempDir()
	pub := filepath.Join(base, "pub.hex")
	writePub(t, pub)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errc := make(chan error, 1)
	go func() {
		errc <- Serve(ctx, Options{
			Dir: filepath.Join(base, "state"), PubPath: pub, Host: "host1",
			Socket: sock, Interval: MinInterval,
		})
	}()
	var dialErr error
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c := NewClient(sock)
		resp, err := c.Get("http://secsvc/v1/status")
		if err == nil {
			resp.Body.Close()
			dialErr = nil
			break
		}
		dialErr = err
		time.Sleep(20 * time.Millisecond)
	}
	if dialErr != nil {
		t.Fatal(dialErr)
	}
	fi, err := os.Lstat(parent)
	if err != nil || fi.Mode().Perm() != 0o750 || !fi.IsDir() {
		t.Fatalf("parent %v %v", fi, err)
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown")
	}
}

func TestRealHostIsNotPlaceholder(t *testing.T) {
	for _, h := range []string{"host1", "web-1.example.com", "localhostx", "my-localhost"} {
		if placeholderHost(h) {
			t.Errorf("%q refused", h)
		}
	}
}

func TestServeRefusesPlaceholderHost(t *testing.T) {
	for _, host := range []string{"", "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "localhost6", "a.localhost", "127.0.0.1", "10.0.0.5", "1.2.3.4"} {
		dir := filepath.Join(t.TempDir(), "state")
		err := Serve(context.Background(), Options{Dir: dir, Interval: DefaultInterval, Host: host, PubPath: filepath.Join(dir, "missing"), Socket: "/tmp/not-used"})
		if codes.Code(err) != codes.HostUnset {
			t.Fatalf("%q: %v", host, err)
		}
		if _, statErr := os.Lstat(dir); !os.IsNotExist(statErr) {
			t.Fatalf("%q: state dir created", host)
		}
	}
}
