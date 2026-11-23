// Package api is the secsvc HTTP service on a Unix socket.
//
// Threats: a missing, forged, expired, over-long, star, root, or wrong-host
// grant is refused before a mutation. A grant that lacks the route entitlement
// is forbidden before the body is parsed. Socket mode is not authentication.
// The ready byte is written only after Listen. Transport.Proxy is a function
// because a nil Proxy honors HTTPS_PROXY. Contact URLs and grant documents are
// not written to responses or logs. An unknown path is refused before auth.
package api

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"github.com/afterdarksys/systemapi-security/internal/engine"
	"github.com/afterdarksys/systemapi-security/internal/grant"
	"github.com/afterdarksys/systemapi-security/internal/ids"
	"github.com/afterdarksys/systemapi-security/internal/modules"
	"github.com/afterdarksys/systemapi-security/internal/notify"
	"github.com/afterdarksys/systemapi-security/internal/paths"
	"github.com/afterdarksys/systemapi-security/internal/store"
	"golang.org/x/sys/unix"
)

const (
	HeaderGrant     = "X-Secsvc-Grant"
	BodyMax         = 64 << 10
	HeaderMax       = 32 << 10
	MinInterval     = 5 * time.Second
	DefaultInterval = 30 * time.Second
	clientTimeout   = 10 * time.Second
	shutdownWait    = 5 * time.Second

	defaultAuditLimit = 50
	maxAuditLimit     = 200
	readyEnv          = "SAHINIT_READY_FD"
	// verifyEvery is the least time between two full verifies.
	verifyEvery = time.Minute
)

// Server verifies grants and calls the engine. It does not start the scan loop.
type Server struct {
	Host string
	Pub  ed25519.PublicKey
	Eng  *engine.Engine
	Now  func() time.Time

	verifyMu   sync.Mutex
	lastVerify time.Time
}

type route struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Entitlement string `json:"entitlement"`
}

type auditRow struct {
	Seq     int64           `json:"seq"`
	Prev    string          `json:"prev"`
	Time    string          `json:"time"`
	Actor   string          `json:"actor"`
	LeaseID string          `json:"lease_id"`
	Action  string          `json:"action"`
	Detail  json.RawMessage `json:"detail"`
	Hash    string          `json:"hash"`
}

// Options is the daemon configuration. Interval must be at least MinInterval.
type Options struct {
	Dir      string
	PubPath  string
	Host     string
	Socket   string
	Interval time.Duration
	Now      func() time.Time
}

var (
	hookMu    sync.Mutex
	orderHook func(step string)
)

func note(step string) {
	hookMu.Lock()
	h := orderHook
	hookMu.Unlock()
	if h != nil {
		h(step)
	}
}

func setOrderHook(h func(step string)) {
	hookMu.Lock()
	orderHook = h
	hookMu.Unlock()
}

func (s *Server) now() time.Time {
	if s != nil && s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func routeTable() []route {
	rows := []route{
		{http.MethodGet, "/v1/audit", grant.EntAudit},
		{http.MethodGet, "/v1/audit/verify", grant.EntAudit},
		{http.MethodGet, "/v1/audit/head", grant.EntAudit},
		{http.MethodPost, "/v1/audit/witness", grant.EntWitness},
		{http.MethodPost, "/v1/baseline", grant.EntBaseline},
		{http.MethodGet, "/v1/catalog", grant.EntRead},
		{http.MethodGet, "/v1/config", grant.EntRead},
		{http.MethodPut, "/v1/config", grant.EntConfig},
		{http.MethodPut, "/v1/contact", grant.EntNotify},
		{http.MethodGet, "/v1/findings", grant.EntRead},
		{http.MethodPost, "/v1/scan", grant.EntScan},
		{http.MethodGet, "/v1/status", grant.EntRead},
		{http.MethodGet, "/v1/modules", grant.EntRead},
		{http.MethodGet, "/v1/report", grant.EntRead},
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Path != rows[j].Path {
			return rows[i].Path < rows[j].Path
		}
		return rows[i].Method < rows[j].Method
	})
	return rows
}

func findRoute(method, path string) (route, bool, bool) {
	var hit route
	known := false
	for _, rt := range routeTable() {
		if rt.Path != path {
			continue
		}
		known = true
		if rt.Method == method {
			hit = rt
		}
	}
	if hit.Path == "" {
		return route{}, known, false
	}
	return hit, true, true
}

// ServeHTTP is the host API. Unknown paths and wrong methods are decided
// before the grant is read. The body is read only after the entitlement check.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt, known, ok := findRoute(r.Method, r.URL.Path)
	if !known {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": codes.BadPath})
		return
	}
	if !ok {
		writeErr(w, codes.Method)
		return
	}
	limit, err := limitOf(r)
	if err != nil {
		writeCode(w, err)
		return
	}
	if s == nil || s.Eng == nil {
		writeErr(w, codes.Failed)
		return
	}
	g, err := s.authorize(r)
	if err != nil {
		writeCode(w, err)
		return
	}
	if !g.Has(rt.Entitlement) {
		writeErr(w, codes.Forbidden)
		return
	}
	switch rt.Path {
	case "/v1/catalog":
		s.catalog(w)
	case "/v1/modules":
		p, c := modules.Catalog()
		writeJSON(w, http.StatusOK, struct {
			Profiles []modules.Profile `json:"profiles"`
			Checks   []modules.Check   `json:"checks"`
		}{p, c})
	case "/v1/report":
		s.writeCall(w, func() (any, error) { return s.Eng.Report() })
	case "/v1/status":
		s.writeCall(w, func() (any, error) { return s.Eng.Status() })
	case "/v1/config":
		if r.Method == http.MethodGet {
			s.writeCall(w, func() (any, error) { return s.Eng.Config() })
			return
		}
		s.putConfig(w, r, g)
	case "/v1/contact":
		s.putContact(w, r, g)
	case "/v1/findings":
		s.findings(w, g, false)
	case "/v1/scan":
		s.postEmpty(w, r, func() error {
			s.findings(w, g, true)
			return nil
		})
	case "/v1/baseline":
		s.postEmpty(w, r, func() error {
			if err := s.Eng.Baseline(g.Actor, g.LeaseID, g.Exp, g.Covers); err != nil {
				return err
			}
			writeOK(w)
			return nil
		})
	case "/v1/audit":
		s.audit(w, limit)
	case "/v1/audit/verify":
		s.verify(w)
	case "/v1/audit/head":
		s.writeCall(w, func() (any, error) { return s.Eng.AuditHead() })
	case "/v1/audit/witness":
		body, err := readBody(w, r)
		if err != nil {
			writeCode(w, err)
			return
		}
		if err := s.Eng.Witness(g.Actor, g.LeaseID, g.Exp, body); err != nil {
			writeCode(w, err)
			return
		}
		writeOK(w)
	default:
		writeErr(w, codes.Failed)
	}
}

func (s *Server) authorize(r *http.Request) (*grant.Grant, error) {
	vals := r.Header.Values(HeaderGrant)
	if len(vals) > 1 {
		return nil, codes.E(codes.GrantBadShape)
	}
	if len(vals) == 0 || vals[0] == "" {
		return nil, codes.E(codes.GrantMissing)
	}
	return grant.Verify(vals[0], s.Pub, s.Host, s.now())
}

func (s *Server) catalog(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, struct {
		Service       string   `json:"service"`
		Grant         string   `json:"grant"`
		NotifyContact string   `json:"notify_contact"`
		Entitlements  []string `json:"entitlements"`
		Routes        []route  `json:"routes"`
	}{
		Service: "secsvc", Grant: grant.Version, NotifyContact: "push:ntfy",
		Entitlements: grant.Ceiling(grant.PurposeOperate), Routes: routeTable(),
	})
}

func (s *Server) writeCall(w http.ResponseWriter, fn func() (any, error)) {
	v, err := fn()
	if err != nil {
		writeCode(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) putConfig(w http.ResponseWriter, r *http.Request, g *grant.Grant) {
	body, err := readBody(w, r)
	if err != nil {
		writeCode(w, err)
		return
	}
	if err := s.Eng.PutConfig(g.Actor, g.LeaseID, g.Exp, body, g.Covers); err != nil {
		writeCode(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) putContact(w http.ResponseWriter, r *http.Request, g *grant.Grant) {
	body, err := readBody(w, r)
	if err != nil {
		writeCode(w, err)
		return
	}
	raw, err := contactValue(body)
	if err != nil {
		writeCode(w, err)
		return
	}
	if err := s.Eng.PutContact(g.Actor, g.LeaseID, g.Exp, raw); err != nil {
		writeCode(w, err)
		return
	}
	writeOK(w)
}

func (s *Server) findings(w http.ResponseWriter, g *grant.Grant, scan bool) {
	var found []ids.Finding
	var err error
	if scan {
		found, err = s.Eng.Scan(g.Actor, g.LeaseID, g.Exp)
	} else {
		found, err = s.Eng.Findings()
	}
	if err != nil {
		writeCode(w, err)
		return
	}
	if found == nil {
		found = []ids.Finding{}
	}
	writeJSON(w, http.StatusOK, struct {
		Findings []ids.Finding `json:"findings"`
	}{found})
}

func (s *Server) postEmpty(w http.ResponseWriter, r *http.Request, fn func() error) {
	body, err := readBody(w, r)
	if err != nil {
		writeCode(w, err)
		return
	}
	if len(body) != 0 {
		writeErr(w, codes.BadPath)
		return
	}
	if err := fn(); err != nil {
		writeCode(w, err)
	}
}

func (s *Server) audit(w http.ResponseWriter, limit int) {
	rows, err := s.Eng.Audit(limit)
	if err != nil {
		writeCode(w, err)
		return
	}
	out := make([]auditRow, 0, len(rows))
	for _, row := range rows {
		detail := row.Detail
		if len(detail) == 0 {
			detail = json.RawMessage(`{}`)
		}
		out = append(out, auditRow{
			Seq: row.Seq, Prev: row.Prev, Time: row.Time, Actor: row.Actor,
			LeaseID: row.LeaseID, Action: row.Action, Detail: detail, Hash: row.Hash,
		})
	}
	writeJSON(w, http.StatusOK, struct {
		Rows []auditRow `json:"rows"`
	}{out})
}

// verify is the full walk. Threats: it reads every segment while holding the
// engine lock, so one authorized caller could stall scans by looping it; a
// second call within verifyEvery is rate_limited (429) before any read.
func (s *Server) verify(w http.ResponseWriter) {
	s.verifyMu.Lock()
	now := s.now()
	if !s.lastVerify.IsZero() && now.Sub(s.lastVerify) < verifyEvery && !now.Before(s.lastVerify) {
		s.verifyMu.Unlock()
		writeErr(w, codes.RateLimited)
		return
	}
	s.lastVerify = now
	s.verifyMu.Unlock()
	n, err := s.Eng.VerifyAudit()
	if err != nil {
		writeCode(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		OK   bool `json:"ok"`
		Rows int  `json:"rows"`
	}{true, n})
}

func limitOf(r *http.Request) (int, error) {
	if r.URL.Path != "/v1/audit" || r.Method != http.MethodGet {
		if r.URL.RawQuery != "" {
			return 0, codes.E(codes.BadPath)
		}
		return 0, nil
	}
	q := r.URL.Query()
	if len(q) == 0 {
		return defaultAuditLimit, nil
	}
	vals, ok := q["limit"]
	if !ok || len(q) != 1 || len(vals) != 1 {
		return 0, codes.E(codes.BadPath)
	}
	s := vals[0]
	if s == "" || s[0] == '0' {
		return 0, codes.E(codes.BadPath)
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, codes.E(codes.BadPath)
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > maxAuditLimit || strconv.Itoa(n) != s {
		return 0, codes.E(codes.BadPath)
	}
	return n, nil
}

func contactValue(body []byte) (string, error) {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil || dec.More() {
		return "", codes.E(codes.BadPath)
	}
	b, ok := raw["contact"]
	if !ok || strings.TrimSpace(string(b)) == "null" {
		return "", codes.E(codes.BadContact)
	}
	if len(raw) != 1 {
		return "", codes.E(codes.BadPath)
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil || s == "" {
		return "", codes.E(codes.BadContact)
	}
	return s, nil
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return []byte{}, nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, BodyMax)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		var maxed *http.MaxBytesError
		if errors.As(err, &maxed) {
			return nil, codes.E(codes.Oversized)
		}
		return nil, codes.E(codes.BadPath)
	}
	if len(b) > BodyMax {
		return nil, codes.E(codes.Oversized)
	}
	return b, nil
}

func writeOK(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, struct {
		OK bool `json:"ok"`
	}{true})
}

func writeCode(w http.ResponseWriter, err error) {
	writeErr(w, codes.Code(err))
}

func writeErr(w http.ResponseWriter, code string) {
	writeJSON(w, statusOf(code), map[string]string{"error": code})
}

func statusOf(code string) int {
	switch code {
	case codes.GrantMissing, codes.GrantBadSig, codes.GrantExpired, codes.GrantFuture:
		return http.StatusUnauthorized
	case codes.GrantBadShape, codes.GrantPurpose, codes.GrantTTL, codes.GrantStar, codes.GrantRootSlash,
		codes.BadContact, codes.BadPath, codes.Oversized, codes.BlockedAddress:
		return http.StatusBadRequest
	case codes.GrantHost, codes.GrantSpent, codes.Forbidden, codes.ConfigScope:
		return http.StatusForbidden
	case codes.Method:
		return http.StatusMethodNotAllowed
	case codes.RateLimited:
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := codes.Marshal(v)
	if err != nil {
		status = http.StatusInternalServerError
		b = []byte(`{"error":"failed"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, err := w.Write(append(b, '\n')); err != nil {
		return
	}
}

// NewClient dials socket. Proxy is notify.NoProxy so HTTPS_PROXY is ignored.
func NewClient(socket string) *http.Client {
	return &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			Proxy: notify.NoProxy,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}
}

// Serve opens state, listens, writes the ready byte, then serves until ctx ends.
// A bad interval returns before the state directory is created. The ready byte
// is written only after Listen succeeds.
func Serve(ctx context.Context, opt Options) error {
	if opt.Interval < MinInterval {
		return codes.E(codes.Usage)
	}
	if placeholderHost(opt.Host) {
		return codes.E(codes.HostUnset)
	}
	if !grant.HostOK(opt.Host) {
		return codes.E(codes.BadHost)
	}
	pub, err := grant.LoadPub(opt.PubPath)
	if err != nil {
		return err
	}
	note("validate")
	st, err := store.Open(opt.Dir, func(raw string) error {
		_, err := notify.Parse(raw)
		return err
	})
	if err != nil {
		return err
	}
	note("store")
	ln, err := listenUnix(opt.Socket)
	if err != nil {
		return err
	}
	note("listen")
	if err := os.Chmod(opt.Socket, 0o660); err != nil {
		return finishListen(ln, opt.Socket, codes.E(codes.BadSocket))
	}
	if err := notifyReady(); err != nil {
		return finishListen(ln, opt.Socket, err)
	}
	note("ready")
	eng := &engine.Engine{
		Store: st, Host: opt.Host, Now: opt.Now, Pub: pub,
		Sender: &notify.Sender{Log: logCode}, Log: logCode,
	}
	srv := &http.Server{
		Handler:           &Server{Host: opt.Host, Pub: pub, Eng: eng, Now: opt.Now},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    HeaderMax,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	loopCtx, loopCancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		eng.Loop(loopCtx, opt.Interval)
	}()
	errc := make(chan error, 1)
	go func() {
		errc <- srv.Serve(ln)
	}()
	select {
	case <-ctx.Done():
		return shutdown(srv, loopCancel, &wg, opt.Socket, errc)
	case err := <-errc:
		loopCancel()
		wg.Wait()
		uerr := unlinkIfSocket(opt.Socket)
		if cerr := asCode(err); cerr != nil {
			return cerr
		}
		return uerr
	}
}

// placeholderHost reports a host that names no particular machine.
// Threats: a placeholder host would make every grant for that name valid on
// every host that ships the same template. Empty, the loopback names, any
// name under .localhost, and any IP literal are refused before any state.
// Names are not resolved: startup does no DNS.
func placeholderHost(h string) bool {
	switch h {
	case "", "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "localhost6", "localhost6.localdomain6":
		return true
	}
	return strings.HasSuffix(h, ".localhost") || net.ParseIP(h) != nil
}

func finishListen(ln net.Listener, path string, cause error) error {
	if err := closeListen(ln, path); err != nil {
		return err
	}
	return cause
}

func shutdown(srv *http.Server, loopCancel context.CancelFunc, wg *sync.WaitGroup, path string, errc <-chan error) error {
	shutCtx, cancel := context.WithTimeout(context.Background(), shutdownWait)
	serr := srv.Shutdown(shutCtx)
	cancel()
	loopCancel()
	wg.Wait()
	uerr := unlinkIfSocket(path)
	var serveErr error
	select {
	case serveErr = <-errc:
	case <-time.After(time.Second):
		serveErr = codes.E(codes.Failed)
	}
	if err := asCode(serveErr); err != nil {
		return err
	}
	if serr != nil {
		return codes.E(codes.Failed)
	}
	return uerr
}

func closeListen(ln net.Listener, path string) error {
	cerr := ln.Close()
	uerr := unlinkIfSocket(path)
	if cerr != nil && !errors.Is(cerr, net.ErrClosed) {
		return codes.E(codes.BadSocket)
	}
	return uerr
}

func asCode(err error) error {
	if err == nil || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	var ce *codes.Error
	if errors.As(err, &ce) {
		return ce
	}
	return codes.E(codes.Failed)
}

func logCode(code string) {
	if code == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "%s\n", code)
}

func listenUnix(path string) (net.Listener, error) {
	if !paths.IsAbsClean(path) {
		return nil, codes.E(codes.BadSocket)
	}
	parent := filepath.Dir(path)
	fi, err := os.Lstat(parent)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, codes.E(codes.BadSocket)
		}
		if err := os.Mkdir(parent, 0o750); err != nil {
			return nil, codes.E(codes.BadSocket)
		}
		if err := os.Chmod(parent, 0o750); err != nil {
			return nil, codes.E(codes.BadSocket)
		}
	} else if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return nil, codes.E(codes.BadSocket)
	}
	st, err := os.Lstat(path)
	if err == nil {
		if st.Mode()&os.ModeSymlink != 0 || st.Mode()&os.ModeSocket == 0 {
			return nil, codes.E(codes.BadSocket)
		}
		if err := os.Remove(path); err != nil {
			return nil, codes.E(codes.BadSocket)
		}
	} else if !os.IsNotExist(err) {
		return nil, codes.E(codes.BadSocket)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, codes.E(codes.BadSocket)
	}
	return ln, nil
}

func unlinkIfSocket(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return codes.E(codes.Failed)
	}
	if fi.Mode()&os.ModeSymlink != 0 || fi.Mode()&os.ModeSocket == 0 {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return codes.E(codes.Failed)
	}
	return nil
}

func notifyReady() error {
	v, ok := os.LookupEnv(readyEnv)
	if !ok || v == "" {
		return nil
	}
	fd, err := strconv.Atoi(v)
	if err != nil || fd < 0 {
		return codes.E(codes.ReadyFailed)
	}
	n, err := unix.Write(fd, []byte{'\n'})
	if err != nil || n != 1 {
		return codes.E(codes.ReadyFailed)
	}
	return nil
}
