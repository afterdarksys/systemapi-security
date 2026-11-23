// Package engine runs scans and the mutating host calls.
//
// Threats: a lease is spent before the commit and stays spent when the
// commit fails. Path coverage is decided before any new path is Lstat'd.
// High findings page once per kind per minute. The contact URL is not an
// audit field. A failed audit does not save detector memory, so the next
// scan retries. Status caps are advisory: a probe result never grants, and
// the report carries a closed reason rather than a path, a contact, an
// address, or an error string. This package does not verify grants.
package engine

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/afterdarksys/systemapi-security/internal/audit"
	"github.com/afterdarksys/systemapi-security/internal/caps"
	"github.com/afterdarksys/systemapi-security/internal/codes"
	"github.com/afterdarksys/systemapi-security/internal/ids"
	"github.com/afterdarksys/systemapi-security/internal/modules"
	"github.com/afterdarksys/systemapi-security/internal/notify"
	"github.com/afterdarksys/systemapi-security/internal/store"
	"golang.org/x/sys/unix"
)

const (
	coalesceWindow = 60 * time.Second
	coalesceCap    = 32
	detailMax      = 8 << 10
	clipMax        = 200
	procMax        = 1 << 20
)

// Status is the GET /v1/status body.
type Status struct {
	System        modules.Snapshot `json:"system"`
	ConfigChanged bool             `json:"config_changed"`
	Host          string           `json:"host"`
	LastScan      string           `json:"last_scan"`
	Armed         Armed            `json:"armed"`
	Listen        string           `json:"listen"`
	OpenFindings  int              `json:"open_findings"`
	Caps          []caps.Result    `json:"caps"`
}

// Armed reports which detectors have a target configured.
type Armed struct {
	Auth      bool `json:"auth"`
	Integrity bool `json:"integrity"`
	Listen    bool `json:"listen"`
}

// Engine is the host scanner. Scan and the API share mu.
type Engine struct {
	// Pub is the grant verification key, reported by the grant_v1 cap only.
	Pub      ed25519.PublicKey
	SystemFS modules.Reader
	mu       sync.Mutex
	Store    *store.Store
	Host     string
	Now      func() time.Time
	Sender   *notify.Sender
	Proc     func() (tcp, tcp6 string, oversize bool, err error)
	Log      func(code string)
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Engine) log(code string) {
	if code == "" || e.Log == nil {
		return
	}
	e.Log(code)
}

// Loop scans once, then on each tick, until ctx is done.
func (e *Engine) Loop(ctx context.Context, every time.Duration) {
	e.quiet()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.quiet()
		}
	}
}

func (e *Engine) quiet() {
	if _, err := e.Scan("secsvc", "", 0); err != nil {
		e.log(codes.Code(err))
	}
}

// Status reads the last scan. It does not scan.
func (e *Engine) Status() (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cfg := e.Store.Config()
	st := e.Store.IDS()
	listen := st.Listen
	if listen == "" {
		listen = ids.StateOff
	}
	if len(cfg.ListenAllow) > 0 && st.LastScan == "" {
		listen = ids.StateWait
	}
	return Status{
		Host: e.Host, LastScan: st.LastScan, Listen: listen, OpenFindings: len(st.Open),
		System: systemView(cfg, st), ConfigChanged: configHash(cfg) != st.ConfigSHA256,
		Armed: Armed{Auth: cfg.AuthLog != "", Integrity: len(cfg.Watch) > 0, Listen: len(cfg.ListenAllow) > 0},
		Caps:  caps.Probe(e.capEnv(cfg)),
	}, nil
}

// capEnv builds the capability probes. Each check returns a sentinel. The
// report never sees a path, the contact string, or a listener address.
func (e *Engine) capEnv(cfg store.Config) caps.Env {
	return caps.Env{
		Audit:     e.auditCheck,
		Auth:      fileCheck(cfg.AuthLog),
		Integrity: watchCheck(cfg.Watch, e.Store.Baseline()),
		Grant:     e.grantCheck(),
		Listen:    e.listenCheck(cfg.ListenAllow),
		Notify:    e.notifyCheck,
	}
}

func (e *Engine) auditCheck() error {
	_, err := e.Store.AuditCount()
	if err == nil {
		return nil
	}
	if c := codes.Code(err); c == codes.AuditBad || c == codes.AuditTruncated {
		return caps.ErrAudit
	}
	return caps.ErrProbe
}

func (e *Engine) grantCheck() caps.Check {
	if len(e.Pub) != ed25519.PublicKeySize {
		return nil
	}
	return func() error { return nil }
}

func (e *Engine) notifyCheck() error {
	raw, err := e.Store.Contact()
	if errors.Is(err, store.ErrNone) {
		return caps.ErrOff
	}
	if err != nil {
		return caps.ErrProbe
	}
	if _, err := notify.Parse(raw); err != nil {
		return caps.ErrContact
	}
	return nil
}

func (e *Engine) listenCheck(allow []string) caps.Check {
	if len(allow) == 0 {
		return nil
	}
	cp := append([]string(nil), allow...)
	return func() error {
		tcp, tcp6, over, err := e.readProc()
		if err != nil {
			if os.IsNotExist(err) {
				return caps.ErrUnsupported
			}
			return caps.ErrUnreadable
		}
		if over {
			return caps.ErrUnreadable
		}
		st, _ := ids.Detect(cp, tcp, tcp6, false, nil)
		if st != ids.StateOK {
			return caps.ErrProbe
		}
		return nil
	}
}

func fileCheck(path string) caps.Check {
	if path == "" {
		return nil
	}
	return func() error { return classFile(path) }
}

// watchCheck is ok only when every watched path is a readable regular file
// with a baseline record. Otherwise the worst reason wins: unreadable, then
// target_missing, then unbaselined.
func watchCheck(paths []string, base map[string]ids.Record) caps.Check {
	if len(paths) == 0 {
		return nil
	}
	cp := append([]string(nil), paths...)
	return func() error {
		missing, unbaselined := false, false
		for _, p := range cp {
			err := classFile(p)
			switch {
			case errors.Is(err, caps.ErrMissing):
				missing = true
				continue
			case err != nil:
				return caps.ErrUnreadable
			}
			if _, ok := base[p]; !ok {
				unbaselined = true
			}
		}
		if missing {
			return caps.ErrMissing
		}
		if unbaselined {
			return caps.ErrUnbaselined
		}
		return nil
	}
}

// classFile opens the path without following a symlink and does not read it.
// Threats: a FIFO or device at a configured path must not block status while
// it holds e.mu, so the open is O_NONBLOCK and fstat decides regularity.
func classFile(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if err == unix.ENOENT {
			return caps.ErrMissing
		}
		return caps.ErrUnreadable
	}
	var st unix.Stat_t
	err = unix.Fstat(fd, &st)
	cerr := unix.Close(fd)
	if err != nil || cerr != nil {
		return caps.ErrUnreadable
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return caps.ErrUnreadable
	}
	return nil
}

// Findings returns the open set from the last scan, sorted by subject then kind.
func (e *Engine) Findings() ([]ids.Finding, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return openFindings(e.Store.IDS()), nil
}

// Config is the public config view. A loose contact mode fails closed.
func (e *Engine) Config() (store.ConfigView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.Store.View()
}

// Audit returns the tail after a fresh verify.
func (e *Engine) Audit(limit int) ([]audit.Row, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.Store.AuditTail(limit)
}

// VerifyAudit re-verifies the chain and returns the row count.
func (e *Engine) VerifyAudit() (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.Store.AuditCount()
}

// PutConfig replaces configuration when covers allows every changed path.
func (e *Engine) PutConfig(actor, lease string, exp int64, body []byte, covers func(string) bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	neu, err := store.DecodeConfig(body)
	if err != nil {
		return err
	}
	old := e.Store.Config()
	if err := store.AllowChange(old, neu, covers); err != nil {
		return err
	}
	if err := store.ProbePaths(neu); err != nil {
		return err
	}
	detail, err := mustDetail(neu)
	if err != nil {
		return err
	}
	if err := e.Store.Spend(lease, exp, e.now()); err != nil {
		return err
	}
	if err := e.Store.PutConfig(neu); err != nil {
		return e.failCommit(actor, lease, "config.set", err)
	}
	if err := e.Store.AppendAudit(actor, lease, "config.set", detail, e.now()); err != nil {
		return err
	}
	return nil
}

// PutContact stores a contact after parse and egress checks.
func (e *Engine) PutContact(actor, lease string, exp int64, raw string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, err := notify.Parse(raw)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), notify.Timeout)
	defer cancel()
	if e.Sender == nil {
		return codes.E(codes.Failed)
	}
	if err := e.Sender.CheckEgress(ctx, c); err != nil {
		return err
	}
	detail, err := mustDetail(struct {
		SHA string `json:"contact_sha256"`
	}{c.SHA256})
	if err != nil {
		return err
	}
	if err := e.Store.Spend(lease, exp, e.now()); err != nil {
		return err
	}
	if err := e.Store.PutContact(c.Normalized); err != nil {
		return e.failCommit(actor, lease, "notify.set", err)
	}
	return e.Store.AppendAudit(actor, lease, "notify.set", detail, e.now())
}

// Baseline measures every watched path. An uncovered path is forbidden.
// An empty watch still spends a lease and writes an empty baseline.
func (e *Engine) Baseline(actor, lease string, exp int64, covers func(string) bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if covers == nil {
		covers = func(string) bool { return false }
	}
	cfg := e.Store.Config()
	for _, p := range cfg.Watch {
		if !covers(p) {
			return codes.E(codes.Forbidden)
		}
	}
	m := map[string]ids.Record{}
	for _, p := range cfg.Watch {
		rec, err := ids.Measure(p)
		if err != nil {
			return err
		}
		m[p] = rec
	}
	type pathHash struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	rows := make([]pathHash, 0, len(m))
	for p, rec := range m {
		rows = append(rows, pathHash{Path: p, SHA256: rec.SHA256})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Path < rows[j].Path })
	detail, err := mustDetail(struct {
		Paths []pathHash `json:"paths"`
	}{rows})
	if err != nil {
		return err
	}
	if err := e.Store.Spend(lease, exp, e.now()); err != nil {
		return err
	}
	if err := e.Store.PutBaseline(m); err != nil {
		return e.failCommit(actor, lease, "baseline.set", err)
	}
	return e.Store.AppendAudit(actor, lease, "baseline.set", detail, e.now())
}

func (e *Engine) failCommit(actor, lease, action string, commit error) error {
	aerr := e.Store.AppendAudit(actor, lease, action, json.RawMessage(`{"error":"failed"}`), e.now())
	if aerr != nil {
		return aerr
	}
	return commit
}

// Scan runs the detectors, writes edges, and returns the open set.
// Threats: a granted scan spends its lease before any detector runs, exactly
// once, as a config mutation does, so one grant cannot replay scans (and the
// pages they send) for its whole TTL. The internal loop passes no lease.
func (e *Engine) Scan(actor, lease string, exp int64) ([]ids.Finding, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	if lease != "" {
		if err := e.Store.Spend(lease, exp, now); err != nil {
			return nil, err
		}
	}
	cfg := e.Store.Config()
	base := e.Store.Baseline()
	st := e.Store.IDS()
	if st.Open == nil {
		st.Open = map[string]store.OpenRec{}
	}
	if st.Coalesce == nil {
		st.Coalesce = map[string]int64{}
	}
	pruneCoalesce(st.Coalesce, now)

	var found []ids.Finding
	if cfg.AuthLog != "" {
		pos := ids.AuthPos{Path: st.AuthPath, Ino: st.AuthIno, Dev: st.AuthDev, Offset: st.AuthOffset}
		next, ev, f := ids.ScanAuth(cfg.AuthLog, pos, st.AuthEvents, cfg.AuthFailLimit, cfg.AuthWindowS, now)
		st.AuthPath, st.AuthIno, st.AuthDev, st.AuthOffset = next.Path, next.Ino, next.Dev, next.Offset
		st.AuthEvents = ev
		if f != nil {
			found = append(found, *f)
		}
	}
	for _, p := range cfg.Watch {
		var ptr *ids.Record
		if rec, ok := base[p]; ok {
			r := rec
			ptr = &r
		}
		if f := ids.Check(p, ptr); f.Kind != "" {
			found = append(found, f)
		}
	}
	listen := ids.StateOff
	if len(cfg.ListenAllow) > 0 {
		tcp, tcp6, over, err := e.readProc()
		var extra []ids.Finding
		listen, extra = ids.Detect(cfg.ListenAllow, tcp, tcp6, over, err)
		found = append(found, extra...)
	}
	system, extra := modules.Scan(e.SystemFS, cfg.Modules)
	found = append(found, extra...)
	sort.Slice(found, func(i, j int) bool {
		if found[i].Subject != found[j].Subject {
			return found[i].Subject < found[j].Subject
		}
		return found[i].Kind < found[j].Kind
	})

	for id, rec := range st.Open {
		rec.Observed = false
		st.Open[id] = rec
	}
	seen := map[string]struct{}{}
	for _, f := range found {
		id := ident(f)
		seen[id] = struct{}{}
		prev, ok := st.Open[id]
		if !ok {
			if err := e.auditFinding(actor, lease, "ids.finding", f, now); err != nil {
				return nil, err
			}
			rec := store.OpenRec{Kind: f.Kind, Severity: f.Severity, Subject: f.Subject, Summary: f.Summary, FirstSeen: now.UTC().Format(time.RFC3339Nano), LastSeen: now.UTC().Format(time.RFC3339Nano), Observed: true}
			if f.Severity != ids.SevHigh {
				rec.Paged = true
			} else {
				okPage, err := e.page(actor, lease, f, &st, now)
				if err != nil {
					return nil, err
				}
				rec.Paged = okPage
			}
			st.Open[id] = rec
			continue
		}
		if prev.Severity != ids.SevHigh && f.Severity == ids.SevHigh {
			prev.Paged = false
		}
		prev.Observed = true
		prev.LastSeen = now.UTC().Format(time.RFC3339Nano)
		prev.Summary = f.Summary
		prev.Severity = f.Severity
		prev.Subject = f.Subject
		if f.Severity == ids.SevHigh && !prev.Paged {
			okPage, err := e.page(actor, lease, f, &st, now)
			if err != nil {
				return nil, err
			}
			prev.Paged = okPage
		}
		if f.Severity != ids.SevHigh {
			prev.Paged = true
		}
		st.Open[id] = prev
	}
	var gone []string
	for id := range st.Open {
		if _, ok := seen[id]; !ok {
			gone = append(gone, id)
		}
	}
	sort.Strings(gone)
	for _, id := range gone {
		rec := st.Open[id]
		disposition := modules.Disposition(rec.Kind, cfg.Modules, system)
		if disposition == "retain" || unbaselinedIntegrity(rec, cfg.Watch, base) {
			continue
		}
		action := "ids.resolved"
		if disposition == "withdraw" {
			action = "ids.withdrawn"
		}
		f := ids.Finding{Kind: rec.Kind, Subject: rec.Subject}
		if err := e.auditFinding(actor, lease, action, f, now); err != nil {
			return nil, err
		}
		delete(st.Open, id)
	}
	st.LastScan = now.UTC().Format(time.RFC3339Nano)
	st.Listen = listen
	st.System = system
	st.ConfigSHA256 = configHash(cfg)
	if err := e.Store.PutIDS(st); err != nil {
		return nil, err
	}
	return openFindings(st), nil
}

// unbaselinedIntegrity reports an open integrity finding on a watched path
// that has no baseline record. Threats: a missing or unloadable baseline (a
// version-1 file loads as none) must not resolve it, or a high change would
// turn into a medium unbaselined and the next baseline would adopt the
// changed file. It stays open until a scan against a real baseline shows the
// file matching, or the path leaves the watch list.
func unbaselinedIntegrity(rec store.OpenRec, watch []string, base map[string]ids.Record) bool {
	switch rec.Kind {
	case ids.KindChange, ids.KindMiss, ids.KindLink, ids.KindNotReg, ids.KindBig:
	default:
		return false
	}
	if _, ok := base[rec.Subject]; ok {
		return false
	}
	for _, p := range watch {
		if p == rec.Subject {
			return true
		}
	}
	return false
}

func (e *Engine) auditFinding(actor, lease, action string, f ids.Finding, now time.Time) error {
	var detail json.RawMessage
	var err error
	if action == "ids.resolved" || action == "ids.withdrawn" {
		detail, err = mustDetail(struct {
			Kind    string `json:"kind"`
			Subject string `json:"subject"`
		}{f.Kind, f.Subject})
	} else {
		detail, err = mustDetail(struct {
			Kind     string `json:"kind"`
			Subject  string `json:"subject"`
			Severity string `json:"severity"`
			Summary  string `json:"summary"`
		}{f.Kind, f.Subject, f.Severity, f.Summary})
	}
	if err != nil {
		return err
	}
	if err := e.Store.AppendAudit(actor, lease, action, detail, now); err != nil {
		return err
	}
	edge, err := mustDetail(struct {
		Action   string `json:"action"`
		Kind     string `json:"kind"`
		Subject  string `json:"subject"`
		Severity string `json:"severity,omitempty"`
		Summary  string `json:"summary,omitempty"`
	}{action, f.Kind, f.Subject, f.Severity, f.Summary})
	if err != nil {
		return err
	}
	return e.Store.AppendEdge(edge)
}

func (e *Engine) page(actor, lease string, f ids.Finding, st *store.IDSState, now time.Time) (bool, error) {
	raw, err := e.Store.Contact()
	if errors.Is(err, store.ErrNone) {
		return true, nil
	}
	sha := ""
	if err != nil {
		return false, e.auditNotify(actor, lease, f.Kind, sha, "", codes.Code(err), now)
	}
	c, perr := notify.Parse(raw)
	if perr != nil {
		return false, e.auditNotify(actor, lease, f.Kind, notify.Fingerprint(raw), "", codes.Code(perr), now)
	}
	sha = c.SHA256
	if ts, ok := st.Coalesce[f.Kind]; ok && now.Sub(time.Unix(0, ts)) < coalesceWindow {
		if err := e.auditNotify(actor, lease, f.Kind, sha, "coalesced", "", now); err != nil {
			return false, err
		}
		return true, nil
	}
	if e.Sender == nil {
		return false, e.auditNotify(actor, lease, f.Kind, sha, "", codes.Failed, now)
	}
	ctx, cancel := context.WithTimeout(context.Background(), notify.Timeout)
	defer cancel()
	if err := e.Sender.Send(ctx, c, []byte(pageBody(e.Host, f))); err != nil {
		return false, e.auditNotify(actor, lease, f.Kind, sha, "", codes.Code(err), now)
	}
	st.Coalesce[f.Kind] = now.UnixNano()
	if err := e.auditNotify(actor, lease, f.Kind, sha, "sent", "", now); err != nil {
		return false, err
	}
	return true, nil
}

func (e *Engine) auditNotify(actor, lease, kind, sha, status, code string, now time.Time) error {
	detail, err := mustDetail(struct {
		Kind   string `json:"kind"`
		SHA    string `json:"contact_sha256"`
		Status string `json:"status,omitempty"`
		Error  string `json:"error,omitempty"`
	}{kind, sha, status, code})
	if err != nil {
		return err
	}
	action := "notify.sent"
	if status == "coalesced" {
		action = "notify.coalesced"
	}
	if code != "" {
		action = "notify.failed"
	}
	return e.Store.AppendAudit(actor, lease, action, detail, now)
}

func (e *Engine) readProc() (string, string, bool, error) {
	if e.Proc != nil {
		return e.Proc()
	}
	tcp, over, err := readProcFile("/proc/net/tcp")
	if err != nil || over {
		return "", "", over, err
	}
	tcp6, over6, err6 := readProcFile("/proc/net/tcp6")
	if err6 != nil {
		if os.IsNotExist(err6) {
			return tcp, "", false, nil
		}
		return "", "", false, err6
	}
	if over6 {
		return "", "", true, nil
	}
	return tcp, tcp6, false, nil
}

func readProcFile(path string) (string, bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", false, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, procMax+1))
	if err != nil {
		return "", false, err
	}
	if len(b) > procMax {
		return "", true, nil
	}
	return string(b), false, nil
}

func ident(f ids.Finding) string {
	if f.Kind == ids.KindAuth || f.Kind == ids.KindAuthNA {
		return f.Kind
	}
	return f.Kind + "\x00" + f.Subject
}

func openFindings(st store.IDSState) []ids.Finding {
	out := make([]ids.Finding, 0, len(st.Open))
	for _, rec := range st.Open {
		out = append(out, ids.Finding{Kind: rec.Kind, Severity: rec.Severity, Subject: rec.Subject, Summary: rec.Summary})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

func pruneCoalesce(m map[string]int64, now time.Time) {
	if m == nil {
		return
	}
	for k, ts := range m {
		if now.Sub(time.Unix(0, ts)) >= coalesceWindow {
			delete(m, k)
		}
	}
	if len(m) <= coalesceCap {
		return
	}
	type pair struct {
		k  string
		ts int64
	}
	ps := make([]pair, 0, len(m))
	for k, ts := range m {
		ps = append(ps, pair{k, ts})
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].ts != ps[j].ts {
			return ps[i].ts < ps[j].ts
		}
		return ps[i].k < ps[j].k
	})
	for len(ps) > coalesceCap {
		delete(m, ps[0].k)
		ps = ps[1:]
	}
}

func pageBody(host string, f ids.Finding) string {
	sub := clip(f.Subject)
	sum := clip(f.Summary)
	switch f.Kind {
	case ids.KindAuth:
		return "secsvc auth_fail on " + host + ": " + sum
	case ids.KindChange:
		return "secsvc integrity_changed on " + host + ": " + sub
	case ids.KindListen:
		return "secsvc listen_unexpected on " + host + ": " + sub
	default:
		return "secsvc " + f.Kind + " on " + host + ": " + sub
	}
}

func clip(s string) string {
	if len(s) <= clipMax {
		return s
	}
	b := []byte(s[:clipMax])
	for len(b) > 0 && !utf8.Valid(b) {
		b = b[:len(b)-1]
	}
	return string(b)
}

func mustDetail(v any) (json.RawMessage, error) {
	b, err := codes.Marshal(v)
	if err != nil || len(b) > detailMax {
		return nil, codes.E(codes.Failed)
	}
	return b, nil
}
