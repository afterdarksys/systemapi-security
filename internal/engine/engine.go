// Package engine runs scans and the mutating host calls.
//
// Threats: a lease is spent before the commit and stays spent when the
// commit fails. Path coverage is decided before any new path is Lstat'd.
// High findings page once per kind per minute. The contact URL is not an
// audit field. A page leaves the host on a topic anyone who learns or
// guesses it can read, so by default it carries a kind, a count and a random
// reference, never the host, a path, a subject or an address. Pages are sent
// after the scan commits, from a bounded queue, so a slow ntfy cannot hold
// the API response past its write timeout. A failed audit does not save
// detector memory, so the next scan retries. Status caps are advisory: a probe result never grants, and
// the report carries a closed reason rather than a path, a contact, an
// address, or an error string. This package does not verify grants.
package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strconv"
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
	pageQueueMax   = 64
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
	// AnchorPub is the hex public key that signs GET /v1/audit/head.
	AnchorPub string `json:"anchor_pub"`
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

	pagesOnce sync.Once
	pages     chan pageJob
}

// pageJob is one page handed from a committed scan to the pager.
type pageJob struct {
	id      string // the open-finding key
	pageID  string
	kind    string
	sha     string
	actor   string
	lease   string
	ts      int64 // the coalesce time the scan set
	finding ids.Finding
	contact notify.Contact
	body    []byte
}

func (e *Engine) queue() chan pageJob {
	e.pagesOnce.Do(func() { e.pages = make(chan pageJob, pageQueueMax) })
	return e.pages
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
		Armed:     Armed{Auth: cfg.AuthLog != "", Integrity: len(cfg.Watch) > 0, Listen: len(cfg.ListenAllow) > 0},
		Caps:      caps.Probe(e.capEnv(cfg)),
		AnchorPub: hex.EncodeToString(e.Store.AnchorPub()),
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
	if c := codes.Code(err); c == codes.AuditBad || c == codes.AuditTruncated || c == codes.AuditLayout {
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

// Audit returns the tail of the newest segment after the bounded check.
func (e *Engine) Audit(limit int) ([]audit.Row, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.Store.AuditTail(limit)
}

// VerifyAudit walks every segment and returns the rows on disk. It holds
// the engine lock for the walk, so the API rate-limits it.
func (e *Engine) VerifyAudit() (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.Store.AuditVerify()
}

// HeadDomain prefixes every signed head, so an anchor signature can never be
// replayed as a grant or anything else the key might sign.
const HeadDomain = "secsvc-audit-head-v1\n"

// Head is the chain position an off-host party records.
type Head struct {
	Host    string `json:"host"`
	Seq     int64  `json:"seq"`
	Hash    string `json:"hash"`
	Segment int    `json:"segment"`
	Time    string `json:"time"`
}

// SignedHead is the GET /v1/audit/head body. Sig is base64 Ed25519 over
// HeadDomain followed by the compact JSON of Head.
type SignedHead struct {
	Head Head   `json:"head"`
	Sig  string `json:"sig"`
}

// AuditHead signs the head after the bounded runtime check.
// Threats: a truncated or rewritten newest segment is refused before
// anything is signed. The anchor key never leaves the store. Root on this
// host holds the key too, so a signed head proves only what this host said
// and when; the witnessing party must keep its own copies.
func (e *Engine) AuditHead() (SignedHead, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	seq, hash, seg, err := e.Store.AuditHead()
	if err != nil {
		return SignedHead{}, err
	}
	h := Head{Host: e.Host, Seq: seq, Hash: hash, Segment: seg, Time: e.now().UTC().Format(time.RFC3339Nano)}
	b, err := codes.Marshal(h)
	if err != nil {
		return SignedHead{}, codes.E(codes.Failed)
	}
	sig := e.Store.SignAnchor(append([]byte(HeadDomain), b...))
	return SignedHead{Head: h, Sig: base64.StdEncoding.EncodeToString(sig)}, nil
}

// Witness stores an off-host witness record and audits it.
// Threats: the body is strict; the lease is spent before the commit; a
// witness the chain does not hold is audit_truncated and breaks the chain.
func (e *Engine) Witness(actor, lease string, exp int64, body []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	w, err := audit.ParseWitness(body)
	if err != nil {
		return err
	}
	detail, err := mustDetail(w)
	if err != nil {
		return err
	}
	if err := e.Store.Spend(lease, exp, e.now()); err != nil {
		return err
	}
	if err := e.Store.AddWitness(w); err != nil {
		return err
	}
	return e.Store.AppendAudit(actor, lease, "audit.witness", detail, e.now())
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
	if err := stateScope(old, neu, e.Store.Dir(), covers); err != nil {
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

// stateScope guards the fields that govern the state directory itself.
// Threats: audit_keep_segments deletes audit history and page_detail sends
// every subject to the contact, so a grant scoped to one watched path must
// not change either; a change needs a grant that covers the state directory,
// otherwise config_scope.
func stateScope(old, neu store.Config, dir string, covers func(string) bool) error {
	if old.AuditKeepSegments == neu.AuditKeepSegments && old.PageDetail == neu.PageDetail {
		return nil
	}
	if covers == nil || !covers(dir) {
		return codes.E(codes.ConfigScope)
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

	var jobs []pageJob
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
			} else if err := e.page(actor, lease, id, f, &rec, &st, now, &jobs); err != nil {
				return nil, err
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
			if err := e.page(actor, lease, id, f, &prev, &st, now, &jobs); err != nil {
				return nil, err
			}
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
	if err := e.enqueue(jobs, &st, cfg.PageDetail, now); err != nil {
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

// page decides the page for a high finding. A missing contact marks it
// paged; a bad contact or no sender is audited page.failed and left unpaged,
// so the next scan retries; a page within a minute of the same kind is
// audited page.coalesced. Otherwise the finding is marked paged and a job is
// queued for the pager, which runs after the scan commits.
func (e *Engine) page(actor, lease, id string, f ids.Finding, rec *store.OpenRec, st *store.IDSState, now time.Time, jobs *[]pageJob) error {
	rec.Paged = false
	raw, err := e.Store.Contact()
	if errors.Is(err, store.ErrNone) {
		rec.Paged = true
		return nil
	}
	if err != nil {
		return e.auditPage(actor, lease, "page.failed", f.Kind, "", rec.PageID, codes.Code(err), now)
	}
	c, perr := notify.Parse(raw)
	if perr != nil {
		return e.auditPage(actor, lease, "page.failed", f.Kind, notify.Fingerprint(raw), rec.PageID, codes.Code(perr), now)
	}
	if ts, ok := st.Coalesce[f.Kind]; ok && now.Sub(time.Unix(0, ts)) < coalesceWindow {
		rec.Paged = true
		return e.auditPage(actor, lease, "page.coalesced", f.Kind, c.SHA256, rec.PageID, "", now)
	}
	if e.Sender == nil {
		return e.auditPage(actor, lease, "page.failed", f.Kind, c.SHA256, rec.PageID, codes.Failed, now)
	}
	if rec.PageID == "" {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return codes.E(codes.Failed)
		}
		rec.PageID = hex.EncodeToString(b[:])
	}
	ts := now.UnixNano()
	st.Coalesce[f.Kind] = ts
	rec.Paged = true
	*jobs = append(*jobs, pageJob{
		id: id, pageID: rec.PageID, kind: f.Kind, sha: c.SHA256, actor: actor, lease: lease,
		ts: ts, finding: f, contact: c,
	})
	return nil
}

// enqueue hands committed jobs to the pager without blocking. A full queue
// is page.failed with queue_full, and the finding is unpaged again so the
// next scan retries.
func (e *Engine) enqueue(jobs []pageJob, st *store.IDSState, detail bool, now time.Time) error {
	if len(jobs) == 0 {
		return nil
	}
	high := 0
	for _, rec := range st.Open {
		if rec.Severity == ids.SevHigh {
			high++
		}
	}
	q := e.queue()
	changed := false
	for _, j := range jobs {
		j.body = []byte(pageBody(e.Host, j.finding, detail, high, j.pageID))
		select {
		case q <- j:
		default:
			if err := e.auditPage(j.actor, j.lease, "page.failed", j.kind, j.sha, j.pageID, codes.QueueFull, now); err != nil {
				return err
			}
			changed = unpage(st, j) || changed
		}
	}
	if changed {
		return e.Store.PutIDS(*st)
	}
	return nil
}

// unpage undoes what page set for j while the finding is still the one paged.
func unpage(st *store.IDSState, j pageJob) bool {
	changed := false
	if rec, ok := st.Open[j.id]; ok && rec.PageID == j.pageID && rec.Paged {
		rec.Paged = false
		st.Open[j.id] = rec
		changed = true
	}
	if ts, ok := st.Coalesce[j.kind]; ok && ts == j.ts {
		delete(st.Coalesce, j.kind)
		changed = true
	}
	return changed
}

// Pager sends queued pages until ctx ends; pages still queued then are
// page.failed and unpaged, so the next start retries them.
func (e *Engine) Pager(ctx context.Context) {
	q := e.queue()
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case j := <-q:
					e.failPage(j, codes.Failed)
				default:
					return
				}
			}
		case j := <-q:
			e.deliver(ctx, j)
		}
	}
}

func (e *Engine) deliver(ctx context.Context, j pageJob) {
	cctx, cancel := context.WithTimeout(ctx, notify.Timeout)
	err := e.Sender.Send(cctx, j.contact, j.body)
	cancel()
	if err != nil {
		e.failPage(j, codes.Code(err))
		return
	}
	if err := e.auditPage(j.actor, j.lease, "page.sent", j.kind, j.sha, j.pageID, "", e.now()); err != nil {
		e.log(codes.Code(err))
	}
}

// failPage audits a failed send and unpages the finding under the engine
// lock, so the next scan pages it again.
func (e *Engine) failPage(j pageJob, code string) {
	if err := e.auditPage(j.actor, j.lease, "page.failed", j.kind, j.sha, j.pageID, code, e.now()); err != nil {
		e.log(codes.Code(err))
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.Store.IDS()
	if unpage(&st, j) {
		if err := e.Store.PutIDS(st); err != nil {
			e.log(codes.Code(err))
		}
	}
}

func (e *Engine) auditPage(actor, lease, action, kind, sha, pageID, code string, now time.Time) error {
	detail, err := mustDetail(struct {
		Kind   string `json:"kind"`
		SHA    string `json:"contact_sha256"`
		PageID string `json:"page_id,omitempty"`
		Error  string `json:"error,omitempty"`
	}{kind, sha, pageID, code})
	if err != nil {
		return err
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
		out = append(out, ids.Finding{Kind: rec.Kind, Severity: rec.Severity, Subject: rec.Subject, Summary: rec.Summary, PageID: rec.PageID})
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

// pageBody is the page text. By default it names only the kind, the number
// of open high findings and the page id. page_detail restores the host and
// a clipped subject or summary.
func pageBody(host string, f ids.Finding, detail bool, high int, ref string) string {
	if !detail {
		return "secsvc high " + f.Kind + ": " + strconv.Itoa(high) + " high finding(s) open, ref " + ref
	}
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
