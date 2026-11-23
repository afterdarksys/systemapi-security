// Package store is the secsvc state directory.
//
// Threats: the contact string is a bearer and lives in its own 0600 file.
// A group- or world-readable contact, a symlink, or a corrupt state file fails
// closed and the contact bytes are not returned. Config, baseline, and lease
// writes are atomic. A lease is recorded before the caller's commit and stays
// spent when that commit fails. This package does not verify grants and does
// not parse the contact grammar; the caller supplies that check. Parent-directory
// symlinks are out of scope.
package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/audit"
	"github.com/afterdarksys/systemapi-security/internal/codes"
	"github.com/afterdarksys/systemapi-security/internal/ids"
	"github.com/afterdarksys/systemapi-security/internal/modules"
	"github.com/afterdarksys/systemapi-security/internal/paths"
	"golang.org/x/sys/unix"
)

const (
	contactMax   = 512
	fileMax      = 1 << 20
	edgeMaxBytes = 1 << 20
	edgeMaxLines = 500
	watchMax     = 64
	listenMax    = 64

	defFailLimit = 5
	defWindowS   = 300
)

// ErrNone means no contact is configured. It is not a codes.Error.
var ErrNone = errors.New("none")

// Config is the host detector configuration. The contact is not in this file.
type Config struct {
	Modules       map[string]modules.Config `json:"modules,omitempty"`
	AuthLog       string                    `json:"auth_log"`
	AuthFailLimit int                       `json:"auth_fail_limit"`
	AuthWindowS   int                       `json:"auth_window_s"`
	Watch         []string                  `json:"watch"`
	ListenAllow   []string                  `json:"listen_allow"`
}

// ConfigView is the GET body. ContactSHA256 is a fingerprint, never the URL.
type ConfigView struct {
	Modules       map[string]modules.Config `json:"modules"`
	AuthLog       string                    `json:"auth_log"`
	AuthFailLimit int                       `json:"auth_fail_limit"`
	AuthWindowS   int                       `json:"auth_window_s"`
	Watch         []string                  `json:"watch"`
	ListenAllow   []string                  `json:"listen_allow"`
	ContactSHA256 string                    `json:"contact_sha256"`
	ContactState  string                    `json:"contact_state"`
}

// OpenRec is one open finding remembered across scans.
type OpenRec struct {
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	Observed  bool   `json:"observed"`
	Kind      string `json:"kind"`
	Severity  string `json:"severity"`
	Subject   string `json:"subject"`
	Summary   string `json:"summary"`
	Paged     bool   `json:"paged"`
}

// IDSState is the detector memory. Map keys may contain a NUL.
type IDSState struct {
	System       modules.Snapshot   `json:"system"`
	ConfigSHA256 string             `json:"config_sha256"`
	AuthOffset   int64              `json:"auth_offset"`
	AuthEvents   []int64            `json:"auth_events"`
	Open         map[string]OpenRec `json:"open"`
	LastScan     string             `json:"last_scan"`
	Coalesce     map[string]int64   `json:"coalesce"`
	Listen       string             `json:"listen"`
}

type spentFile struct {
	Leases map[string]int64 `json:"leases"`
}

// Store is one state directory. Methods are safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	dir     string
	cfg     Config
	base    map[string]ids.Record
	baseV   int
	ids     IDSState
	spent   map[string]int64
	chain   *audit.Chain
	contact string
	hasC    bool
}

// Open creates or opens dir. parse checks a stored contact and may be nil
// only when no contact file exists. A bad contact refuses startup.
func Open(dir string, parse func(string) error) (*Store, error) {
	if err := prepareDir(dir); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, spent: map[string]int64{}}
	cfg, err := s.loadConfig()
	if err != nil {
		return nil, err
	}
	if err := ProbePaths(cfg); err != nil {
		return nil, err
	}
	base, baseV, err := s.loadBaseline()
	if err != nil {
		return nil, err
	}
	st, err := s.loadIDS()
	if err != nil {
		return nil, err
	}
	spent, err := s.loadSpent(time.Now())
	if err != nil {
		return nil, err
	}
	raw, ok, err := readContact(filepath.Join(dir, "contact"), parse)
	if err != nil {
		return nil, err
	}
	if err := s.checkEdges(); err != nil {
		return nil, err
	}
	chain, err := audit.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		return nil, err
	}
	s.cfg = cfg
	s.base = base
	s.baseV = baseV
	s.ids = st
	s.spent = spent
	s.chain = chain
	s.contact = raw
	s.hasC = ok
	return s, nil
}

func prepareDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			return codes.E(codes.BadDir)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			return codes.E(codes.BadDir)
		}
	} else if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return codes.E(codes.BadDir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return codes.E(codes.BadDir)
	}
	return nil
}

// Config returns a copy of the detector configuration.
func (s *Store) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneConfig(s.cfg)
}

// Baseline returns a copy of the integrity baseline.
func (s *Store) Baseline() map[string]ids.Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneBase(s.base)
}

// BaselineLegacy reports a version-1 baseline that the engine must upgrade
// once, with an audit row, before comparing.
func (s *Store) BaselineLegacy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.baseV < ids.BaselineVersion
}

// IDS returns a copy of the detector memory.
func (s *Store) IDS() IDSState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneIDS(s.ids)
}

// View is the config GET body. A loose contact mode fails closed.
func (s *Store) View() (ConfigView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, ok, err := readContact(filepath.Join(s.dir, "contact"), nil)
	if err != nil {
		return ConfigView{}, err
	}
	v := ConfigView{
		Modules: modules.CloneConfig(s.cfg.Modules),
		AuthLog: s.cfg.AuthLog, AuthFailLimit: s.cfg.AuthFailLimit, AuthWindowS: s.cfg.AuthWindowS,
		Watch: append([]string(nil), s.cfg.Watch...), ListenAllow: append([]string(nil), s.cfg.ListenAllow...),
		ContactState: "off",
	}
	if v.Watch == nil {
		v.Watch = []string{}
	}
	if v.ListenAllow == nil {
		v.ListenAllow = []string{}
	}
	if ok {
		v.ContactState = "set"
		v.ContactSHA256 = shaHex(raw)
		s.contact = raw
		s.hasC = true
	} else {
		s.contact = ""
		s.hasC = false
	}
	return v, nil
}

// Contact returns the stored bearer string. ErrNone means it is unset.
// The mode is checked on every read.
func (s *Store) Contact() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, ok, err := readContact(filepath.Join(s.dir, "contact"), nil)
	if err != nil {
		return "", err
	}
	if !ok {
		s.hasC = false
		s.contact = ""
		return "", ErrNone
	}
	s.contact = raw
	s.hasC = true
	return raw, nil
}

// PutConfig replaces the configuration. The caller has already probed paths.
func (s *Store) PutConfig(c Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	norm, err := Normalize(c)
	if err != nil {
		return err
	}
	b, err := codes.Marshal(norm)
	if err != nil {
		return codes.E(codes.Failed)
	}
	if err := writeAtomic(s.dir, "config.json", append(b, '\n'), 0o600); err != nil {
		return err
	}
	s.cfg = norm
	return nil
}

// PutContact stores the exact contact string with no newline.
func (s *Store) PutContact(raw string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if raw == "" || len(raw) > contactMax || strings.ContainsAny(raw, "\r\n\x00") {
		return codes.E(codes.BadContact)
	}
	if err := writeAtomic(s.dir, "contact", []byte(raw), 0o600); err != nil {
		return err
	}
	s.contact = raw
	s.hasC = true
	return nil
}

// PutBaseline replaces the baseline map.
func (s *Store) PutBaseline(m map[string]ids.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m == nil {
		m = map[string]ids.Record{}
	}
	for p, rec := range m {
		if !paths.IsAbsClean(p) || paths.IsRoot(p) || !hex64(rec.SHA256) || rec.Size < 0 {
			return codes.E(codes.BadPath)
		}
	}
	b, err := codes.Marshal(baselineFile{V: ids.BaselineVersion, Records: m})
	if err != nil {
		return codes.E(codes.Failed)
	}
	if err := writeAtomic(s.dir, "baseline.json", append(b, '\n'), 0o600); err != nil {
		return err
	}
	s.base = cloneBase(m)
	s.baseV = ids.BaselineVersion
	return nil
}

// PutIDS replaces detector memory.
func (s *Store) PutIDS(st IDSState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st = fillIDS(st)
	b, err := codes.Marshal(st)
	if err != nil {
		return codes.E(codes.Failed)
	}
	if err := writeAtomic(s.dir, "ids-state.json", append(b, '\n'), 0o600); err != nil {
		return err
	}
	s.ids = cloneIDS(st)
	return nil
}

// Spend records lease id until exp. A second unexpired use is grant_spent.
// The id stays spent when a later commit by the caller fails.
func (s *Store) Spend(id string, exp int64, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" {
		return codes.E(codes.GrantBadShape)
	}
	s.prune(now)
	if _, ok := s.spent[id]; ok {
		return codes.E(codes.GrantSpent)
	}
	if exp <= now.Unix() {
		return codes.E(codes.GrantExpired)
	}
	s.spent[id] = exp
	if err := s.persistSpent(); err != nil {
		delete(s.spent, id)
		return codes.E(codes.Failed)
	}
	return nil
}

// AppendAudit adds one chain row.
func (s *Store) AppendAudit(actor, lease, action string, detail json.RawMessage, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chain.Append(actor, lease, action, detail, now)
}

// AuditTail returns the last limit rows after a fresh verify.
func (s *Store) AuditTail(limit int) ([]audit.Row, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chain.Tail(limit)
}

// AuditCount re-verifies the chain. A failure marks it broken.
func (s *Store) AuditCount() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.chain.ReadAll()
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

// AppendEdge records one finding edge. A huge or long file keeps the tail.
func (s *Store) AppendEdge(rec []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(rec) == 0 || bytes.ContainsAny(rec, "\n\r") {
		return codes.E(codes.Failed)
	}
	path := filepath.Join(s.dir, "findings.jsonl")
	fi, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return codes.E(codes.Failed)
	}
	if err == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular()) {
		return codes.E(codes.Failed)
	}
	line := append(append([]byte{}, rec...), '\n')
	if os.IsNotExist(err) {
		return writeAtomic(s.dir, "findings.jsonl", line, 0o600)
	}
	data, rerr := readUpTo(path, edgeMaxBytes+1)
	corrupt := rerr != nil || (len(data) > 0 && data[len(data)-1] != '\n')
	if corrupt {
		return writeAtomic(s.dir, "findings.jsonl", line, 0o600)
	}
	if len(data) > edgeMaxBytes || bytes.Count(data, []byte{'\n'}) >= edgeMaxLines {
		kept := trimEdges(data)
		return writeAtomic(s.dir, "findings.jsonl", append(kept, line...), 0o600)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return codes.E(codes.Failed)
	}
	_, werr := f.Write(line)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		return codes.E(codes.Failed)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return codes.E(codes.Failed)
	}
	return nil
}

func trimEdges(data []byte) []byte {
	buf := data
	if len(buf) > edgeMaxBytes {
		buf = buf[len(buf)-edgeMaxBytes:]
		i := bytes.IndexByte(buf, '\n')
		if i < 0 {
			buf = nil
		} else {
			buf = buf[i+1:]
		}
	}
	parts := bytes.Split(buf, []byte{'\n'})
	if len(parts) > 0 && len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > edgeMaxLines-1 {
		parts = parts[len(parts)-(edgeMaxLines-1):]
	}
	if len(parts) == 0 {
		return nil
	}
	return append(bytes.Join(parts, []byte{'\n'}), '\n')
}

// DecodeConfig parses an API config body. Syntax and shape errors are bad_path.
func DecodeConfig(body []byte) (Config, error) {
	c, err := parseConfig(body)
	if err != nil {
		if codes.Code(err) == codes.BadPath {
			return Config{}, err
		}
		return Config{}, codes.E(codes.BadPath)
	}
	return c, nil
}

// Normalize applies defaults and rejects a config that cannot be stored.
func Normalize(c Config) (Config, error) {
	if err := modules.Validate(c.Modules); err != nil {
		return Config{}, codes.E(codes.BadPath)
	}
	c.Modules = modules.CloneConfig(c.Modules)
	var err error
	c.AuthFailLimit, err = normLimit(c.AuthFailLimit, defFailLimit, 1, 1000)
	if err != nil {
		return Config{}, err
	}
	c.AuthWindowS, err = normLimit(c.AuthWindowS, defWindowS, 1, 3600)
	if err != nil {
		return Config{}, err
	}
	if c.AuthLog != "" && (!paths.IsAbsClean(c.AuthLog) || paths.IsRoot(c.AuthLog)) {
		return Config{}, codes.E(codes.BadPath)
	}
	if c.Watch == nil {
		c.Watch = []string{}
	}
	if len(c.Watch) > watchMax {
		return Config{}, codes.E(codes.BadPath)
	}
	seen := map[string]struct{}{}
	for _, p := range c.Watch {
		if !paths.IsAbsClean(p) || paths.IsRoot(p) {
			return Config{}, codes.E(codes.BadPath)
		}
		if _, ok := seen[p]; ok {
			return Config{}, codes.E(codes.BadPath)
		}
		seen[p] = struct{}{}
	}
	if c.ListenAllow == nil {
		c.ListenAllow = []string{}
	}
	if len(c.ListenAllow) > listenMax {
		return Config{}, codes.E(codes.BadPath)
	}
	heard := map[string]struct{}{}
	for i, raw := range c.ListenAllow {
		canon, err := canonListen(raw)
		if err != nil {
			return Config{}, err
		}
		if _, ok := heard[canon]; ok {
			return Config{}, codes.E(codes.BadPath)
		}
		heard[canon] = struct{}{}
		c.ListenAllow[i] = canon
	}
	return c, nil
}

// Listener tables the listen detector reads. A listen_allow change governs
// them, so it needs a grant that covers both.
var listenInputs = []string{"/proc/net/tcp", "/proc/net/tcp6"}

// AllowChange returns nil when covers authorizes every changed field. An
// unchanged path may stay outside the grant roots. A changed watch, auth_log,
// or module path is forbidden when uncovered.
//
// Threats: a grant scoped to one path must not change a global field. Each
// global field needs coverage of what it governs: listen_allow needs both
// listener tables; auth_fail_limit and auth_window_s need every auth_log set
// before or after, and at least one must be set. Otherwise config_scope.
func AllowChange(old, neu Config, covers func(string) bool) error {
	if covers == nil {
		covers = func(string) bool { return false }
	}
	if !modules.ChangeAllowed(old.Modules, neu.Modules, covers) {
		return codes.E(codes.Forbidden)
	}
	if old.AuthLog != neu.AuthLog {
		if old.AuthLog != "" && !covers(old.AuthLog) {
			return codes.E(codes.Forbidden)
		}
		if neu.AuthLog != "" && !covers(neu.AuthLog) {
			return codes.E(codes.Forbidden)
		}
	}
	prev := map[string]struct{}{}
	for _, p := range old.Watch {
		prev[p] = struct{}{}
	}
	next := map[string]struct{}{}
	for _, p := range neu.Watch {
		next[p] = struct{}{}
	}
	for p := range prev {
		if _, ok := next[p]; !ok && !covers(p) {
			return codes.E(codes.Forbidden)
		}
	}
	for p := range next {
		if _, ok := prev[p]; !ok && !covers(p) {
			return codes.E(codes.Forbidden)
		}
	}
	if !sameSet(old.ListenAllow, neu.ListenAllow) {
		for _, p := range listenInputs {
			if !covers(p) {
				return codes.E(codes.ConfigScope)
			}
		}
	}
	if old.AuthFailLimit != neu.AuthFailLimit || old.AuthWindowS != neu.AuthWindowS {
		if old.AuthLog == "" && neu.AuthLog == "" {
			return codes.E(codes.ConfigScope)
		}
		for _, p := range []string{old.AuthLog, neu.AuthLog} {
			if p != "" && !covers(p) {
				return codes.E(codes.ConfigScope)
			}
		}
	}
	return nil
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]struct{}, len(a))
	for _, s := range a {
		m[s] = struct{}{}
	}
	for _, s := range b {
		if _, ok := m[s]; !ok {
			return false
		}
	}
	return true
}

// ProbePaths Lstats auth_log and watch paths. A missing path is allowed.
// A symlink, directory, or unreadable path is bad_path and is not followed.
func ProbePaths(c Config) error {
	list := make([]string, 0, 1+len(c.Watch))
	if c.AuthLog != "" {
		list = append(list, c.AuthLog)
	}
	list = append(list, c.Watch...)
	for _, p := range list {
		fi, err := os.Lstat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return codes.E(codes.BadPath)
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
			return codes.E(codes.BadPath)
		}
	}
	return nil
}

func canonListen(s string) (string, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil || strings.Contains(host, "%") {
		return "", codes.E(codes.BadPath)
	}
	ip := net.ParseIP(host)
	if ip == nil || port == "" || (len(port) > 1 && port[0] == '0') {
		return "", codes.E(codes.BadPath)
	}
	n, err := strconv.Atoi(port)
	if err != nil || strconv.Itoa(n) != port || n < 1 || n > 65535 {
		return "", codes.E(codes.BadPath)
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(n)), nil
}

func normLimit(v, def, min, max int) (int, error) {
	if v == 0 {
		return def, nil
	}
	if v < min || v > max {
		return 0, codes.E(codes.BadPath)
	}
	return v, nil
}

func (s *Store) loadConfig() (Config, error) {
	b, err := readState(filepath.Join(s.dir, "config.json"), fileMax)
	if err != nil {
		if os.IsNotExist(err) {
			return freshConfig(), nil
		}
		return Config{}, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return Config{}, codes.E(codes.Failed)
	}
	c, err := parseConfig(b)
	if err != nil {
		if codes.Code(err) == codes.BadPath {
			return Config{}, err
		}
		return Config{}, codes.E(codes.Failed)
	}
	return c, nil
}

func parseConfig(body []byte) (Config, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return Config{}, err
	}
	if dec.More() {
		return Config{}, errors.New("trailing")
	}
	return Normalize(c)
}

func freshConfig() Config {
	return Config{AuthFailLimit: defFailLimit, AuthWindowS: defWindowS, Watch: []string{}, ListenAllow: []string{}}
}

// baselineFile is baseline.json from version 2 on. Version 1 was the bare
// path-to-record map.
type baselineFile struct {
	V       int                   `json:"v"`
	Records map[string]ids.Record `json:"records"`
}

// loadBaseline returns the records and the format version. A missing file is
// an empty current baseline.
func (s *Store) loadBaseline() (map[string]ids.Record, int, error) {
	b, err := readState(filepath.Join(s.dir, "baseline.json"), fileMax)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]ids.Record{}, ids.BaselineVersion, nil
		}
		return nil, 0, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, 0, codes.E(codes.Failed)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil || dec.More() {
		return nil, 0, codes.E(codes.Failed)
	}
	version := 1
	if _, ok := raw["v"]; ok {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		var f struct {
			V       int                        `json:"v"`
			Records map[string]json.RawMessage `json:"records"`
		}
		if err := dec.Decode(&f); err != nil || dec.More() || f.V != ids.BaselineVersion {
			return nil, 0, codes.E(codes.Failed)
		}
		version = f.V
		raw = f.Records
	}
	if raw == nil {
		raw = map[string]json.RawMessage{}
	}
	out := make(map[string]ids.Record, len(raw))
	for p, msg := range raw {
		if !paths.IsAbsClean(p) || paths.IsRoot(p) {
			return nil, 0, codes.E(codes.BadPath)
		}
		rd := json.NewDecoder(bytes.NewReader(msg))
		rd.DisallowUnknownFields()
		var rec ids.Record
		if err := rd.Decode(&rec); err != nil || rd.More() {
			return nil, 0, codes.E(codes.Failed)
		}
		if !hex64(rec.SHA256) || rec.Size < 0 {
			return nil, 0, codes.E(codes.Failed)
		}
		if version == 1 && (rec.Mode&^0o777 != 0 || rec.UID != 0 || rec.GID != 0) {
			return nil, 0, codes.E(codes.Failed)
		}
		out[p] = rec
	}
	return out, version, nil
}

func (s *Store) loadIDS() (IDSState, error) {
	b, err := readState(filepath.Join(s.dir, "ids-state.json"), fileMax)
	if err != nil {
		if os.IsNotExist(err) {
			return freshIDS(), nil
		}
		return IDSState{}, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return IDSState{}, codes.E(codes.Failed)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var st IDSState
	if err := dec.Decode(&st); err != nil || dec.More() {
		return IDSState{}, codes.E(codes.Failed)
	}
	if st.AuthOffset < 0 {
		return IDSState{}, codes.E(codes.Failed)
	}
	if st.LastScan != "" {
		if _, err := time.Parse(time.RFC3339Nano, st.LastScan); err != nil {
			return IDSState{}, codes.E(codes.Failed)
		}
	}
	switch st.Listen {
	case "", ids.StateOff, ids.StateOK, ids.StateBad, ids.StateWait:
	default:
		return IDSState{}, codes.E(codes.Failed)
	}
	st = fillIDS(st)
	for _, rec := range st.Open {
		if rec.Kind == "" || (rec.Severity != ids.SevHigh && rec.Severity != ids.SevMedium) {
			return IDSState{}, codes.E(codes.Failed)
		}
	}
	return st, nil
}

func freshIDS() IDSState {
	return IDSState{AuthEvents: []int64{}, Open: map[string]OpenRec{}, Coalesce: map[string]int64{}}
}

func fillIDS(st IDSState) IDSState {
	if st.AuthEvents == nil {
		st.AuthEvents = []int64{}
	}
	if st.Open == nil {
		st.Open = map[string]OpenRec{}
	}
	if st.Coalesce == nil {
		st.Coalesce = map[string]int64{}
	}
	return st
}

func (s *Store) loadSpent(now time.Time) (map[string]int64, error) {
	b, err := readState(filepath.Join(s.dir, "spent.json"), fileMax)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]int64{}, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, codes.E(codes.Failed)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f spentFile
	if err := dec.Decode(&f); err != nil || dec.More() {
		return nil, codes.E(codes.Failed)
	}
	if f.Leases == nil {
		f.Leases = map[string]int64{}
	}
	s.spent = f.Leases
	s.prune(now)
	return s.spent, nil
}

func (s *Store) prune(now time.Time) {
	if s.spent == nil {
		s.spent = map[string]int64{}
	}
	n := now.Unix()
	for id, exp := range s.spent {
		if exp <= n {
			delete(s.spent, id)
		}
	}
}

func (s *Store) persistSpent() error {
	b, err := codes.Marshal(spentFile{Leases: s.spent})
	if err != nil {
		return err
	}
	return writeAtomic(s.dir, "spent.json", append(b, '\n'), 0o600)
}

func (s *Store) checkEdges() error {
	path := filepath.Join(s.dir, "findings.jsonl")
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return codes.E(codes.Failed)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return codes.E(codes.Failed)
	}
	return os.Chmod(path, 0o600)
}

func readContact(path string, parse func(string) error) (string, bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, codes.E(codes.Failed)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return "", false, codes.E(codes.Failed)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", false, codes.E(codes.Failed)
	}
	if fi.Size() > contactMax {
		return "", false, codes.E(codes.BadContact)
	}
	b, err := readUpTo(path, contactMax+1)
	if err != nil {
		return "", false, codes.E(codes.Failed)
	}
	if len(b) > contactMax {
		return "", false, codes.E(codes.BadContact)
	}
	raw := string(b)
	if parse != nil {
		if err := parse(raw); err != nil {
			return "", false, err
		}
	}
	return raw, true, nil
}

func readState(path string, max int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, codes.E(codes.Failed)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, codes.E(codes.Failed)
	}
	b, err := readUpTo(path, max+1)
	if err != nil {
		return nil, codes.E(codes.Failed)
	}
	if int64(len(b)) > max {
		return nil, codes.E(codes.Failed)
	}
	return b, nil
}

func readUpTo(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

func writeAtomic(dir, name string, data []byte, mode os.FileMode) error {
	dest := filepath.Join(dir, name)
	if fi, err := os.Lstat(dest); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return codes.E(codes.Failed)
		}
	} else if !os.IsNotExist(err) {
		return codes.E(codes.Failed)
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return codes.E(codes.Failed)
	}
	tmp := filepath.Join(dir, ".tmp."+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return codes.E(codes.Failed)
	}
	done := false
	defer func() {
		if !done {
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return codes.E(codes.Failed)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return codes.E(codes.Failed)
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return codes.E(codes.Failed)
	}
	if err := f.Close(); err != nil {
		return codes.E(codes.Failed)
	}
	if err := os.Rename(tmp, dest); err != nil {
		return codes.E(codes.Failed)
	}
	done = true
	if err := syncDir(dir); err != nil {
		return codes.E(codes.Failed)
	}
	if err := os.Chmod(dest, mode); err != nil {
		return codes.E(codes.Failed)
	}
	return nil
}

func syncDir(dir string) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	err = unix.Fsync(fd)
	cerr := unix.Close(fd)
	if err != nil {
		return err
	}
	return cerr
}

func cloneConfig(c Config) Config {
	out := c
	out.Modules = modules.CloneConfig(c.Modules)
	out.Watch = append([]string{}, c.Watch...)
	out.ListenAllow = append([]string{}, c.ListenAllow...)
	if out.Watch == nil {
		out.Watch = []string{}
	}
	if out.ListenAllow == nil {
		out.ListenAllow = []string{}
	}
	return out
}

func cloneBase(m map[string]ids.Record) map[string]ids.Record {
	out := make(map[string]ids.Record, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneIDS(st IDSState) IDSState {
	st = fillIDS(st)
	st.System = modules.CloneSnapshot(st.System)
	ev := append([]int64{}, st.AuthEvents...)
	open := make(map[string]OpenRec, len(st.Open))
	for k, v := range st.Open {
		open[k] = v
	}
	co := make(map[string]int64, len(st.Coalesce))
	for k, v := range st.Coalesce {
		co[k] = v
	}
	st.AuthEvents = ev
	st.Open = open
	st.Coalesce = co
	return st
}

func shaHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hex64(s string) bool {
	if len(s) != 64 || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
