// Package audit is the host's append-only hash chain.
//
// Threats: a rewritten, reordered, truncated, or extra-field line must fail
// verification. The chain does not store contact URLs, grant documents, or
// keys. A symlink is not followed. A failed append marks the chain broken so
// later appends fail closed. This is the host record; it is not cp_audit.
//
// Threats (truncation): a local anchor, audit.head, holds the last seq and
// hash. It is written atomically after each append. A chain that ends before
// the anchor's seq, whose row at that seq has another hash, or that is missing
// while the anchor exists is audit_truncated. The anchor is read before the
// chain so a concurrent append never looks like a truncation. Residual: root
// can rewrite both files together; an off-host anchor is a later batch.
package audit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"golang.org/x/sys/unix"
)

const (
	MaxLine   = 64 << 10
	MaxDetail = 8 << 10
	headMax   = 1 << 10
)

// Genesis is the prev value of the first row: 64 zero hex chars.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Row is one verified audit record.
type Row struct {
	Seq     int64
	Prev    string
	Time    string
	Actor   string
	LeaseID string
	Action  string
	Detail  json.RawMessage
	Hash    string
}

type body struct {
	Seq     int64           `json:"seq"`
	Prev    string          `json:"prev"`
	Time    string          `json:"time"`
	Actor   string          `json:"actor"`
	LeaseID string          `json:"lease_id"`
	Action  string          `json:"action"`
	Detail  json.RawMessage `json:"detail"`
}

type stored struct {
	body
	Hash string `json:"hash"`
}

// Chain is an open audit.jsonl. Appends are serialized.
type Chain struct {
	mu     sync.Mutex
	path   string
	seq    int64
	prev   string
	broken bool
}

// anchor is the content of audit.head.
type anchor struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}

// HeadPath is the anchor file kept next to the chain: audit.jsonl -> audit.head.
func HeadPath(path string) string {
	return strings.TrimSuffix(path, ".jsonl") + ".head"
}

// Open verifies path and remembers the tail. A missing file with no anchor is
// an empty chain. A symlink or a broken chain is audit_bad; a chain shorter
// than its anchor is audit_truncated. A chain written before the anchor
// existed gets one, plus an audit.anchor_init row naming the seq it starts at.
// An anchor behind the chain (a crash between the two writes) is moved up.
func Open(path string) (*Chain, error) {
	rows, a, hasAnchor, err := load(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, codes.E(codes.Failed)
		}
	}
	c := &Chain{path: path, prev: Genesis}
	if n := len(rows); n > 0 {
		c.seq = rows[n-1].Seq
		c.prev = rows[n-1].Hash
	}
	if c.seq == 0 {
		return c, nil
	}
	if !hasAnchor {
		detail, err := codes.Marshal(struct {
			Seq int64 `json:"seq"`
		}{c.seq})
		if err != nil {
			return nil, codes.E(codes.Failed)
		}
		if err := c.Append("secsvc", "", "audit.anchor_init", detail, time.Now()); err != nil {
			return nil, err
		}
		return c, nil
	}
	if a.Seq != c.seq {
		if err := writeHead(HeadPath(path), anchor{Seq: c.seq, Hash: c.prev}); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// VerifyFile checks the chain against its anchor and returns the row count.
// A missing chain with no anchor is empty. It never writes.
func VerifyFile(path string) (int, error) {
	rows, _, _, err := load(path)
	if err != nil {
		return 0, err
	}
	return len(rows), nil
}

// load reads the anchor first, then the chain, so an append between the two
// reads leaves the chain at or past the anchor.
func load(path string) ([]Row, anchor, bool, error) {
	a, ok, err := readHead(HeadPath(path))
	if err != nil {
		return nil, anchor{}, false, err
	}
	rows, err := readAll(path)
	if err != nil {
		return nil, anchor{}, false, err
	}
	if ok && (int64(len(rows)) < a.Seq || rows[a.Seq-1].Hash != a.Hash) {
		return nil, anchor{}, false, codes.E(codes.AuditTruncated)
	}
	return rows, a, ok, nil
}

func readHead(path string) (anchor, bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return anchor{}, false, nil
		}
		return anchor{}, false, codes.E(codes.AuditBad)
	}
	if !fi.Mode().IsRegular() {
		return anchor{}, false, codes.E(codes.AuditBad)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return anchor{}, false, codes.E(codes.AuditBad)
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return anchor{}, false, codes.E(codes.AuditBad)
	}
	data, err := io.ReadAll(io.LimitReader(f, headMax+1))
	if err != nil || len(data) > headMax {
		return anchor{}, false, codes.E(codes.AuditBad)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var a anchor
	if err := dec.Decode(&a); err != nil || dec.More() || a.Seq < 1 || !lowerHex(a.Hash) {
		return anchor{}, false, codes.E(codes.AuditBad)
	}
	return a, true, nil
}

// writeHead replaces the anchor: temp file, fsync, rename, directory fsync.
func writeHead(path string, a anchor) error {
	b, err := codes.Marshal(a)
	if err != nil {
		return codes.E(codes.Failed)
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return codes.E(codes.Failed)
	}
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, ".head."+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return codes.E(codes.Failed)
	}
	_, werr := f.Write(append(b, '\n'))
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		os.Remove(tmp)
		return codes.E(codes.Failed)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return codes.E(codes.Failed)
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return codes.E(codes.Failed)
	}
	serr = unix.Fsync(fd)
	cerr = unix.Close(fd)
	if serr != nil || cerr != nil {
		return codes.E(codes.Failed)
	}
	return nil
}

// Append writes one row. detail nil becomes {}. The in-memory tail moves only
// after the line is fsynced.
func (c *Chain) Append(actor, lease, action string, detail json.RawMessage, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken {
		return codes.E(codes.AuditBad)
	}
	det, err := compactDetail(detail)
	if err != nil {
		return err
	}
	b := body{
		Seq:     c.seq + 1,
		Prev:    c.prev,
		Time:    now.UTC().Format(time.RFC3339Nano),
		Actor:   actor,
		LeaseID: lease,
		Action:  action,
		Detail:  det,
	}
	raw, err := codes.Marshal(b)
	if err != nil {
		c.broken = true
		return codes.E(codes.Failed)
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	line, err := codes.Marshal(stored{body: b, Hash: hash})
	if err != nil {
		c.broken = true
		return codes.E(codes.Failed)
	}
	if len(line) > MaxLine {
		c.broken = true
		return codes.E(codes.AuditBad)
	}
	f, err := os.OpenFile(c.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		c.broken = true
		return codes.E(codes.AuditBad)
	}
	_, werr := f.Write(append(line, '\n'))
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		c.broken = true
		return codes.E(codes.Failed)
	}
	if err := os.Chmod(c.path, 0o600); err != nil {
		c.broken = true
		return codes.E(codes.Failed)
	}
	c.seq = b.Seq
	c.prev = hash
	if err := writeHead(HeadPath(c.path), anchor{Seq: c.seq, Hash: c.prev}); err != nil {
		c.broken = true
		return err
	}
	return nil
}

// ReadAll re-verifies the file. A failure marks the chain broken.
func (c *Chain) ReadAll() ([]Row, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rows, _, _, err := load(c.path)
	if err != nil {
		c.broken = true
		return nil, err
	}
	c.seq = 0
	c.prev = Genesis
	if n := len(rows); n > 0 {
		c.seq = rows[n-1].Seq
		c.prev = rows[n-1].Hash
	}
	return rows, nil
}

// Tail returns the last limit rows in chain order. limit <= 0 returns all.
func (c *Chain) Tail(limit int) ([]Row, error) {
	rows, err := c.ReadAll()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit >= len(rows) {
		return rows, nil
	}
	return append([]Row(nil), rows[len(rows)-limit:]...), nil
}

func compactDetail(d json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(d)) == 0 {
		return json.RawMessage(`{}`), nil
	}
	if len(d) > MaxDetail {
		return nil, codes.E(codes.Failed)
	}
	dec := json.NewDecoder(bytes.NewReader(d))
	var obj map[string]json.RawMessage
	if err := dec.Decode(&obj); err != nil || dec.More() {
		return nil, codes.E(codes.Failed)
	}
	out, err := codes.Marshal(obj)
	if err != nil || len(out) > MaxDetail {
		return nil, codes.E(codes.Failed)
	}
	return out, nil
}

func readAll(path string) ([]Row, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, codes.E(codes.AuditBad)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, codes.E(codes.AuditBad)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, codes.E(codes.AuditBad)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, codes.E(codes.AuditBad)
	}
	if len(data) == 0 {
		return nil, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, codes.E(codes.AuditBad)
	}
	parts := bytes.Split(data[:len(data)-1], []byte{'\n'})
	rows := make([]Row, 0, len(parts))
	prev := Genesis
	for i, p := range parts {
		row, err := checkLine(p, int64(i+1), prev)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
		prev = row.Hash
	}
	return rows, nil
}

func checkLine(p []byte, seq int64, prev string) (Row, error) {
	if len(p) == 0 || len(p) > MaxLine {
		return Row{}, codes.E(codes.AuditBad)
	}
	dec := json.NewDecoder(bytes.NewReader(p))
	dec.DisallowUnknownFields()
	var ln stored
	if err := dec.Decode(&ln); err != nil || dec.More() {
		return Row{}, codes.E(codes.AuditBad)
	}
	if ln.Seq != seq || ln.Prev != prev {
		return Row{}, codes.E(codes.AuditBad)
	}
	if !lowerHex(ln.Hash) {
		return Row{}, codes.E(codes.AuditBad)
	}
	if len(bytes.TrimSpace(ln.Detail)) == 0 || len(ln.Detail) > MaxDetail || !jsonObject(ln.Detail) {
		return Row{}, codes.E(codes.AuditBad)
	}
	raw, err := codes.Marshal(ln.body)
	if err != nil {
		return Row{}, codes.E(codes.AuditBad)
	}
	sum := sha256.Sum256(raw)
	got, err := hex.DecodeString(ln.Hash)
	if err != nil || len(got) != sha256.Size {
		return Row{}, codes.E(codes.AuditBad)
	}
	if subtle.ConstantTimeCompare(sum[:], got) != 1 {
		return Row{}, codes.E(codes.AuditBad)
	}
	return Row{
		Seq: ln.Seq, Prev: ln.Prev, Time: ln.Time, Actor: ln.Actor,
		LeaseID: ln.LeaseID, Action: ln.Action, Detail: append(json.RawMessage(nil), ln.Detail...),
		Hash: ln.Hash,
	}, nil
}

func jsonObject(d json.RawMessage) bool {
	dec := json.NewDecoder(bytes.NewReader(d))
	var obj map[string]json.RawMessage
	return dec.Decode(&obj) == nil && !dec.More()
}

func lowerHex(s string) bool {
	if len(s) != 64 || s != strings.ToLower(s) {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
