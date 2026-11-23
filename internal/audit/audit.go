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

// Open verifies path against its anchor and remembers the tail. A missing
// chain with no anchor is a fresh store. A symlink or a broken chain is
// audit_bad. A non-empty chain with no anchor, a chain short of its anchor,
// or a chain more than one row past it is audit_truncated; a chain written
// before anchors existed is anchored once with Anchor, by the operator. An
// anchor exactly one row behind (a crash between the row and the anchor) is
// moved up.
func Open(path string) (*Chain, error) {
	rows, a, _, err := load(path)
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
	if c.seq != 0 && a.Seq != c.seq {
		if err := writeHead(HeadPath(path), anchor{Seq: c.seq, Hash: c.prev}); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Anchor is the operator step for a chain written before anchors existed. It
// verifies the whole chain, writes the anchor, and appends an
// audit.anchor_init row naming the seq and hash it anchored. An existing
// anchor is anchor_exists; an empty chain needs none and is left alone. The
// caller must hold the store lock so no daemon appends meanwhile.
func Anchor(path string, now time.Time) (int, error) {
	head := HeadPath(path)
	if _, err := os.Lstat(head); err == nil {
		return 0, codes.E(codes.AnchorExists)
	} else if !os.IsNotExist(err) {
		return 0, codes.E(codes.AuditBad)
	}
	rows, err := readAll(path)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	last := rows[len(rows)-1]
	if err := writeHead(head, anchor{Seq: last.Seq, Hash: last.Hash}); err != nil {
		return 0, err
	}
	detail, err := codes.Marshal(struct {
		Seq  int64  `json:"seq"`
		Hash string `json:"hash"`
	}{last.Seq, last.Hash})
	if err != nil {
		return 0, codes.E(codes.Failed)
	}
	c := &Chain{path: path, seq: last.Seq, prev: last.Hash}
	if err := c.Append("secsvc", "", "audit.anchor_init", detail, now); err != nil {
		return 0, err
	}
	return len(rows) + 1, nil
}

// VerifyFile checks the chain against its anchor and returns the row count.
// A missing chain with no anchor is empty. It never writes. A running daemon
// writes the row before the anchor, so a reader in another process retries a
// short while before it calls the chain truncated.
func VerifyFile(path string) (int, error) {
	var err error
	for i := 0; i < 3; i++ {
		var rows []Row
		rows, _, _, err = load(path)
		if err == nil {
			return len(rows), nil
		}
		if codes.Code(err) != codes.AuditTruncated {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return 0, err
}

// load reads the anchor first, then the chain. The chain must hold the
// anchor's row and at most one row past it, the only state a crash between
// the row and the anchor can leave. A non-empty chain with no anchor is
// truncated: the anchor is created with the first row.
func load(path string) ([]Row, anchor, bool, error) {
	a, ok, err := readHead(HeadPath(path))
	if err != nil {
		return nil, anchor{}, false, err
	}
	rows, err := readAll(path)
	if err != nil {
		return nil, anchor{}, false, err
	}
	n := int64(len(rows))
	if !ok {
		if n > 0 {
			return nil, anchor{}, false, codes.E(codes.AuditTruncated)
		}
		return rows, a, false, nil
	}
	if n < a.Seq || n > a.Seq+1 || rows[a.Seq-1].Hash != a.Hash {
		return nil, anchor{}, false, codes.E(codes.AuditTruncated)
	}
	return rows, a, true, nil
}

// openState opens a state file O_NONBLOCK|O_NOFOLLOW and refuses anything
// fstat does not call regular, so a FIFO swapped in never blocks a read.
// A missing file keeps its not-exist error.
func openState(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if err == unix.ENOENT {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, codes.E(codes.AuditBad)
	}
	return os.NewFile(uintptr(fd), path), nil
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
	f, err := openState(path)
	if err != nil {
		return anchor{}, false, codes.E(codes.AuditBad)
	}
	defer f.Close()
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
	// This chain wrote row c.seq; the file must still hold it, unchanged.
	if c.seq > 0 && (int64(len(rows)) < c.seq || rows[c.seq-1].Hash != c.prev) {
		c.broken = true
		return nil, codes.E(codes.AuditTruncated)
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
	f, err := openState(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
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
