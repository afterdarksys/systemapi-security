// Package audit is the host's append-only hash chain.
//
// Threats: a rewritten, reordered, truncated, or extra-field line must fail
// verification. The chain does not store contact URLs, grant documents, or
// keys. A symlink is not followed. A failed append marks the chain broken so
// later appends fail closed. This is the host record; it is not cp_audit.
package audit

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"golang.org/x/sys/unix"
)

const (
	MaxLine   = 64 << 10
	MaxDetail = 8 << 10
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

// Open verifies path and remembers the tail. A missing file is an empty chain.
// A symlink or a broken chain is audit_bad.
func Open(path string) (*Chain, error) {
	rows, err := readAll(path)
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
	return c, nil
}

// VerifyFile checks the chain and returns the row count. A missing file is empty.
func VerifyFile(path string) (int, error) {
	rows, err := readAll(path)
	if err != nil {
		return 0, err
	}
	return len(rows), nil
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
	return nil
}

// ReadAll re-verifies the file. A failure marks the chain broken.
func (c *Chain) ReadAll() ([]Row, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rows, err := readAll(c.path)
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
