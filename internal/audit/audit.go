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
// can rewrite every file together; the signed head and stored witnesses
// (head.go) let an off-host party catch that.
//
// Threats (size): rows live in capped segments, audit/NNNNNN.jsonl. The hash
// chain runs across segments. A runtime read (status, the tail, the head)
// reads only the newest segment, the index, the anchor and the witness file,
// so it is bounded; only a full verify walks every segment, line by line
// with a bounded buffer, and only it catches a rewritten old segment.
package audit

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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
	indexMax  = 1 << 20

	// SegDir holds the segments and their index inside the state directory.
	SegDir = "audit"
	// IndexName is the closed-segment index inside SegDir.
	IndexName = "segments.json"
	// HeadName is the anchor inside the state directory.
	HeadName = "audit.head"
	// LegacyName is the single-file chain from before segments.
	LegacyName = "audit.jsonl"

	DefaultSegBytes = 4 << 20
	DefaultSegRows  = 20000
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

// anchor is the content of audit.head.
type anchor struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}

// entry is one closed segment in the index. Entry i is segment i+1.
type entry struct {
	First int64  `json:"first"`
	Last  int64  `json:"last"`
	Hash  string `json:"hash"`
}

type indexFile struct {
	V        int     `json:"v"`
	Segments []entry `json:"segments"`
}

// Options caps a segment. Zero values take the defaults. A segment rolls
// before a row that would pass either cap, so it holds at least one row.
type Options struct {
	SegBytes int64
	SegRows  int
}

func (o Options) norm() (Options, error) {
	if o.SegBytes == 0 {
		o.SegBytes = DefaultSegBytes
	}
	if o.SegRows == 0 {
		o.SegRows = DefaultSegRows
	}
	// Two rows at least, so the audit.pruned row written after a roll never
	// rolls again by row count.
	if o.SegBytes < 1 || o.SegBytes > DefaultSegBytes || o.SegRows < 2 || o.SegRows > DefaultSegRows {
		return Options{}, codes.E(codes.Failed)
	}
	return o, nil
}

// Chain is an open segmented chain. Appends are serialized.
type Chain struct {
	mu    sync.Mutex
	dir   string
	opt   Options
	keep  int
	index []entry
	seg   int   // the open segment: len(index)+1
	rows  int   // rows in the open segment
	size  int64 // bytes in the open segment
	seq   int64
	prev  string
	low   int // lowest segment number still on disk
	wit   *Witness
	// walking counts full walks in progress; prune defers deletes meanwhile.
	walking int
	broken  bool
}

func segName(n int) string { return fmt.Sprintf("%06d.jsonl", n) }

func segPath(dir string, n int) string {
	return filepath.Join(dir, SegDir, segName(n))
}

// checkLayout refuses the single-file chain: it is moved only by Migrate.
func checkLayout(dir string) error {
	_, err := os.Lstat(filepath.Join(dir, LegacyName))
	if err == nil {
		return codes.E(codes.AuditLayout)
	}
	if !os.IsNotExist(err) {
		return codes.E(codes.AuditBad)
	}
	return nil
}

// segDir reports whether SegDir exists as a real directory.
func segDir(dir string) (bool, error) {
	fi, err := os.Lstat(filepath.Join(dir, SegDir))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, codes.E(codes.AuditBad)
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return false, codes.E(codes.AuditBad)
	}
	return true, nil
}

// Open verifies the newest segment against the index and the anchor and
// remembers the tail. A fresh store gets an empty SegDir. The old single-file
// layout is audit_layout. keep is the number of closed segments retained
// (0 keeps all). An anchor exactly one row behind (a crash between the row
// and the anchor) is moved up.
func Open(dir string, opt Options, keep int) (*Chain, error) {
	opt, err := opt.norm()
	if err != nil || keep < 0 {
		return nil, codes.E(codes.Failed)
	}
	if err := checkLayout(dir); err != nil {
		return nil, err
	}
	ok, err := segDir(dir)
	if err != nil {
		return nil, err
	}
	if !ok {
		if err := os.Mkdir(filepath.Join(dir, SegDir), 0o700); err != nil {
			return nil, codes.E(codes.AuditBad)
		}
	}
	if err := os.Chmod(filepath.Join(dir, SegDir), 0o700); err != nil {
		return nil, codes.E(codes.Failed)
	}
	t, err := loadTail(dir)
	if err != nil {
		return nil, err
	}
	c := &Chain{dir: dir, opt: opt, keep: keep, index: t.index, seg: len(t.index) + 1, rows: len(t.rows), size: t.size}
	c.seq, c.prev = t.end()
	if c.seq != 0 && t.a.Seq != c.seq {
		if err := writeAtomic(filepath.Join(dir, HeadName), anchor{Seq: c.seq, Hash: c.prev}); err != nil {
			return nil, err
		}
	}
	if c.low, err = lowest(dir, len(c.index)); err != nil {
		return nil, err
	}
	w, err := lastWitness(dir)
	if err != nil {
		return nil, err
	}
	if w != nil {
		if err := c.checkWitness(*w, t.rows); err != nil {
			return nil, err
		}
	}
	c.wit = w
	return c, nil
}

// SetKeep changes how many closed segments are retained. It applies at the
// next roll.
func (c *Chain) SetKeep(keep int) error {
	if keep < 0 {
		return codes.E(codes.Failed)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keep = keep
	return nil
}

// lowest returns the lowest segment number on disk: one past the highest
// missing closed segment.
func lowest(dir string, closed int) (int, error) {
	for n := closed; n >= 1; n-- {
		fi, err := os.Lstat(segPath(dir, n))
		if err != nil {
			if os.IsNotExist(err) {
				return n + 1, nil
			}
			return 0, codes.E(codes.AuditBad)
		}
		if !fi.Mode().IsRegular() {
			return 0, codes.E(codes.AuditBad)
		}
	}
	return 1, nil
}

// tail is what a runtime read sees: the anchor, the index and the newest
// segment.
type tail struct {
	a     anchor
	hasA  bool
	index []entry
	rows  []Row
	size  int64
}

func (t tail) end() (int64, string) {
	if n := len(t.rows); n > 0 {
		return t.rows[n-1].Seq, t.rows[n-1].Hash
	}
	if n := len(t.index); n > 0 {
		return t.index[n-1].Last, t.index[n-1].Hash
	}
	return 0, Genesis
}

// link is the first seq and prev hash of the segment after idx.
func link(idx []entry) (int64, string) {
	if n := len(idx); n > 0 {
		return idx[n-1].Last + 1, idx[n-1].Hash
	}
	return 1, Genesis
}

// loadTail reads the anchor first, then the index and the newest segment.
// The newest segment's first row must link to the index's last entry, no
// segment may sit past it, and the chain must end at the anchor or exactly
// one row past it.
func loadTail(dir string) (tail, error) {
	if err := checkLayout(dir); err != nil {
		return tail{}, err
	}
	a, hasA, err := readHead(filepath.Join(dir, HeadName))
	if err != nil {
		return tail{}, err
	}
	t := tail{a: a, hasA: hasA}
	ok, err := segDir(dir)
	if err != nil {
		return tail{}, err
	}
	if ok {
		if t.index, err = readIndex(dir); err != nil {
			return tail{}, err
		}
		n := len(t.index) + 1
		if _, err := os.Lstat(segPath(dir, n+1)); err == nil || !os.IsNotExist(err) {
			return tail{}, codes.E(codes.AuditBad)
		}
		data, err := readCapped(segPath(dir, n), DefaultSegBytes)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return tail{}, err
		}
		first, prev := link(t.index)
		if t.rows, err = parseRows(data, first, prev); err != nil {
			return tail{}, err
		}
		t.size = int64(len(data))
	}
	seq, hash := t.end()
	before := ""
	if n := len(t.rows); n > 0 {
		before = t.rows[n-1].Prev
	}
	if err := checkAnchor(a, hasA, seq, hash, before, len(t.rows) > 0); err != nil {
		return tail{}, err
	}
	return t, nil
}

// checkAnchor: a non-empty chain needs an anchor; the chain ends at the
// anchor's row, or one row past it when that row's prev is the anchor hash.
func checkAnchor(a anchor, hasA bool, seq int64, hash, before string, rows bool) error {
	if !hasA {
		if seq > 0 {
			return codes.E(codes.AuditTruncated)
		}
		return nil
	}
	if seq == a.Seq && hash == a.Hash {
		return nil
	}
	if seq == a.Seq+1 && rows && before == a.Hash {
		return nil
	}
	return codes.E(codes.AuditTruncated)
}

func readIndex(dir string) ([]entry, error) {
	data, err := readCapped(filepath.Join(dir, SegDir, IndexName), indexMax)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f indexFile
	if err := dec.Decode(&f); err != nil || dec.More() || f.V != 1 || len(f.Segments) == 0 {
		return nil, codes.E(codes.AuditBad)
	}
	next := int64(1)
	for _, e := range f.Segments {
		if e.First != next || e.Last < e.First || !lowerHex(e.Hash) {
			return nil, codes.E(codes.AuditBad)
		}
		next = e.Last + 1
	}
	return f.Segments, nil
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
		return nil, codes.E(codes.AuditBad)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, codes.E(codes.AuditBad)
	}
	return os.NewFile(uintptr(fd), path), nil
}

// readCapped reads a state file of at most max bytes. More is audit_bad.
func readCapped(path string, max int64) ([]byte, error) {
	f, err := openState(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, codes.E(codes.AuditBad)
	}
	return data, nil
}

func readHead(path string) (anchor, bool, error) {
	data, err := readCapped(path, headMax)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return anchor{}, false, nil
		}
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

// writeAtomic replaces path with v as JSON: temp file, fsync, rename,
// directory fsync.
func writeAtomic(path string, v any) error {
	b, err := codes.Marshal(v)
	if err != nil {
		return codes.E(codes.Failed)
	}
	return writeBytes(path, append(b, '\n'))
}

func writeBytes(path string, data []byte) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return codes.E(codes.Failed)
	}
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, ".tmp."+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return codes.E(codes.Failed)
	}
	_, werr := f.Write(data)
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
	return syncDir(dir)
}

func syncDir(dir string) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return codes.E(codes.Failed)
	}
	serr := unix.Fsync(fd)
	cerr := unix.Close(fd)
	if serr != nil || cerr != nil {
		return codes.E(codes.Failed)
	}
	return nil
}

func writeIndex(segDirPath string, idx []entry) error {
	return writeAtomic(filepath.Join(segDirPath, IndexName), indexFile{V: 1, Segments: idx})
}

// encode returns the stored line and its hash.
func encode(b body) ([]byte, string, error) {
	raw, err := codes.Marshal(b)
	if err != nil {
		return nil, "", codes.E(codes.Failed)
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	line, err := codes.Marshal(stored{body: b, Hash: hash})
	if err != nil {
		return nil, "", codes.E(codes.Failed)
	}
	if len(line) > MaxLine {
		return nil, "", codes.E(codes.AuditBad)
	}
	return line, hash, nil
}

// appendLine appends line and a newline to path, fsyncs it, and fsyncs the
// directory when the file is new.
func appendLine(path string, line []byte) error {
	_, statErr := os.Lstat(path)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return codes.E(codes.AuditBad)
	}
	_, werr := f.Write(append(append([]byte(nil), line...), '\n'))
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		return codes.E(codes.Failed)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return codes.E(codes.Failed)
	}
	if os.IsNotExist(statErr) {
		return syncDir(filepath.Dir(path))
	}
	return nil
}

// Append writes one row. detail nil becomes {}. The in-memory tail moves only
// after the line is fsynced. A full segment is closed in the index first, so
// a crash leaves the index ahead of an empty next segment, which Open
// accepts. A roll prunes when retention is set.
func (c *Chain) Append(actor, lease, action string, detail json.RawMessage, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken {
		return codes.E(codes.AuditBad)
	}
	rolled, err := c.appendLocked(actor, lease, action, detail, now)
	if err != nil {
		return err
	}
	if rolled && c.keep > 0 {
		return c.prune(now)
	}
	return nil
}

func (c *Chain) appendLocked(actor, lease, action string, detail json.RawMessage, now time.Time) (bool, error) {
	det, err := compactDetail(detail)
	if err != nil {
		return false, err
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
	line, hash, err := encode(b)
	if err != nil {
		c.broken = true
		return false, err
	}
	rolled := false
	if c.rows > 0 && (c.rows >= c.opt.SegRows || c.size+int64(len(line))+1 > c.opt.SegBytes) {
		idx := append(append([]entry(nil), c.index...), entry{First: c.seq - int64(c.rows) + 1, Last: c.seq, Hash: c.prev})
		if err := writeIndex(filepath.Join(c.dir, SegDir), idx); err != nil {
			c.broken = true
			return false, err
		}
		c.index = idx
		c.seg++
		c.rows, c.size = 0, 0
		rolled = true
	}
	if err := appendLine(segPath(c.dir, c.seg), line); err != nil {
		c.broken = true
		return false, err
	}
	c.seq = b.Seq
	c.prev = hash
	c.rows++
	c.size += int64(len(line)) + 1
	if err := writeAtomic(filepath.Join(c.dir, HeadName), anchor{Seq: c.seq, Hash: c.prev}); err != nil {
		c.broken = true
		return false, err
	}
	return rolled, nil
}

// prune drops the oldest closed segments beyond keep. The audit.pruned row
// comes first and names the dropped range and the last seq and hash of its
// last segment, so a full verify can tell pruning from deletion. The index
// keeps every entry, so the next retained segment stays linked. A failed
// delete leaves the files; they still verify, and the next roll retries.
func (c *Chain) prune(now time.Time) error {
	through := c.seg - 1 - c.keep
	if through < c.low {
		return nil
	}
	e := c.index[through-1]
	detail, err := codes.Marshal(pruned{From: c.low, Through: through, LastSeq: e.Last, Hash: e.Hash})
	if err != nil {
		return codes.E(codes.Failed)
	}
	if _, err := c.appendLocked("secsvc", "", "audit.pruned", detail, now); err != nil {
		return err
	}
	if c.walking > 0 {
		return nil
	}
	for n := c.low; n <= through; n++ {
		if err := os.Remove(segPath(c.dir, n)); err != nil && !os.IsNotExist(err) {
			return nil
		}
	}
	if err := syncDir(filepath.Join(c.dir, SegDir)); err != nil {
		return nil
	}
	c.low = through + 1
	return nil
}

// pruned is the detail of an audit.pruned row.
type pruned struct {
	From    int    `json:"from"`
	Through int    `json:"through"`
	LastSeq int64  `json:"last_seq"`
	Hash    string `json:"hash"`
}

// check is the bounded runtime read. The running daemon is the only writer,
// so the disk must hold exactly what this chain wrote: the same index, the
// same newest segment ending at the same row, and the same newest witness.
func (c *Chain) check() ([]Row, error) {
	t, err := loadTail(c.dir)
	if err != nil {
		return nil, err
	}
	seq, hash := t.end()
	if !sameIndex(t.index, c.index) || len(t.rows) != c.rows || seq != c.seq || hash != c.prev {
		return nil, codes.E(codes.AuditTruncated)
	}
	w, err := lastWitness(c.dir)
	if err != nil {
		return nil, err
	}
	if (w == nil) != (c.wit == nil) || (w != nil && *w != *c.wit) {
		return nil, codes.E(codes.AuditTruncated)
	}
	if w != nil {
		if err := c.checkWitness(*w, t.rows); err != nil {
			return nil, err
		}
	}
	return t.rows, nil
}

func sameIndex(a, b []entry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ReadAll re-verifies the newest segment and returns its rows. A failure
// marks the chain broken.
func (c *Chain) ReadAll() ([]Row, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rows, err := c.check()
	if err != nil {
		c.broken = true
		return nil, err
	}
	return rows, nil
}

// Tail returns the last limit rows of the newest segment in chain order.
// limit <= 0 returns the whole segment.
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

// Head is the last row after the runtime check: its seq and hash and the
// segment that holds it (0 for an empty chain).
func (c *Chain) Head() (int64, string, int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.check(); err != nil {
		c.broken = true
		return 0, "", 0, err
	}
	seg := c.seg
	if c.rows == 0 {
		seg = c.seg - 1
	}
	return c.seq, c.prev, seg, nil
}

// Verify is the full check: the runtime read under the chain lock, then a
// walk of every retained segment without it. Closed segments do not change,
// so the walk uses the index, newest segment, anchor and witnesses as they
// were under the lock; a prune that lands during the walk leaves its files
// for the next roll. A failure marks the chain broken.
func (c *Chain) Verify() (int, error) {
	c.mu.Lock()
	rows, err := c.check()
	var s snap
	if err == nil {
		var wits []Witness
		wits, err = readWitnesses(c.dir)
		s = snap{
			a: anchor{Seq: c.seq, Hash: c.prev}, hasA: c.seq > 0, seg: true,
			idx: append([]entry(nil), c.index...), open: rows, wits: wits,
		}
	}
	if err != nil {
		c.broken = true
		c.mu.Unlock()
		return 0, err
	}
	c.walking++
	c.mu.Unlock()
	if walkHook != nil {
		walkHook()
	}
	n, err := walkAll(c.dir, s)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.walking--
	if err != nil {
		c.broken = true
		return 0, err
	}
	return n, nil
}

// walkHook is a test hook run after Verify releases the chain lock.
var walkHook func()

// WitnessError is audit_truncated caused by a stored witness. Seq names the
// witness, so an operator knows which off-host record disagrees.
type WitnessError struct{ Seq int64 }

func (e *WitnessError) Error() string { return codes.AuditTruncated }

func (e *WitnessError) Unwrap() error { return codes.E(codes.AuditTruncated) }

// verifyRetry is a test hook called before each VerifyDir retry.
var verifyRetry func(attempt int)

// VerifyDir is the full check of the chain in state directory dir and
// returns the number of rows on disk. A missing chain with no anchor is
// empty. It never writes. A running daemon writes the row before the anchor,
// so a reader in another process retries a short while before it calls the
// chain truncated.
func VerifyDir(dir string) (int, error) {
	var err error
	for i := 0; i < 3; i++ {
		var n int
		n, err = verifyAll(dir)
		if err == nil {
			return n, nil
		}
		if codes.Code(err) != codes.AuditTruncated || i == 2 {
			break
		}
		if verifyRetry != nil {
			verifyRetry(i)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return 0, err
}

// snap is what a full walk checks against. open is the newest segment's
// rows when diskOpen is false.
type snap struct {
	a        anchor
	hasA     bool
	seg      bool
	idx      []entry
	open     []Row
	diskOpen bool
	wits     []Witness
}

// verifyAll reads the anchor, witnesses and index from disk and walks.
func verifyAll(dir string) (int, error) {
	if err := checkLayout(dir); err != nil {
		return 0, err
	}
	var s snap
	var err error
	if s.a, s.hasA, err = readHead(filepath.Join(dir, HeadName)); err != nil {
		return 0, err
	}
	if s.wits, err = readWitnesses(dir); err != nil {
		return 0, err
	}
	if s.seg, err = segDir(dir); err != nil {
		return 0, err
	}
	if s.seg {
		if s.idx, err = readIndex(dir); err != nil {
			return 0, err
		}
		if _, err := os.Lstat(segPath(dir, len(s.idx)+2)); err == nil || !os.IsNotExist(err) {
			return 0, codes.E(codes.AuditBad)
		}
	}
	s.diskOpen = true
	return walkAll(dir, s)
}

// walkAll walks every retained segment against the index, the anchor, the
// prune record and every stored witness.
//
// Threats: a missing segment is pruning only when the newest audit.pruned
// row covers it and names the index entry it ended at; otherwise it is
// audit_truncated. A rewritten old segment no longer ends at its index entry
// or no longer links, and is audit_bad. A stored witness the chain does not
// hold is a WitnessError naming its seq.
func walkAll(dir string, s snap) (int, error) {
	want := map[int64]string{}
	for _, w := range s.wits {
		if h, ok := want[w.Seq]; ok && h != w.Hash {
			return 0, &WitnessError{Seq: w.Seq}
		}
		want[w.Seq] = w.Hash
	}
	if !s.seg {
		if s.hasA {
			return 0, codes.E(codes.AuditTruncated)
		}
		for _, w := range s.wits {
			return 0, &WitnessError{Seq: w.Seq}
		}
		return 0, nil
	}
	idx := s.idx
	closed := len(idx)
	low, err := lowest(dir, closed)
	if err != nil {
		return 0, err
	}
	var (
		count    int
		last     Row
		openRows bool
		pr       pruned
		walked   = int64(-1)
	)
	visit := func(row Row, _ []byte) error {
		count++
		if walked < 0 {
			walked = row.Seq
		}
		if h, ok := want[row.Seq]; ok && h != row.Hash {
			return &WitnessError{Seq: row.Seq}
		}
		if row.Action == "audit.pruned" && row.Actor == "secsvc" {
			dec := json.NewDecoder(bytes.NewReader(row.Detail))
			dec.DisallowUnknownFields()
			var p pruned
			if err := dec.Decode(&p); err != nil {
				return codes.E(codes.AuditBad)
			}
			pr = p
		}
		return nil
	}
	for n := low; n <= closed; n++ {
		first, prev := link(idx[:n-1])
		_, end, missing, err := walk(segPath(dir, n), first, prev, visit)
		if err != nil {
			return 0, err
		}
		e := idx[n-1]
		if missing {
			return 0, codes.E(codes.AuditTruncated)
		}
		if end.Seq != e.Last || end.Hash != e.Hash {
			return 0, codes.E(codes.AuditBad)
		}
	}
	if s.diskOpen {
		first, prev := link(idx)
		got, end, _, err := walk(segPath(dir, closed+1), first, prev, visit)
		if err != nil {
			return 0, err
		}
		if got > 0 {
			openRows, last = true, end
		}
	} else {
		for _, row := range s.open {
			if err := visit(row, nil); err != nil {
				return 0, err
			}
		}
		if n := len(s.open); n > 0 {
			openRows, last = true, s.open[n-1]
		}
	}
	if low > 1 {
		if pr.Through < low-1 || pr.Through > closed || pr.From < 1 ||
			idx[pr.Through-1].Last != pr.LastSeq || idx[pr.Through-1].Hash != pr.Hash {
			return 0, codes.E(codes.AuditTruncated)
		}
	}
	t := tail{index: idx}
	if openRows {
		t.rows = []Row{last}
	}
	seq, hash := t.end()
	if err := checkAnchor(s.a, s.hasA, seq, hash, last.Prev, openRows); err != nil {
		return 0, err
	}
	for _, w := range s.wits {
		if w.Seq > seq {
			return 0, &WitnessError{Seq: w.Seq}
		}
		if walked >= 0 && w.Seq >= walked {
			continue
		}
		i := sort.Search(len(idx), func(i int) bool { return idx[i].Last >= w.Seq })
		if i < len(idx) && idx[i].Last == w.Seq && idx[i].Hash != w.Hash {
			return 0, &WitnessError{Seq: w.Seq}
		}
	}
	return count, nil
}

// walk streams one segment line by line with a buffer of one line. A
// missing file reports missing and no rows.
func walk(path string, first int64, prev string, visit func(Row, []byte) error) (int, Row, bool, error) {
	f, err := openState(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, Row{}, true, nil
		}
		return 0, Row{}, false, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, MaxLine+1)
	var last Row
	n := 0
	for {
		line, err := r.ReadSlice('\n')
		if err == io.EOF && len(line) == 0 {
			return n, last, false, nil
		}
		if err != nil {
			return 0, Row{}, false, codes.E(codes.AuditBad)
		}
		row, err := checkLine(line[:len(line)-1], first+int64(n), prev)
		if err != nil {
			return 0, Row{}, false, err
		}
		if err := visit(row, line[:len(line)-1]); err != nil {
			return 0, Row{}, false, err
		}
		prev = row.Hash
		last = row
		n++
	}
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

// parseRows verifies data as consecutive rows from seq first after prev.
func parseRows(data []byte, first int64, prev string) ([]Row, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, codes.E(codes.AuditBad)
	}
	parts := bytes.Split(data[:len(data)-1], []byte{'\n'})
	rows := make([]Row, 0, len(parts))
	for i, p := range parts {
		row, err := checkLine(p, first+int64(i), prev)
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
