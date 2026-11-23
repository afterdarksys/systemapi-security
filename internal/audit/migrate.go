package audit

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"golang.org/x/sys/unix"
)

// Anchor is the operator step for a single-file chain written before anchors
// existed. It verifies the whole chain, writes the anchor, and appends an
// audit.anchor_init row naming the seq and hash it anchored. An existing
// anchor is anchor_exists; an empty chain needs none and is left alone; a
// segmented chain is audit_layout. The caller must hold the store lock.
func Anchor(dir string, now time.Time) (int, error) {
	if ok, err := segDir(dir); err != nil || ok {
		if err != nil {
			return 0, err
		}
		return 0, codes.E(codes.AuditLayout)
	}
	head := filepath.Join(dir, HeadName)
	if _, err := os.Lstat(head); err == nil {
		return 0, codes.E(codes.AnchorExists)
	} else if !os.IsNotExist(err) {
		return 0, codes.E(codes.AuditBad)
	}
	path := filepath.Join(dir, LegacyName)
	n, last, _, err := walk(path, 1, Genesis, func(Row, []byte) error { return nil })
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}
	if err := writeAtomic(head, anchor{Seq: last.Seq, Hash: last.Hash}); err != nil {
		return 0, err
	}
	raw, err := codes.Marshal(anchor{Seq: last.Seq, Hash: last.Hash})
	if err != nil {
		return 0, codes.E(codes.Failed)
	}
	detail, err := compactDetail(raw)
	if err != nil {
		return 0, err
	}
	line, hash, err := encode(body{
		Seq: last.Seq + 1, Prev: last.Hash, Time: now.UTC().Format(time.RFC3339Nano),
		Actor: "secsvc", Action: "audit.anchor_init", Detail: detail,
	})
	if err != nil {
		return 0, err
	}
	if err := appendLine(path, line); err != nil {
		return 0, err
	}
	if err := writeAtomic(head, anchor{Seq: last.Seq + 1, Hash: hash}); err != nil {
		return 0, err
	}
	return n + 1, nil
}

// Migrate moves a single-file chain into segments. The caller must hold the
// store lock.
//
// Threats: the old file is verified line by line against its anchor exactly
// as Open verified it (a non-empty chain with no anchor is audit_truncated;
// run Anchor first), so a truncated chain is never blessed by a migration.
// The segments and index are built in a temporary directory and renamed into
// place only when complete. The old file is kept as audit.jsonl.migrated.
// An existing segment directory is audit_layout.
func Migrate(dir string, opt Options, now time.Time) (int, error) {
	opt, err := opt.norm()
	if err != nil {
		return 0, err
	}
	if ok, err := segDir(dir); err != nil || ok {
		if err != nil {
			return 0, err
		}
		return 0, codes.E(codes.AuditLayout)
	}
	legacy := filepath.Join(dir, LegacyName)
	if _, err := os.Lstat(legacy); err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, codes.E(codes.AuditBad)
	}
	a, hasA, err := readHead(filepath.Join(dir, HeadName))
	if err != nil {
		return 0, err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return 0, codes.E(codes.Failed)
	}
	tmp := filepath.Join(dir, ".audit.migrate."+hex.EncodeToString(rnd[:]))
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return 0, codes.E(codes.Failed)
	}
	done := false
	defer func() {
		if !done {
			os.RemoveAll(tmp)
		}
	}()
	w := &segWriter{dir: tmp, opt: opt, seg: 1}
	n, last, _, err := walk(legacy, 1, Genesis, w.add)
	if err == nil {
		err = w.close()
	}
	if err != nil {
		return 0, err
	}
	t := tail{index: w.index}
	if n > 0 {
		t.rows = []Row{last}
	}
	seq, hash := t.end()
	if err := checkAnchor(a, hasA, seq, hash, last.Prev, n > 0); err != nil {
		return 0, err
	}
	if len(w.index) > 0 {
		if err := writeIndex(tmp, w.index); err != nil {
			return 0, err
		}
	}
	if err := syncDir(tmp); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, filepath.Join(dir, SegDir)); err != nil {
		return 0, codes.E(codes.Failed)
	}
	done = true
	if err := os.Rename(legacy, legacy+".migrated"); err != nil {
		return 0, codes.E(codes.Failed)
	}
	if err := syncDir(dir); err != nil {
		return 0, err
	}
	c, err := Open(dir, opt, 0)
	if err != nil {
		return 0, err
	}
	detail, err := codes.Marshal(struct {
		Seq      int64  `json:"seq"`
		Hash     string `json:"hash"`
		Segments int    `json:"segments"`
	}{seq, hash, len(w.index) + 1})
	if err != nil {
		return 0, codes.E(codes.Failed)
	}
	if err := c.Append("secsvc", "", "audit.migrated", detail, now); err != nil {
		return 0, err
	}
	return n + 1, nil
}

// segWriter splits verified rows into segments with the same caps Append
// uses.
type segWriter struct {
	dir   string
	opt   Options
	seg   int
	rows  int
	size  int64
	first int64
	last  Row
	f     *os.File
	index []entry
}

func (w *segWriter) add(row Row, line []byte) error {
	if w.rows > 0 && (w.rows >= w.opt.SegRows || w.size+int64(len(line))+1 > w.opt.SegBytes) {
		if err := w.close(); err != nil {
			return err
		}
		w.index = append(w.index, entry{First: w.first, Last: w.last.Seq, Hash: w.last.Hash})
		w.seg++
		w.rows, w.size = 0, 0
	}
	if w.f == nil {
		f, err := os.OpenFile(filepath.Join(w.dir, segName(w.seg)), os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err != nil {
			return codes.E(codes.Failed)
		}
		w.f = f
		w.first = row.Seq
	}
	if _, err := w.f.Write(append(append([]byte(nil), line...), '\n')); err != nil {
		return codes.E(codes.Failed)
	}
	w.rows++
	w.size += int64(len(line)) + 1
	w.last = row
	return nil
}

func (w *segWriter) close() error {
	if w.f == nil {
		return nil
	}
	serr := w.f.Sync()
	cerr := w.f.Close()
	w.f = nil
	if err := errors.Join(serr, cerr); err != nil {
		return codes.E(codes.Failed)
	}
	return nil
}
