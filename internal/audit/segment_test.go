package audit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
)

// small rolls every three rows.
var small = Options{SegRows: 3}

func readIdx(t *testing.T, dir string) []entry {
	t.Helper()
	idx, err := readIndex(dir)
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

func TestSegmentsRollAndLink(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, small, 0)
	appendN(t, c, 10)
	for n := 1; n <= 4; n++ {
		if _, err := os.Stat(seg(dir, n)); err != nil {
			t.Fatalf("segment %d: %v", n, err)
		}
	}
	idx := readIdx(t, dir)
	if len(idx) != 3 || idx[0] != (entry{1, 3, idx[0].Hash}) || idx[2].Last != 9 {
		t.Fatalf("index %+v", idx)
	}
	// The newest segment's first row links to the index.
	rows, err := c.ReadAll()
	if err != nil || len(rows) != 1 || rows[0].Seq != 10 || rows[0].Prev != idx[2].Hash {
		t.Fatalf("newest %+v %v", rows, err)
	}
	// The tail reads only the newest segment.
	if tail, err := c.Tail(50); err != nil || len(tail) != 1 {
		t.Fatalf("tail %d %v", len(tail), err)
	}
	if n, err := VerifyDir(dir); err != nil || n != 10 {
		t.Fatalf("verify %d %v", n, err)
	}
	// Reopen continues the same segment.
	c = openChain(t, dir, small, 0)
	appendN(t, c, 2)
	if _, err := os.Stat(seg(dir, 5)); !os.IsNotExist(err) {
		t.Fatal("rolled early")
	}
	appendN(t, c, 1)
	if _, err := os.Stat(seg(dir, 5)); err != nil {
		t.Fatal("did not roll")
	}
}

func TestSegmentByteCap(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, Options{SegBytes: 600}, 0)
	appendN(t, c, 6)
	for n := 1; ; n++ {
		st, err := os.Stat(seg(dir, n))
		if os.IsNotExist(err) {
			if n < 3 {
				t.Fatalf("only %d segments", n-1)
			}
			break
		}
		if err != nil || st.Size() > 600 {
			t.Fatalf("segment %d size %v %v", n, st, err)
		}
	}
	if n, err := VerifyDir(dir); err != nil || n != 6 {
		t.Fatalf("verify %d %v", n, err)
	}
}

// The runtime read is bounded to the newest segment, so a rewritten old
// segment is caught only by the full verify.
func TestRewrittenOldSegmentNeedsFullVerify(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, small, 0)
	appendN(t, c, 7)
	raw, err := os.ReadFile(seg(dir, 1))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(raw), "\n")
	// Rewrite segment 1 as a self-consistent forgery of the same length.
	if err := os.WriteFile(seg(dir, 1), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	prev := Genesis
	for i := int64(1); i <= 3; i++ {
		prev = forgeRow(t, seg(dir, 1), i, prev)
	}
	if _, err := c.ReadAll(); err != nil {
		t.Fatalf("runtime should not read old segments: %v", err)
	}
	_, err = VerifyDir(dir)
	wantCode(t, err, codes.AuditBad, "full verify")
	_, err = c.Verify()
	wantCode(t, err, codes.AuditBad, "chain verify")
	// A line changed inside the old segment, too.
	if err := os.WriteFile(seg(dir, 1), []byte(lines[0]+flipHash(lines[1])+lines[2]), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = VerifyDir(dir)
	wantCode(t, err, codes.AuditBad, "flipped hash")
}

func TestTruncateNewestSegment(t *testing.T) {
	for name, keepRows := range map[string]int{"to_empty": 0, "one_row": 1} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			c := openChain(t, dir, small, 0)
			appendN(t, c, 8) // segment 3 holds 7 and 8
			raw, err := os.ReadFile(seg(dir, 3))
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.SplitAfter(string(raw), "\n")
			if err := os.WriteFile(seg(dir, 3), []byte(strings.Join(lines[:keepRows], "")), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = c.ReadAll()
			wantCode(t, err, codes.AuditTruncated, "runtime")
			_, err = Open(dir, small, 0)
			wantCode(t, err, codes.AuditTruncated, "open")
			_, err = VerifyDir(dir)
			wantCode(t, err, codes.AuditTruncated, "verify")
		})
	}
	// Deleting the newest segment file and the last index entry together
	// still ends the chain short of the anchor.
	dir := t.TempDir()
	c := openChain(t, dir, small, 0)
	appendN(t, c, 7)
	if err := os.Remove(seg(dir, 3)); err != nil {
		t.Fatal(err)
	}
	idx := readIdx(t, dir)
	if err := writeIndex(filepath.Join(dir, SegDir), idx[:1]); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(seg(dir, 2)); err != nil {
		t.Fatal(err)
	}
	_, err := Open(dir, small, 0)
	wantCode(t, err, codes.AuditTruncated, "open")
	_, err = c.ReadAll()
	wantCode(t, err, codes.AuditTruncated, "runtime")
}

func TestDeletedSegmentIsTruncation(t *testing.T) {
	for _, n := range []int{1, 2} {
		dir := t.TempDir()
		c := openChain(t, dir, small, 0)
		appendN(t, c, 10)
		if err := os.Remove(seg(dir, n)); err != nil {
			t.Fatal(err)
		}
		_, err := VerifyDir(dir)
		wantCode(t, err, codes.AuditTruncated, "verify")
		_, err = c.Verify()
		wantCode(t, err, codes.AuditTruncated, "chain verify")
	}
}

func TestIndexTampering(t *testing.T) {
	setup := func(t *testing.T) (string, *Chain, []entry) {
		dir := t.TempDir()
		c := openChain(t, dir, small, 0)
		appendN(t, c, 10)
		return dir, c, readIdx(t, dir)
	}
	t.Run("last_hash", func(t *testing.T) {
		dir, c, idx := setup(t)
		idx[2].Hash = strings.Repeat("a", 64)
		if err := writeIndex(filepath.Join(dir, SegDir), idx); err != nil {
			t.Fatal(err)
		}
		_, err := c.ReadAll()
		wantCode(t, err, codes.AuditBad, "runtime")
		_, err = Open(dir, small, 0)
		wantCode(t, err, codes.AuditBad, "open")
	})
	t.Run("old_hash", func(t *testing.T) {
		dir, c, idx := setup(t)
		idx[0].Hash = strings.Repeat("a", 64)
		if err := writeIndex(filepath.Join(dir, SegDir), idx); err != nil {
			t.Fatal(err)
		}
		_, err := c.ReadAll()
		wantCode(t, err, codes.AuditTruncated, "runtime")
		_, err = VerifyDir(dir)
		wantCode(t, err, codes.AuditBad, "verify")
	})
	t.Run("dropped_entry", func(t *testing.T) {
		dir, c, idx := setup(t)
		if err := writeIndex(filepath.Join(dir, SegDir), idx[:2]); err != nil {
			t.Fatal(err)
		}
		_, err := c.ReadAll()
		wantCode(t, err, codes.AuditBad, "runtime")
		_, err = Open(dir, small, 0)
		wantCode(t, err, codes.AuditBad, "open")
		_, err = VerifyDir(dir)
		wantCode(t, err, codes.AuditBad, "verify")
	})
	t.Run("gap", func(t *testing.T) {
		dir, _, idx := setup(t)
		idx[1].First++
		if err := writeIndex(filepath.Join(dir, SegDir), idx); err != nil {
			t.Fatal(err)
		}
		_, err := Open(dir, small, 0)
		wantCode(t, err, codes.AuditBad, "open")
	})
	t.Run("deleted", func(t *testing.T) {
		dir, c, _ := setup(t)
		if err := os.Remove(filepath.Join(dir, SegDir, IndexName)); err != nil {
			t.Fatal(err)
		}
		_, err := c.ReadAll()
		wantCode(t, err, codes.AuditBad, "runtime")
	})
}

// The roll writes the index before the next segment. A crash between them
// leaves a closed index and no next segment, which opens and continues.
func TestCrashBetweenRollAndIndex(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, small, 0)
	appendN(t, c, 3)
	rows, err := c.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeIndex(filepath.Join(dir, SegDir), []entry{{1, 3, rows[2].Hash}}); err != nil {
		t.Fatal(err)
	}
	c = openChain(t, dir, small, 0)
	if seq, _, segN, err := c.Head(); err != nil || seq != 3 || segN != 1 {
		t.Fatalf("head %d %d %v", seq, segN, err)
	}
	appendN(t, c, 1)
	if _, err := os.Stat(seg(dir, 2)); err != nil {
		t.Fatal(err)
	}
	if n, err := VerifyDir(dir); err != nil || n != 4 {
		t.Fatalf("verify %d %v", n, err)
	}

	// The other order (a next segment the index does not close the previous
	// one for) is never written by Append and is refused.
	dir2 := t.TempDir()
	c2 := openChain(t, dir2, small, 0)
	appendN(t, c2, 3)
	forgeRow(t, seg(dir2, 2), 4, c2.prev)
	_, err = Open(dir2, small, 0)
	wantCode(t, err, codes.AuditBad, "segment past the index")
	_, err = VerifyDir(dir2)
	wantCode(t, err, codes.AuditBad, "verify segment past the index")
}

func prunedRows(t *testing.T, dir string) []pruned {
	t.Helper()
	var out []pruned
	idx := readIdx(t, dir)
	low, err := lowest(dir, len(idx))
	if err != nil {
		t.Fatal(err)
	}
	for n := low; n <= len(idx)+1; n++ {
		first, prev := link(idx[:n-1])
		_, _, _, err := walk(seg(dir, n), first, prev, func(r Row, _ []byte) error {
			if r.Action == "audit.pruned" {
				var p pruned
				if err := json.Unmarshal(r.Detail, &p); err != nil {
					t.Fatal(err)
				}
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestRetention(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, small, 2)
	appendN(t, c, 20)
	idx := readIdx(t, dir)
	closed := len(idx)
	if closed < 6 {
		t.Fatalf("closed %d", closed)
	}
	for n := 1; n <= closed+1; n++ {
		_, err := os.Stat(seg(dir, n))
		if n <= closed-2 && !os.IsNotExist(err) {
			t.Fatalf("segment %d kept", n)
		}
		if n > closed-2 && err != nil {
			t.Fatalf("segment %d dropped: %v", n, err)
		}
	}
	// The index keeps every entry, from seq 1.
	if idx[0].First != 1 {
		t.Fatalf("index %+v", idx)
	}
	ps := prunedRows(t, dir)
	if len(ps) == 0 {
		t.Fatal("no audit.pruned row")
	}
	p := ps[len(ps)-1]
	if p.Through != closed-2 || p.LastSeq != idx[p.Through-1].Last || p.Hash != idx[p.Through-1].Hash {
		t.Fatalf("pruned %+v index %+v", p, idx)
	}
	if _, err := VerifyDir(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, small, 2); err != nil {
		t.Fatal(err)
	}
	// Deleting the oldest retained segment is not pruning.
	if err := os.Remove(seg(dir, closed-1)); err != nil {
		t.Fatal(err)
	}
	_, err := VerifyDir(dir)
	wantCode(t, err, codes.AuditTruncated, "deleted past the prune")
}

// Dropping the oldest segment without an audit.pruned row is truncation.
func TestPruneRowRequired(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, small, 0)
	appendN(t, c, 10)
	if err := os.Remove(seg(dir, 1)); err != nil {
		t.Fatal(err)
	}
	_, err := VerifyDir(dir)
	wantCode(t, err, codes.AuditTruncated, "no row")
}

func TestLegacyLayoutRefused(t *testing.T) {
	dir := t.TempDir()
	writeLegacy(t, dir, 2, true)
	_, err := Open(dir, Options{}, 0)
	wantCode(t, err, codes.AuditLayout, "open")
	_, err = VerifyDir(dir)
	wantCode(t, err, codes.AuditLayout, "verify")
}

// writeLegacy writes a single-file chain of n rows, with or without anchor.
func writeLegacy(t *testing.T, dir string, n int, withHead bool) []string {
	t.Helper()
	prev := Genesis
	var hashes []string
	for i := 1; i <= n; i++ {
		line, hash, err := encode(body{Seq: int64(i), Prev: prev, Time: "2026-01-01T00:00:00Z", Actor: "a", Action: "config.set", Detail: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		if err := appendLine(filepath.Join(dir, LegacyName), line); err != nil {
			t.Fatal(err)
		}
		prev = hash
		hashes = append(hashes, hash)
	}
	if withHead && n > 0 {
		if err := writeAtomic(headOf(dir), anchor{Seq: int64(n), Hash: prev}); err != nil {
			t.Fatal(err)
		}
	}
	return hashes
}

func TestMigrate(t *testing.T) {
	dir := t.TempDir()
	hashes := writeLegacy(t, dir, 8, true)
	n, err := Migrate(dir, small, time.Unix(5, 0))
	if err != nil || n != 9 {
		t.Fatalf("migrate %d %v", n, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, LegacyName)); !os.IsNotExist(err) {
		t.Fatal("old file left in place")
	}
	if _, err := os.Stat(filepath.Join(dir, LegacyName+".migrated")); err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyDir(dir); err != nil || got != 9 {
		t.Fatalf("verify %d %v", got, err)
	}
	c := openChain(t, dir, small, 0)
	rows, err := c.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	last := rows[len(rows)-1]
	want := `{"hash":"` + hashes[7] + `","segments":3,"seq":8}`
	if last.Action != "audit.migrated" || string(last.Detail) != want {
		t.Fatalf("%s %s", last.Action, last.Detail)
	}
	_, err = Migrate(dir, small, time.Unix(6, 0))
	wantCode(t, err, codes.AuditLayout, "second migrate")
}

func TestMigrateRefusesUnanchoredOrShort(t *testing.T) {
	dir := t.TempDir()
	writeLegacy(t, dir, 3, false)
	_, err := Migrate(dir, small, time.Unix(1, 0))
	wantCode(t, err, codes.AuditTruncated, "no anchor")
	if _, err := os.Lstat(filepath.Join(dir, SegDir)); !os.IsNotExist(err) {
		t.Fatal("segments written for a refused migration")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("leftovers %v", entries)
	}
	// Anchor then migrate is the operator path for a pre-anchor chain.
	if n, err := Anchor(dir, time.Unix(2, 0)); err != nil || n != 4 {
		t.Fatalf("anchor %d %v", n, err)
	}
	if n, err := Migrate(dir, small, time.Unix(3, 0)); err != nil || n != 5 {
		t.Fatalf("migrate %d %v", n, err)
	}
	_, err = Anchor(dir, time.Unix(4, 0))
	wantCode(t, err, codes.AuditLayout, "anchor on segments")

	dir2 := t.TempDir()
	writeLegacy(t, dir2, 4, true)
	raw, err := os.ReadFile(filepath.Join(dir2, LegacyName))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(raw), "\n")
	if err := os.WriteFile(filepath.Join(dir2, LegacyName), []byte(lines[0]+lines[1]), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Migrate(dir2, small, time.Unix(1, 0))
	wantCode(t, err, codes.AuditTruncated, "short of anchor")
}

func TestAnchorCommand(t *testing.T) {
	dir := t.TempDir()
	if n, err := Anchor(dir, time.Unix(1, 0)); err != nil || n != 0 {
		t.Fatalf("empty %d %v", n, err)
	}
	if _, err := os.Lstat(headOf(dir)); !os.IsNotExist(err) {
		t.Fatal("empty chain anchored")
	}
	hashes := writeLegacy(t, dir, 3, false)
	n, err := Anchor(dir, time.Unix(5, 0))
	if err != nil || n != 4 {
		t.Fatalf("anchor %d %v", n, err)
	}
	if _, err := Migrate(dir, Options{}, time.Unix(6, 0)); err != nil {
		t.Fatal(err)
	}
	c := openChain(t, dir, Options{}, 0)
	rows, err := c.ReadAll()
	if err != nil || len(rows) != 5 || rows[3].Action != "audit.anchor_init" {
		t.Fatalf("%+v %v", rows, err)
	}
	if want := `{"hash":"` + hashes[2] + `","seq":3}`; string(rows[3].Detail) != want {
		t.Fatalf("detail %s want %s", rows[3].Detail, want)
	}
	dir2 := t.TempDir()
	writeLegacy(t, dir2, 2, true)
	_, err = Anchor(dir2, time.Unix(6, 0))
	wantCode(t, err, codes.AnchorExists, "second anchor")
	// A broken chain is not anchored.
	dir3 := t.TempDir()
	writeLegacy(t, dir3, 2, false)
	raw, _ := os.ReadFile(filepath.Join(dir3, LegacyName))
	if err := os.WriteFile(filepath.Join(dir3, LegacyName), []byte(flipHash(string(raw))), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Anchor(dir3, time.Unix(7, 0))
	wantCode(t, err, codes.AuditBad, "broken")
	if _, err := os.Lstat(headOf(dir3)); !os.IsNotExist(err) {
		t.Fatal("broken chain anchored")
	}
}

func witnessAt(t *testing.T, c *Chain, seq int64) Witness {
	t.Helper()
	h, err := c.hashAt(seq, nil)
	if seq > c.seq-int64(c.rows) {
		rows, rerr := c.ReadAll()
		if rerr != nil {
			t.Fatal(rerr)
		}
		h, err = c.hashAt(seq, rows)
	}
	if err != nil || h == "" {
		t.Fatalf("hash at %d: %q %v", seq, h, err)
	}
	return Witness{Seq: seq, Hash: h, Witness: "cp-1", Time: "2026-11-23T00:00:00Z"}
}

func TestWitness(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, small, 0)
	appendN(t, c, 8)
	// A witness in a closed, retained segment (not its last row) and one in
	// the newest segment.
	if err := c.AddWitness(witnessAt(t, c, 2)); err != nil {
		t.Fatal(err)
	}
	w := witnessAt(t, c, 8)
	if err := c.AddWitness(w); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ReadAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDir(dir); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(dir, WitnessName)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("witness file %v", err)
	}
	if _, err := Open(dir, small, 0); err != nil {
		t.Fatal(err)
	}

	// A witness the chain does not hold now is refused and not stored, so
	// a witness grant cannot make the store unopenable.
	refused := func(t *testing.T, code string, mut func(*Witness)) {
		d := t.TempDir()
		c := openChain(t, d, small, 0)
		appendN(t, c, 4)
		w := witnessAt(t, c, 4)
		mut(&w)
		wantCode(t, c.AddWitness(w), code, "add")
		if _, err := os.Lstat(filepath.Join(d, WitnessName)); !os.IsNotExist(err) {
			t.Fatal("refused witness stored")
		}
		appendN(t, c, 1)
		if _, err := c.ReadAll(); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(d, small, 0); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("mismatch", func(t *testing.T) {
		refused(t, codes.WitnessMismatch, func(w *Witness) { w.Hash = strings.Repeat("b", 64) })
	})
	t.Run("past_end", func(t *testing.T) {
		refused(t, codes.WitnessMismatch, func(w *Witness) { w.Seq = 99 })
	})
	t.Run("pruned", func(t *testing.T) {
		d := t.TempDir()
		c := openChain(t, d, small, 1)
		appendN(t, c, 12)
		idx := readIdx(t, d)
		if _, err := os.Stat(seg(d, 1)); !os.IsNotExist(err) {
			t.Fatal("segment 1 not pruned")
		}
		// Seq 2 sits inside pruned segment 1: no hash can be checked.
		wantCode(t, c.AddWitness(Witness{Seq: 2, Hash: strings.Repeat("d", 64), Witness: "cp-1", Time: "2026-11-23T00:00:00Z"}), codes.WitnessUnverifiable, "inside pruned")
		// Its last row is recorded in the index: only that hash is accepted.
		wantCode(t, c.AddWitness(Witness{Seq: 3, Hash: strings.Repeat("d", 64), Witness: "cp-1", Time: "2026-11-23T00:00:00Z"}), codes.WitnessMismatch, "pruned last, wrong hash")
		if err := c.AddWitness(Witness{Seq: 3, Hash: idx[0].Hash, Witness: "cp-1", Time: "2026-11-23T00:00:00Z"}); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyDir(d); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("chain_rolled_back", func(t *testing.T) {
		d := t.TempDir()
		c := openChain(t, d, small, 0)
		appendN(t, c, 5)
		w := witnessAt(t, c, 5)
		if err := c.AddWitness(w); err != nil {
			t.Fatal(err)
		}
		// Restore an older chain with its own anchor: the stored witness
		// catches it at open and in verify.
		raw, err := os.ReadFile(seg(d, 2))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.SplitAfter(string(raw), "\n")
		if err := os.WriteFile(seg(d, 2), []byte(lines[0]), 0o600); err != nil {
			t.Fatal(err)
		}
		rows, err := parseRows([]byte(lines[0]), 4, readIdx(t, d)[0].Hash)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeAtomic(headOf(d), anchor{Seq: 4, Hash: rows[0].Hash}); err != nil {
			t.Fatal(err)
		}
		_, err = Open(d, small, 0)
		wantCode(t, err, codes.AuditTruncated, "open")
		_, err = VerifyDir(d)
		var we *WitnessError
		if !errors.As(err, &we) || we.Seq != 5 {
			t.Fatalf("verify does not name the witness: %v", err)
		}
	})
	t.Run("file_deleted_at_runtime", func(t *testing.T) {
		d := t.TempDir()
		c := openChain(t, d, small, 0)
		appendN(t, c, 2)
		if err := c.AddWitness(witnessAt(t, c, 2)); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(d, WitnessName)); err != nil {
			t.Fatal(err)
		}
		_, err := c.ReadAll()
		wantCode(t, err, codes.AuditTruncated, "runtime")
	})
	t.Run("old_witness_rewritten", func(t *testing.T) {
		d := t.TempDir()
		c := openChain(t, d, small, 0)
		appendN(t, c, 8)
		w1 := witnessAt(t, c, 2)
		if err := c.AddWitness(w1); err != nil {
			t.Fatal(err)
		}
		if err := c.AddWitness(witnessAt(t, c, 8)); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(d, WitnessName))
		if err != nil {
			t.Fatal(err)
		}
		bad := strings.Replace(string(raw), w1.Hash, strings.Repeat("c", 64), 1)
		if err := os.WriteFile(filepath.Join(d, WitnessName), []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = VerifyDir(d)
		wantCode(t, err, codes.AuditTruncated, "verify")
		var we *WitnessError
		if !errors.As(err, &we) || we.Seq != 2 {
			t.Fatalf("verify does not name the witness: %v", err)
		}
	})
}

func TestWitnessCompaction(t *testing.T) {
	defer func(l, k int) { witnessLines, witnessKeep = l, k }(witnessLines, witnessKeep)
	witnessLines, witnessKeep = 10, 4
	dir := t.TempDir()
	c := openChain(t, dir, Options{}, 0)
	appendN(t, c, 1)
	w := witnessAt(t, c, 1)
	for i := 0; i < witnessLines; i++ {
		if err := c.AddWitness(w); err != nil {
			t.Fatal(err)
		}
	}
	ws, err := readWitnesses(dir)
	if err != nil || len(ws) != witnessKeep {
		t.Fatalf("%d %v", len(ws), err)
	}
	if _, err := c.ReadAll(); err != nil {
		t.Fatal(err)
	}
}

func TestParseWitness(t *testing.T) {
	good := `{"seq":1,"hash":"` + strings.Repeat("a", 64) + `","witness":"cp-1","time":"2026-11-23T00:00:00Z"}`
	if _, err := ParseWitness([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]string{
		"extra":     strings.Replace(good, "{", `{"x":1,`, 1),
		"seq":       strings.Replace(good, `"seq":1`, `"seq":0`, 1),
		"upper":     strings.Replace(good, "aaaa", "AAAA", 1),
		"witness":   strings.Replace(good, "cp-1", "cp 1", 1),
		"time":      strings.Replace(good, "2026-11-23T00:00:00Z", "yesterday", 1),
		"long_time": strings.Replace(good, "2026-11-23T00:00:00Z", "2026-11-23T00:00:00.1234567890+00:00", 1),
		"two":       good + good,
	} {
		_, err := ParseWitness([]byte(b))
		wantCode(t, err, codes.BadPath, name)
	}
}

// The reviewer's repro: 877 witnesses with the longest label and a 64-byte
// time once passed the read cap and made the store unopenable (audit_bad).
// With time capped at 35 the line count alone would still pass the cap near
// 970 witnesses, so this adds one short of the line compaction.
func TestWitnessGrowthKeepsStoreOpen(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, Options{}, 0)
	appendN(t, c, 1)
	w := witnessAt(t, c, 1)
	w.Witness = strings.Repeat("w", 128)
	w.Time = "2026-11-23T00:00:00.123456789+00:00"
	if len(w.Time) != 35 {
		t.Fatal(len(w.Time))
	}
	for i := 0; i < witnessLines-1; i++ {
		if err := c.AddWitness(w); err != nil {
			t.Fatalf("witness %d: %v", i, err)
		}
	}
	st, err := os.Stat(filepath.Join(dir, WitnessName))
	if err != nil || st.Size() > int64(witnessCompact) {
		t.Fatalf("witness file %v %v", st.Size(), err)
	}
	if _, err := Open(dir, Options{}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDir(dir); err != nil {
		t.Fatal(err)
	}
}

// The full walk runs without the chain lock: appends, rolls and a deferred
// prune proceed while it walks, and the walk still verifies.
func TestVerifyWithoutLock(t *testing.T) {
	dir := t.TempDir()
	c := openChain(t, dir, small, 2)
	appendN(t, c, 30)
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 20; i++ {
			if _, err := c.Verify(); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	appendN(t, c, 60)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := c.Verify(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDir(dir); err != nil {
		t.Fatal(err)
	}
}
