package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
)

const (
	// WitnessName is the stored witness file inside the state directory.
	WitnessName = "witness.jsonl"
	witnessMax  = 256 << 10
)

// Before an append, a file that would reach witnessLines witnesses or pass
// witnessCompact bytes is compacted to at most witnessKeep of the newest,
// in at most half of witnessCompact bytes, the new one included. A witness
// line is under 300 bytes, so the file stays well below witnessMax, the
// read cap, and witness growth can never make the store unopenable.
var (
	witnessKeep    = 500
	witnessLines   = 1000
	witnessCompact = 128 << 10
)

var witnessRe = regexp.MustCompile(`^[A-Za-z0-9:._@/-]{1,128}$`)

// Witness is a record that an off-host party saw the chain at seq with hash.
type Witness struct {
	Seq     int64  `json:"seq"`
	Hash    string `json:"hash"`
	Witness string `json:"witness"`
	Time    string `json:"time"`
}

// ParseWitness decodes one witness strictly. A bad shape is bad_path.
func ParseWitness(b []byte) (Witness, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var w Witness
	if err := dec.Decode(&w); err != nil || dec.More() {
		return Witness{}, codes.E(codes.BadPath)
	}
	if w.Seq < 1 || !lowerHex(w.Hash) || !witnessRe.MatchString(w.Witness) || len(w.Time) > 35 {
		return Witness{}, codes.E(codes.BadPath)
	}
	if _, err := time.Parse(time.RFC3339, w.Time); err != nil {
		return Witness{}, codes.E(codes.BadPath)
	}
	return w, nil
}

// readWitnesses returns every stored witness in file order. A missing file
// is none; a malformed or oversized one is audit_bad.
func readWitnesses(dir string) ([]Witness, error) {
	data, err := readCapped(filepath.Join(dir, WitnessName), witnessMax)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	if data[len(data)-1] != '\n' {
		return nil, codes.E(codes.AuditBad)
	}
	var out []Witness
	for _, p := range bytes.Split(data[:len(data)-1], []byte{'\n'}) {
		w, err := ParseWitness(p)
		if err != nil {
			return nil, codes.E(codes.AuditBad)
		}
		out = append(out, w)
	}
	return out, nil
}

func lastWitness(dir string) (*Witness, error) {
	ws, err := readWitnesses(dir)
	if err != nil || len(ws) == 0 {
		return nil, err
	}
	w := ws[len(ws)-1]
	return &w, nil
}

// hashAt returns the hash of row seq. rows is the newest segment. A row in a
// pruned segment cannot be checked and returns "".
func (c *Chain) hashAt(seq int64, rows []Row) (string, error) {
	if seq < 1 || seq > c.seq {
		return "", codes.E(codes.AuditTruncated)
	}
	if len(rows) > 0 && seq >= rows[0].Seq {
		return rows[seq-rows[0].Seq].Hash, nil
	}
	i := sort.Search(len(c.index), func(i int) bool { return c.index[i].Last >= seq })
	if i == len(c.index) {
		return "", codes.E(codes.AuditTruncated)
	}
	e := c.index[i]
	if seq == e.Last {
		return e.Hash, nil
	}
	if i+1 < c.low {
		return "", nil
	}
	data, err := readCapped(segPath(c.dir, i+1), DefaultSegBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", codes.E(codes.AuditTruncated)
		}
		return "", err
	}
	first, prev := link(c.index[:i])
	seg, err := parseRows(data, first, prev)
	if err != nil {
		return "", err
	}
	if n := len(seg); n == 0 || seg[n-1].Seq != e.Last || seg[n-1].Hash != e.Hash {
		return "", codes.E(codes.AuditBad)
	}
	return seg[seq-first].Hash, nil
}

// checkWitness: the chain must still hold w.Seq with w.Hash.
func (c *Chain) checkWitness(w Witness, rows []Row) error {
	h, err := c.hashAt(w.Seq, rows)
	if err != nil {
		return err
	}
	if h != "" && h != w.Hash {
		return &WitnessError{Seq: w.Seq}
	}
	return nil
}

// AddWitness stores w when the chain holds it now.
//
// Threats: only a witness of a row the chain holds, with the same hash, is
// stored, so a witness grant cannot plant a record that makes the store
// unopenable. A seq past the end or another hash is witness_mismatch; a row
// in a pruned segment that is not that segment's last row cannot be
// checked and is witness_unverifiable. Neither is stored or breaks the
// chain; the caller audits the refusal. A stored witness that later stops
// matching is tampering, and open, the runtime read and verify report
// audit_truncated naming its seq. The runtime read checks the newest one.
func (c *Chain) AddWitness(w Witness) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken {
		return codes.E(codes.AuditBad)
	}
	rows, err := c.check()
	if err != nil {
		c.broken = true
		return err
	}
	h, err := c.hashAt(w.Seq, rows)
	switch {
	case codes.Code(err) == codes.AuditTruncated:
		return codes.E(codes.WitnessMismatch)
	case err != nil:
		c.broken = true
		return err
	case h == "":
		return codes.E(codes.WitnessUnverifiable)
	case h != w.Hash:
		return codes.E(codes.WitnessMismatch)
	}
	line, err := codes.Marshal(w)
	if err != nil {
		return codes.E(codes.Failed)
	}
	path := filepath.Join(c.dir, WitnessName)
	ws, err := readWitnesses(c.dir)
	if err != nil {
		c.broken = true
		return err
	}
	size := 0
	olds := make([][]byte, len(ws))
	for i, old := range ws {
		if olds[i], err = codes.Marshal(old); err != nil {
			return codes.E(codes.Failed)
		}
		size += len(olds[i]) + 1
	}
	if len(ws)+1 >= witnessLines || size+len(line)+1 > witnessCompact {
		keep, kept := 0, len(line)+1
		for i := len(olds) - 1; i >= 0 && keep+1 < witnessKeep && kept+len(olds[i])+1 <= witnessCompact/2; i-- {
			keep++
			kept += len(olds[i]) + 1
		}
		var buf bytes.Buffer
		for _, b := range olds[len(olds)-keep:] {
			buf.Write(append(b, '\n'))
		}
		buf.Write(append(line, '\n'))
		err = writeBytes(path, buf.Bytes())
	} else {
		err = appendLine(path, line)
	}
	if err != nil {
		c.broken = true
		return err
	}
	c.wit = &w
	return nil
}
