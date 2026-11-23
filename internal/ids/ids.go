// Package ids is the host detectors: auth-log tail, file integrity, and listeners.
//
// Threats: a symlink is a finding and is not followed. Auth matching is a fixed
// substring list, never an operator regex, and the raw log line is not a finding.
// An unreadable auth log suppresses auth_fail for that scan. Listener decode
// failure is unsupported, so a partial /proc view is not treated as clean.
// An empty allowlist does not read /proc. This is not a packet IDS. A symlink
// in a parent directory is out of scope. Every open of a configured path is
// O_NONBLOCK|O_NOFOLLOW and fstat must say regular before a read, so a FIFO or
// device swapped in after Lstat is not_regular rather than a hung scan. Reads
// are capped.
package ids

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"golang.org/x/sys/unix"
)

const (
	ScanMax    = 1 << 20
	LineMax    = 8 << 10
	EventsMax  = 10000
	FileMax    = 4 << 20
	ListenCap  = 16
	KindAuth   = "auth_fail"
	KindAuthNA = "auth_log_unavailable"
	KindLink   = "integrity_symlink"
	KindNotReg = "integrity_not_file"
	KindMiss   = "integrity_missing"
	KindBase   = "integrity_unbaselined"
	KindChange = "integrity_changed"
	KindBig    = "integrity_oversize"
	KindListen = "listen_unexpected"
	KindTrunc  = "listen_truncated"
	SevHigh    = "high"
	SevMedium  = "medium"
	StateOff   = "off"
	StateOK    = "ok"
	StateBad   = "unsupported"
	StateWait  = "pending"
)

// Finding is one detector result. Subject is a stable identity, not a log line.
type Finding struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Subject  string `json:"subject"`
	Summary  string `json:"summary"`
}

// BaselineVersion is the current baseline.json format. Version 1 recorded
// only the permission bits; version 2 records the full mode, uid, and gid.
const BaselineVersion = 2

// Record is one baselined regular file. Mode is the full st_mode: file type,
// setuid, setgid, sticky, and permission bits.
//
// Threats: a chmod u+s, a chown, or a type change with the same content must
// be integrity_changed, so every one of these fields is compared.
type Record struct {
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	UID    uint32 `json:"uid"`
	GID    uint32 `json:"gid"`
}

var (
	failPhrases = []string{"Failed password", "Invalid user", "authentication failure", "Failed publickey"}
	hexAddr     = regexp.MustCompile(`^[0-9A-Fa-f]+:[0-9A-Fa-f]+$`)
)

// AuthPos is where the auth tail stopped: the file it read, identified by
// path, inode, and device, and the byte offset after the last whole line.
type AuthPos struct {
	Path   string
	Ino    uint64
	Dev    uint64
	Offset int64
}

// ScanAuth tails path from pos. A read error yields one medium finding and
// leaves pos and events unchanged. Count uses timestamps inside the window.
//
// Threats: (a) rotation is a different inode or device, or a size below the
// offset, and restarts at 0, so a new file that grew past the old offset is
// not skipped. (b) A first scan of a path, with no saved position for it,
// starts at the end of the file and pages on nothing: old lines would be
// dated now. (c) The IP comes only from sshd's fixed structure, never from a
// substring an attacker can put in a user name.
func ScanAuth(path string, pos AuthPos, events []int64, limit, windowS int, now time.Time) (AuthPos, []int64, *Finding) {
	lines, next, err := readWindow(path, pos)
	if err != nil {
		return pos, append([]int64(nil), events...), &Finding{
			Kind: KindAuthNA, Severity: SevMedium, Subject: KindAuthNA, Summary: "auth log unavailable",
		}
	}
	nowS := now.Unix()
	win := int64(windowS)
	kept := make([]int64, 0, len(events)+len(lines))
	for _, ts := range events {
		if nowS-ts > win {
			continue
		}
		kept = append(kept, ts)
	}
	ip := ""
	for _, line := range lines {
		if !authFail(line) {
			continue
		}
		kept = append(kept, nowS)
		if ip == "" {
			ip = lineIP(line)
		}
	}
	if len(kept) > EventsMax {
		kept = append([]int64(nil), kept[len(kept)-EventsMax:]...)
	}
	if limit > 0 && len(kept) >= limit {
		sum := fmt.Sprintf("%d failures", len(kept))
		if ip != "" {
			sum = fmt.Sprintf("%d failures from %s", len(kept), ip)
		}
		return next, kept, &Finding{Kind: KindAuth, Severity: SevHigh, Subject: KindAuth, Summary: sum}
	}
	return next, kept, nil
}

func authFail(line string) bool {
	for _, p := range failPhrases {
		if strings.Contains(line, p) {
			return true
		}
	}
	return false
}

// lineIP reads sshd's "... from ADDR port N ..." structure: the token after
// the last " from " before the last " port ". A user name can contain
// " from " but sshd writes the real address and port after it. Anything that
// does not parse as an IP yields no IP.
func lineIP(line string) string {
	i := strings.LastIndex(line, " port ")
	if i < 0 {
		return ""
	}
	head := line[:i]
	j := strings.LastIndex(head, " from ")
	if j < 0 {
		return ""
	}
	tok := head[j+len(" from "):]
	if strings.ContainsAny(tok, " \t") {
		return ""
	}
	if ip := net.ParseIP(tok); ip != nil {
		return ip.String()
	}
	return ""
}

func readWindow(path string, pos AuthPos) ([]string, AuthPos, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, pos, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, pos, codes.E(codes.BadPath)
	}
	f, st, err := openRegular(path)
	if err != nil {
		return nil, pos, err
	}
	defer f.Close()
	cur := AuthPos{Path: path, Ino: uint64(st.Ino), Dev: uint64(st.Dev), Offset: pos.Offset}
	if pos.Path != path {
		cur.Offset = st.Size
		return nil, cur, nil
	}
	if pos.Ino != cur.Ino || pos.Dev != cur.Dev || pos.Offset < 0 || pos.Offset > st.Size {
		cur.Offset = 0
	}
	offset := cur.Offset
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, pos, err
	}
	buf := make([]byte, ScanMax)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, pos, err
	}
	data := buf[:n]
	if len(data) == 0 {
		return nil, cur, nil
	}
	rel := bytes.LastIndexByte(data, '\n')
	if rel < 0 {
		cur.Offset = offset + int64(len(data))
		return nil, cur, nil
	}
	cur.Offset = offset + int64(rel) + 1
	parts := bytes.Split(data[:rel], []byte{'\n'})
	lines := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) > LineMax {
			continue
		}
		lines = append(lines, string(p))
	}
	return lines, cur, nil
}

// Check reports the integrity state of path. A nil base means the path has no
// baseline record. An empty Kind means the file matches its baseline.
func Check(path string, base *Record) Finding {
	baselined := base != nil
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			if baselined {
				return Finding{Kind: KindMiss, Severity: SevHigh, Subject: path, Summary: "missing"}
			}
			return Finding{Kind: KindBase, Severity: SevMedium, Subject: path, Summary: "unbaselined"}
		}
		return unread(path, baselined)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return Finding{Kind: KindLink, Severity: SevHigh, Subject: path, Summary: "symlink"}
	}
	if !fi.Mode().IsRegular() {
		sev := SevMedium
		if baselined {
			sev = SevHigh
		}
		return Finding{Kind: KindNotReg, Severity: sev, Subject: path, Summary: "not a file"}
	}
	if fi.Size() > FileMax {
		return oversize(path, baselined)
	}
	rec, err := hashOpen(path)
	if err != nil {
		if err == errBig {
			return oversize(path, baselined)
		}
		if codes.Code(err) == codes.NotRegular {
			sev := SevMedium
			if baselined {
				sev = SevHigh
			}
			return Finding{Kind: KindNotReg, Severity: sev, Subject: path, Summary: "not a file"}
		}
		return unread(path, baselined)
	}
	if !baselined {
		return Finding{Kind: KindBase, Severity: SevMedium, Subject: path, Summary: "unbaselined"}
	}
	if rec.SHA256 != base.SHA256 || rec.Size != base.Size {
		return Finding{Kind: KindChange, Severity: SevHigh, Subject: path, Summary: "changed " + rec.SHA256[:12]}
	}
	if rec.Mode != base.Mode || rec.UID != base.UID || rec.GID != base.GID {
		return Finding{Kind: KindChange, Severity: SevHigh, Subject: path, Summary: "mode or owner changed"}
	}
	return Finding{}
}

// Upgrade turns a version-1 record into a current one. What version 1 held
// (hash, size, permission bits) is kept, so a change made before the upgrade
// still shows on the next check. What it lacked (type, setuid, setgid, sticky,
// uid, gid) is read from the file now. An unreadable file keeps a regular
// type and uid and gid 0, which fails closed on the next check.
func Upgrade(path string, v1 Record) Record {
	out := Record{SHA256: v1.SHA256, Size: v1.Size, Mode: unix.S_IFREG | v1.Mode&0o777}
	f, st, err := openRegular(path)
	if err != nil {
		return out
	}
	f.Close()
	out.Mode = uint32(st.Mode)&^0o777 | v1.Mode&0o777
	out.UID = st.Uid
	out.GID = st.Gid
	return out
}

func oversize(path string, baselined bool) Finding {
	sev := SevMedium
	if baselined {
		sev = SevHigh
	}
	return Finding{Kind: KindBig, Severity: sev, Subject: path, Summary: "oversize"}
}

func unread(path string, baselined bool) Finding {
	if baselined {
		return Finding{Kind: KindChange, Severity: SevHigh, Subject: path, Summary: "unreadable"}
	}
	return Finding{Kind: KindBase, Severity: SevMedium, Subject: path, Summary: "unbaselined"}
}

var errBig = codes.E(codes.Oversized)

// Measure hashes a regular file for a baseline. Symlinks, directories, missing
// paths, unreadable files, and files over FileMax are bad_path.
func Measure(path string) (Record, error) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Size() > FileMax {
		return Record{}, codes.E(codes.BadPath)
	}
	rec, err := hashOpen(path)
	if err != nil {
		return Record{}, codes.E(codes.BadPath)
	}
	return rec, nil
}

// openRegular opens path O_NONBLOCK|O_NOFOLLOW and refuses anything fstat
// does not call a regular file, so a FIFO never blocks the open or the read.
func openRegular(path string) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, st, err
	}
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, st, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, st, codes.E(codes.NotRegular)
	}
	return os.NewFile(uintptr(fd), path), st, nil
}

func hashOpen(path string) (Record, error) {
	f, st, err := openRegular(path)
	if err != nil {
		return Record{}, err
	}
	defer f.Close()
	if st.Size > FileMax {
		return Record{}, errBig
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, FileMax+1))
	if err != nil {
		return Record{}, err
	}
	if n > FileMax {
		return Record{}, errBig
	}
	sum := h.Sum(nil)
	return Record{SHA256: hex.EncodeToString(sum), Mode: uint32(st.Mode), Size: st.Size, UID: st.Uid, GID: st.Gid}, nil
}

// Detect compares listeners in tcp and tcp6 text with the allowlist.
// An empty allowlist is off and does not parse. oversize or readErr or a
// decode failure is unsupported.
func Detect(allow []string, tcp, tcp6 string, oversize bool, readErr error) (string, []Finding) {
	if len(allow) == 0 {
		return StateOff, nil
	}
	if oversize || readErr != nil {
		return StateBad, nil
	}
	got, err := parseProc(tcp)
	if err != nil {
		return StateBad, nil
	}
	got6, err := parseProc(tcp6)
	if err != nil {
		return StateBad, nil
	}
	ok := make(map[string]struct{}, len(allow))
	for _, a := range allow {
		ok[a] = struct{}{}
	}
	seen := map[string]struct{}{}
	var bad []string
	for _, addr := range append(got, got6...) {
		if _, hit := ok[addr]; hit {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		bad = append(bad, addr)
	}
	sort.Strings(bad)
	var out []Finding
	trunc := false
	if len(bad) > ListenCap {
		bad = bad[:ListenCap]
		trunc = true
	}
	for _, addr := range bad {
		out = append(out, Finding{Kind: KindListen, Severity: SevHigh, Subject: addr, Summary: addr})
	}
	if trunc {
		out = append(out, Finding{Kind: KindTrunc, Severity: SevMedium, Subject: KindTrunc, Summary: "listen truncated"})
	}
	return StateOK, out
}

func parseProc(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !hexAddr.MatchString(f[1]) {
			continue
		}
		if len(f) < 4 {
			return nil, codes.E(codes.Failed)
		}
		if f[3] != "0A" && f[3] != "0a" {
			continue
		}
		addr, err := decodeSock(f[1])
		if err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	return out, nil
}

func decodeSock(local string) (string, error) {
	host, port, ok := strings.Cut(local, ":")
	if !ok || len(port) != 4 {
		return "", codes.E(codes.Failed)
	}
	n, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return "", codes.E(codes.Failed)
	}
	raw, err := hex.DecodeString(host)
	if err != nil {
		return "", codes.E(codes.Failed)
	}
	var ip net.IP
	switch len(raw) {
	case 4:
		ip = net.IPv4(raw[3], raw[2], raw[1], raw[0])
	case 16:
		rev := make([]byte, 16)
		for i := 0; i < 4; i++ {
			g := raw[i*4 : i*4+4]
			rev[i*4], rev[i*4+1], rev[i*4+2], rev[i*4+3] = g[3], g[2], g[1], g[0]
		}
		ip = net.IP(rev)
	default:
		return "", codes.E(codes.Failed)
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(n, 10)), nil
}
