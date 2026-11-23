package modules

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const ReadLimit = 1 << 20

type Metadata struct {
	Mode fs.FileMode
	UID  uint32
	GID  uint32
}

// Reader permits fixture tests without touching the running host. Implementations
// must bound reads, reject special files and not follow arbitrary symlinks.
type Reader interface {
	ReadFile(string) ([]byte, error)
	Metadata(string) (Metadata, error)
	OS() string
}

type HostFS struct{}

func (HostFS) OS() string { return runtime.GOOS }

func openFile(p string) (*os.File, unix.Stat_t, error) {
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	f := os.NewFile(uintptr(fd), p)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, st, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		f.Close()
		return nil, st, errMalformed
	}
	return f, st, nil
}

func (HostFS) ReadFile(p string) ([]byte, error) {
	// The one allowed final-component symlink is the standard os-release alias.
	// Open the fixed target, never a pathname supplied by the link.
	if p == "/etc/os-release" {
		target, err := os.Readlink(p)
		if err == nil {
			resolved := target
			if !path.IsAbs(target) {
				resolved = path.Join("/etc", target)
			}
			if path.Clean(resolved) != "/usr/lib/os-release" {
				return nil, errMalformed
			}
			p = "/usr/lib/os-release"
		}
	}
	f, _, err := openFile(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, ReadLimit+1))
	if err != nil {
		return nil, err
	}
	if len(b) > ReadLimit {
		return nil, errOversized
	}
	return b, nil
}

func (HostFS) Metadata(p string) (Metadata, error) {
	// Lstat avoids needing read access just to assess permissions. It never
	// follows a final symlink, and no data is read using this result.
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		return Metadata{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return Metadata{}, errMalformed
	}
	return Metadata{Mode: fs.FileMode(st.Mode & 0777), UID: st.Uid, GID: st.Gid}, nil
}

func fileReason(err error) string {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		return "target_missing"
	}
	return "unreadable"
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9._+~^\-]{0,64}$`)

// parseRelease is a data parser, never a shell interpreter. Only three bounded
// fields are used. Unknown fields are ignored and unsafe values are rejected.
func parseRelease(b []byte) (string, string, error) {
	vals := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return "", "", errMalformed
		}
		if k != "ID" && k != "VERSION_ID" {
			continue
		}
		if _, exists := vals[k]; exists {
			return "", "", errMalformed
		}
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
			if v[len(v)-1] != v[0] {
				return "", "", errMalformed
			}
			v = v[1 : len(v)-1]
		}
		vals[k] = v
	}
	if !idPattern.MatchString(vals["ID"]) || !versionPattern.MatchString(vals["VERSION_ID"]) {
		return "", "", errMalformed
	}
	return vals["ID"], vals["VERSION_ID"], nil
}

func detect(f Reader) Platform {
	if f.OS() != "linux" {
		return Platform{State: "absent", Reason: "unsupported_os"}
	}
	b, err := f.ReadFile("/etc/os-release")
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) {
		b, err = f.ReadFile("/usr/lib/os-release")
	}
	if err != nil {
		return Platform{State: "degraded", Reason: reason(err)}
	}
	id, version, err := parseRelease(b)
	if err != nil {
		return Platform{State: "degraded", Reason: reason(err)}
	}
	out := Platform{ID: id, Version: version, State: "absent", Reason: "unsupported_distro"}
	// Exact ID matching deliberately avoids treating derivatives as validated.
	for _, p := range profiles {
		for _, alias := range p.OSIDs {
			if id == alias {
				out.Profile = p.ID
				out.State = "ok"
				out.Reason = ""
				return out
			}
		}
	}
	return out
}
