// Package paths is the slash-clean path policy shared by grants and config.
// A path is usable only when it is absolute and path.Clean does not change it.
package paths

import (
	"path"
	"strings"
)

const Max = 4096

// IsAbsClean reports whether p is an absolute path that path.Clean leaves unchanged.
func IsAbsClean(p string) bool {
	if p == "" || len(p) > Max {
		return false
	}
	if strings.ContainsRune(p, 0) || strings.ContainsAny(p, "\r\n") {
		return false
	}
	return path.IsAbs(p) && path.Clean(p) == p
}

// IsRoot reports the sash root rule: a leading slash whose clean form is "/".
// "/", "//", "/./", and "/.." are roots. "/tmp/../tmp" is not.
func IsRoot(p string) bool {
	if p == "" || strings.ContainsRune(p, 0) {
		return false
	}
	return strings.HasPrefix(p, "/") && path.Clean(p) == "/"
}

// Under reports whether child is root or a descendant of root.
// "/" covers nothing. "/var/lib" does not cover "/var/lib2".
func Under(child, root string) bool {
	if child == "" || root == "" {
		return false
	}
	c := path.Clean(child)
	r := path.Clean(root)
	if r == "/" || c == "/" {
		return false
	}
	return c == r || strings.HasPrefix(c, r+"/")
}
