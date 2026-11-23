// Package codes holds the stable error strings secsvc prints and returns.
// Callers compare these strings. They are not paths, keys, or request bodies.
package codes

import (
	"bytes"
	"encoding/json"
	"errors"
)

const (
	GrantMissing   = "grant_missing"
	GrantBadSig    = "grant_bad_sig"
	GrantExpired   = "grant_expired"
	GrantBadShape  = "grant_bad_shape"
	GrantHost      = "grant_host"
	GrantSpent     = "grant_spent"
	GrantPurpose   = "grant_purpose"
	GrantTTL       = "grant_ttl"
	GrantStar      = "grant_star"
	GrantRootSlash = "grant_root_slash"
	Forbidden      = "forbidden"
	BadContact     = "bad_contact"
	BadPath        = "bad_path"
	Oversized      = "oversized"
	Method         = "method"
	Failed         = "failed"
	AuditBad       = "audit_bad"
	BadPub         = "bad_pub"
	BadDir         = "bad_dir"
	BadSocket      = "bad_socket"
	BadHost        = "bad_host"
	SeedPerms      = "seed_perms"
	BlockedAddress = "blocked_address"
	Timeout        = "timeout"
	SendFailed     = "send_failed"
	Usage          = "usage"
	ReadyFailed    = "ready_failed"
	AuditTruncated = "audit_truncated"
	NotRegular     = "not_regular"
)

// Error is a stable code. Error() returns only that code.
type Error struct{ Code string }

func (e *Error) Error() string {
	if e == nil {
		return Failed
	}
	return e.Code
}

// E returns a stable error. The code is not wrapped with a path or a secret.
func E(code string) error { return &Error{Code: code} }

// Code extracts a stable code. Unknown errors become "failed" so a path or
// URL inside err.Error() is never forwarded to a log or a client.
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) && e.Code != "" {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return Failed
}

// Marshal encodes JSON with HTML escaping off so hashed bytes stay stable.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
