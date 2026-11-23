// Package grant verifies secsvc/2 Ed25519 grants.
//
// Threats: a forged, swapped, expired, over-long, star, or filesystem-root
// grant must not authorize a call. The signature is checked before expiry,
// star, root, TTL, purpose ceiling, and host. iat is signed: a grant issued in
// the future (beyond MaxSkew) is grant_future, and exp - iat above MaxTTL is
// grant_ttl, so a far-future grant never becomes usable in its last minutes.
// A secsvc/1 grant has no iat and is grant_bad_shape. The daemon holds only a public
// key. This package does not verify sash/1 or systemapi leases, does not
// spend lease ids (the API does), and does not stop a parent-directory symlink.
package grant

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"github.com/afterdarksys/systemapi-security/internal/paths"
)

const (
	Version         = "secsvc/2"
	Domain          = "secsvc-grant-v2\n"
	MaxDocument     = 16 << 10
	MaxTTL          = 900
	MaxSkew         = 60
	MaxEntitlements = 16
	MaxWatch        = 64
	PurposeRead     = "security:read"
	PurposeConfig   = "security:config"
	PurposeOperate  = "security:operate"
	// PurposeWitness is the off-host anchor's purpose. Only it carries
	// security.witness, so no config or operate grant can post a witness.
	PurposeWitness = "security:witness"
	EntAudit       = "security.audit"
	EntBaseline    = "security.baseline"
	EntConfig      = "security.config"
	EntNotify      = "security.notify"
	EntRead        = "security.read"
	EntScan        = "security.scan"
	EntWitness     = "security.witness"
)

var (
	actorRe = regexp.MustCompile(`^[A-Za-z0-9:._@/-]{1,128}$`)
	hostRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`)
	leaseRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	entRe   = regexp.MustCompile(`^[a-z][a-z0-9.]{0,63}$`)
)

// Grant is a verified secsvc/2 document. Slices are sorted and non-nil.
type Grant struct {
	V            string
	Actor        string
	Host         string
	Purpose      string
	Iat          int64
	Exp          int64
	LeaseID      string
	Entitlements []string
	Watch        []string
}

type signed struct {
	V            string   `json:"v"`
	Actor        string   `json:"actor"`
	Host         string   `json:"host"`
	Purpose      string   `json:"purpose"`
	Iat          int64    `json:"iat"`
	Exp          int64    `json:"exp"`
	LeaseID      string   `json:"lease_id"`
	Entitlements []string `json:"entitlements"`
	Watch        []string `json:"watch"`
}

type wire struct {
	signed
	Sig string `json:"sig"`
}

// Ceiling returns a copy of the entitlements a purpose may carry, already sorted.
// An unknown purpose returns nil.
func Ceiling(purpose string) []string {
	var src []string
	switch purpose {
	case PurposeRead:
		src = []string{EntAudit, EntRead}
	case PurposeConfig:
		src = []string{EntAudit, EntBaseline, EntConfig, EntNotify, EntRead}
	case PurposeOperate:
		src = []string{EntAudit, EntBaseline, EntConfig, EntNotify, EntRead, EntScan}
	case PurposeWitness:
		src = []string{EntAudit, EntWitness}
	default:
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// Fill returns the purpose ceiling. The CLI uses it when entitlements are omitted.
func Fill(purpose string) []string { return Ceiling(purpose) }

// HostOK reports whether host matches the grant host grammar.
func HostOK(host string) bool { return hostRe.MatchString(host) }

// ActorOK reports whether actor matches the grant actor grammar.
func ActorOK(actor string) bool { return actorRe.MatchString(actor) }

// LeaseOK reports whether id matches the lease grammar.
func LeaseOK(id string) bool { return leaseRe.MatchString(id) }

// NewLeaseID returns 32 hex chars from 16 CSPRNG bytes.
func NewLeaseID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", codes.E(codes.Failed)
	}
	return hex.EncodeToString(b[:]), nil
}

// NormalizeWire strips one trailing newline. A remaining newline or a
// document over MaxDocument is grant_bad_shape. An empty result is empty.
func NormalizeWire(b []byte) (string, error) {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	if bytesContainsCRLF(b) || len(b) > MaxDocument {
		return "", codes.E(codes.GrantBadShape)
	}
	return string(b), nil
}

func bytesContainsCRLF(b []byte) bool {
	for _, c := range b {
		if c == '\n' || c == '\r' {
			return true
		}
	}
	return false
}

// Sign produces compact grant JSON. It sorts entitlement and watch copies
// and does not enforce expiry, TTL, star, root, purpose, or host. The seed
// must be 32 bytes. The caller is not mutated.
func Sign(seed []byte, g Grant) ([]byte, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, codes.E(codes.Failed)
	}
	s := signed{
		V:            g.V,
		Actor:        g.Actor,
		Host:         g.Host,
		Purpose:      g.Purpose,
		Iat:          g.Iat,
		Exp:          g.Exp,
		LeaseID:      g.LeaseID,
		Entitlements: norm(g.Entitlements),
		Watch:        norm(g.Watch),
	}
	msg, err := message(s)
	if err != nil {
		return nil, codes.E(codes.GrantBadShape)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, msg)
	out, err := codes.Marshal(wire{signed: s, Sig: base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		return nil, codes.E(codes.GrantBadShape)
	}
	return out, nil
}

// Verify checks doc against pub for daemon host at now.
// Order: shape, then signature, then star, root, expiry, iat, TTL, purpose, host.
func Verify(doc string, pub ed25519.PublicKey, host string, now time.Time) (*Grant, error) {
	if doc == "" {
		return nil, codes.E(codes.GrantMissing)
	}
	if len(doc) > MaxDocument || strings.ContainsAny(doc, "\r\n") {
		return nil, codes.E(codes.GrantBadShape)
	}
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.DisallowUnknownFields()
	var w wire
	if err := dec.Decode(&w); err != nil {
		return nil, codes.E(codes.GrantBadShape)
	}
	if dec.More() {
		return nil, codes.E(codes.GrantBadShape)
	}
	var raw map[string]json.RawMessage
	dec2 := json.NewDecoder(strings.NewReader(doc))
	dec2.DisallowUnknownFields()
	if err := dec2.Decode(&raw); err != nil {
		return nil, codes.E(codes.GrantBadShape)
	}
	for _, k := range []string{"v", "actor", "host", "purpose", "iat", "exp", "lease_id", "entitlements", "watch", "sig"} {
		b, ok := raw[k]
		if !ok || strings.TrimSpace(string(b)) == "null" {
			return nil, codes.E(codes.GrantBadShape)
		}
	}
	if err := shape(w); err != nil {
		return nil, err
	}
	if w.Sig == "" {
		return nil, codes.E(codes.GrantBadShape)
	}
	sig, err := base64.StdEncoding.DecodeString(w.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize || len(pub) != ed25519.PublicKeySize {
		return nil, codes.E(codes.GrantBadSig)
	}
	msg, err := message(w.signed)
	if err != nil {
		return nil, codes.E(codes.GrantBadShape)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return nil, codes.E(codes.GrantBadSig)
	}
	if hasStar(w.Entitlements) || hasStar(w.Watch) {
		return nil, codes.E(codes.GrantStar)
	}
	if hasRoot(w.Watch) {
		return nil, codes.E(codes.GrantRootSlash)
	}
	nowS := now.Unix()
	if w.Exp <= nowS {
		return nil, codes.E(codes.GrantExpired)
	}
	if w.Iat > nowS+MaxSkew {
		return nil, codes.E(codes.GrantFuture)
	}
	if w.Exp <= w.Iat || w.Exp-w.Iat > MaxTTL || w.Exp > nowS+MaxTTL {
		return nil, codes.E(codes.GrantTTL)
	}
	if err := ceilingOK(w.Purpose, w.Entitlements); err != nil {
		return nil, err
	}
	if w.Host != host {
		return nil, codes.E(codes.GrantHost)
	}
	return &Grant{
		V:            w.V,
		Actor:        w.Actor,
		Host:         w.Host,
		Purpose:      w.Purpose,
		Iat:          w.Iat,
		Exp:          w.Exp,
		LeaseID:      w.LeaseID,
		Entitlements: norm(w.Entitlements),
		Watch:        norm(w.Watch),
	}, nil
}

func shape(w wire) error {
	if w.V != Version || w.Iat <= 0 || !actorRe.MatchString(w.Actor) || !hostRe.MatchString(w.Host) || !leaseRe.MatchString(w.LeaseID) {
		return codes.E(codes.GrantBadShape)
	}
	switch w.Purpose {
	case PurposeRead, PurposeConfig, PurposeOperate, PurposeWitness:
	default:
		return codes.E(codes.GrantBadShape)
	}
	if len(w.Entitlements) > MaxEntitlements || len(w.Watch) > MaxWatch {
		return codes.E(codes.GrantBadShape)
	}
	if dups(w.Entitlements) || dups(w.Watch) {
		return codes.E(codes.GrantBadShape)
	}
	for _, e := range w.Entitlements {
		if e == "*" {
			continue
		}
		if !entRe.MatchString(e) {
			return codes.E(codes.GrantBadShape)
		}
	}
	for _, p := range w.Watch {
		if err := watchShape(p); err != nil {
			return err
		}
	}
	return nil
}

func watchShape(p string) error {
	if p == "" || strings.ContainsRune(p, 0) || strings.ContainsAny(p, "\r\n") {
		return codes.E(codes.GrantBadShape)
	}
	if p == "*" || paths.IsRoot(p) {
		return nil
	}
	if !paths.IsAbsClean(p) {
		return codes.E(codes.GrantBadShape)
	}
	return nil
}

func ceilingOK(purpose string, ents []string) error {
	allow := Ceiling(purpose)
	for _, e := range ents {
		if !contains(allow, e) {
			return codes.E(codes.GrantPurpose)
		}
	}
	return nil
}

// Has reports whether g authorizes ent. A star or empty entry authorizes nothing.
// The purpose ceiling is checked again so a constructed grant fails closed.
func (g *Grant) Has(ent string) bool {
	if g == nil || ent == "" || ent == "*" {
		return false
	}
	if !contains(Ceiling(g.Purpose), ent) {
		return false
	}
	for _, e := range g.Entitlements {
		if e == "*" || e == "" {
			return false
		}
	}
	return contains(g.Entitlements, ent)
}

// Covers reports whether p is under a watch root.
// Any star or root entry covers nothing. p itself must be absolute and clean.
func (g *Grant) Covers(p string) bool {
	if g == nil || !paths.IsAbsClean(p) || paths.IsRoot(p) {
		return false
	}
	for _, w := range g.Watch {
		if w == "*" || w == "" || paths.IsRoot(w) {
			return false
		}
	}
	for _, w := range g.Watch {
		if paths.Under(p, w) {
			return true
		}
	}
	return false
}

func message(s signed) ([]byte, error) {
	s.Entitlements = norm(s.Entitlements)
	s.Watch = norm(s.Watch)
	body, err := codes.Marshal(s)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 0, len(Domain)+len(body))
	msg = append(msg, Domain...)
	msg = append(msg, body...)
	return msg, nil
}

func norm(in []string) []string {
	out := append([]string(nil), in...)
	if out == nil {
		out = []string{}
	}
	sort.Strings(out)
	return out
}

func dups(ss []string) bool {
	seen := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			return true
		}
		seen[s] = struct{}{}
	}
	return false
}

func hasStar(ss []string) bool {
	for _, s := range ss {
		if s == "*" {
			return true
		}
	}
	return false
}

func hasRoot(ss []string) bool {
	for _, s := range ss {
		if paths.IsRoot(s) {
			return true
		}
	}
	return false
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
