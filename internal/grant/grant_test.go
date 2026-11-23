package grant

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
)

func testKey(t *testing.T) (seed []byte, pub ed25519.PublicKey) {
	t.Helper()
	seed, pub, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != ed25519.SeedSize || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("key sizes seed=%d pub=%d", len(seed), len(pub))
	}
	return seed, pub
}

func goodGrant(now time.Time) Grant {
	return Grant{
		V:            Version,
		Actor:        "ops:ryan",
		Host:         "localhost",
		Purpose:      PurposeRead,
		Iat:          now.Unix(),
		Exp:          now.Unix() + 600,
		LeaseID:      "lease-0001",
		Entitlements: []string{EntRead, EntAudit},
		Watch:        []string{"/var/lib"},
	}
}

func mustSign(t *testing.T, seed []byte, g Grant) string {
	t.Helper()
	b, err := Sign(seed, g)
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(string(b), "\r\n") {
		t.Fatalf("signed document contains a newline: %q", b)
	}
	return string(b)
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if codes.Code(err) != code {
		t.Fatalf("code %q, want %q (%v)", codes.Code(err), code, err)
	}
	if err != nil && err.Error() != code {
		t.Fatalf("Error() %q leaked past the stable code", err.Error())
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	seed, pub := testKey(t)
	in := goodGrant(now)
	order := append([]string(nil), in.Entitlements...)
	doc := mustSign(t, seed, in)
	if !strings.EqualFold(strings.Join(order, ","), strings.Join(in.Entitlements, ",")) && (in.Entitlements[0] != order[0]) {
		t.Fatal("Sign mutated the caller entitlement order")
	}
	g, err := Verify(doc, pub, "localhost", now)
	if err != nil {
		t.Fatal(err)
	}
	if g.Entitlements[0] != EntAudit || g.Entitlements[1] != EntRead {
		t.Fatalf("entitlements not sorted: %v", g.Entitlements)
	}
	if !g.Has(EntRead) || !g.Has(EntAudit) || g.Has(EntScan) || g.Has("") || g.Has("*") {
		t.Fatalf("Has failed closed or open: %v", g.Entitlements)
	}
	if !g.Covers("/var/lib") || !g.Covers("/var/lib/x") || g.Covers("/var/lib2") || g.Covers("/") || g.Covers("/tmp/../tmp") {
		t.Fatal("Covers mismatch")
	}
	id, err := NewLeaseID()
	if err != nil || len(id) != 32 || !LeaseOK(id) {
		t.Fatalf("lease %q err %v", id, err)
	}
	if Ceiling(PurposeRead)[0] != EntAudit || Fill(PurposeOperate)[len(Fill(PurposeOperate))-1] != EntScan {
		t.Fatalf("ceiling %v %v", Ceiling(PurposeRead), Fill(PurposeOperate))
	}
	if !HostOK("localhost") || HostOK("Local") || !ActorOK("ops:ryan") || ActorOK("*") {
		t.Fatal("grammar")
	}
}

func TestVerifyRejects(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	seed, pub := testKey(t)
	_, other := testKey(t)
	base := mustSign(t, seed, goodGrant(now))

	t.Run("missing", func(t *testing.T) {
		_, err := Verify("", pub, "localhost", now)
		wantCode(t, err, codes.GrantMissing)
	})
	t.Run("whitespace", func(t *testing.T) {
		_, err := Verify("   ", pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("oversized", func(t *testing.T) {
		_, err := Verify(strings.Repeat("a", MaxDocument+1), pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("newline", func(t *testing.T) {
		_, err := Verify(base+"\n", pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("cr", func(t *testing.T) {
		_, err := Verify(strings.Replace(base, "localhost", "local\rhost", 1), pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("unknown", func(t *testing.T) {
		_, err := Verify(strings.TrimSuffix(base, "}")+`,"extra":1}`, pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("trailing", func(t *testing.T) {
		_, err := Verify(base+`{"a":1}`, pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("nullwatch", func(t *testing.T) {
		doc := strings.Replace(base, `"watch":["/var/lib"]`, `"watch":null`, 1)
		_, err := Verify(doc, pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("misswatch", func(t *testing.T) {
		doc := strings.Replace(base, `,"watch":["/var/lib"]`, ``, 1)
		_, err := Verify(doc, pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("float", func(t *testing.T) {
		g := goodGrant(now)
		doc := mustSign(t, seed, g)
		doc = strings.Replace(doc, `"exp":`+itoa(g.Exp), `"exp":1.0`, 1)
		_, err := Verify(doc, pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("emptysig", func(t *testing.T) {
		doc := replaceSig(t, base, "")
		_, err := Verify(doc, pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("badsig", func(t *testing.T) {
		_, err := Verify(replaceSig(t, base, base64.StdEncoding.EncodeToString(make([]byte, 32))), pub, "localhost", now)
		wantCode(t, err, codes.GrantBadSig)
	})
	t.Run("badb64", func(t *testing.T) {
		_, err := Verify(replaceSig(t, base, "!!!!"), pub, "localhost", now)
		wantCode(t, err, codes.GrantBadSig)
	})
	t.Run("nilpub", func(t *testing.T) {
		_, err := Verify(base, nil, "localhost", now)
		wantCode(t, err, codes.GrantBadSig)
	})
	t.Run("wrongkey", func(t *testing.T) {
		_, err := Verify(base, other, "localhost", now)
		wantCode(t, err, codes.GrantBadSig)
	})
	t.Run("tamper", func(t *testing.T) {
		_, err := Verify(strings.Replace(base, "ops:ryan", "ops:evil", 1), pub, "localhost", now)
		wantCode(t, err, codes.GrantBadSig)
	})
	t.Run("unsorted", func(t *testing.T) {
		doc := strings.Replace(base, `["security.audit","security.read"]`, `["security.read","security.audit"]`, 1)
		g, err := Verify(doc, pub, "localhost", now)
		if err != nil {
			t.Fatal(err)
		}
		if g.Entitlements[0] != EntAudit {
			t.Fatalf("got %v", g.Entitlements)
		}
	})
}

func TestPolicyAfterSignature(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	seed, pub := testKey(t)

	sign := func(mut func(*Grant)) string {
		t.Helper()
		g := goodGrant(now)
		mut(&g)
		return mustSign(t, seed, g)
	}

	t.Run("expired", func(t *testing.T) {
		_, err := Verify(sign(func(g *Grant) { g.Exp = now.Unix() }), pub, "localhost", now)
		wantCode(t, err, codes.GrantExpired)
	})
	t.Run("ttl-eq", func(t *testing.T) {
		doc := sign(func(g *Grant) { g.Exp = now.Unix() + MaxTTL })
		if _, err := Verify(doc, pub, "localhost", now); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("ttl-over", func(t *testing.T) {
		_, err := Verify(sign(func(g *Grant) { g.Exp = now.Unix() + MaxTTL + 1 }), pub, "localhost", now)
		wantCode(t, err, codes.GrantTTL)
	})
	t.Run("star", func(t *testing.T) {
		doc := sign(func(g *Grant) { g.Entitlements = []string{"*"} })
		_, err := Verify(doc, pub, "localhost", now)
		wantCode(t, err, codes.GrantStar)
		_, err = Verify(flipSig(t, doc), pub, "localhost", now)
		wantCode(t, err, codes.GrantBadSig)
	})
	t.Run("dupstar", func(t *testing.T) {
		doc := sign(func(g *Grant) { g.Entitlements = []string{"*", "*"} })
		_, err := Verify(doc, pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
		_, err = Verify(flipSig(t, doc), pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("dupent", func(t *testing.T) {
		doc := sign(func(g *Grant) { g.Entitlements = []string{EntRead, EntRead} })
		_, err := Verify(doc, pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	for _, root := range []string{"/", "//", "/./", "/..", "/foo/../../"} {
		root := root
		t.Run("root-"+root, func(t *testing.T) {
			doc := sign(func(g *Grant) { g.Watch = []string{root} })
			_, err := Verify(doc, pub, "localhost", now)
			wantCode(t, err, codes.GrantRootSlash)
			if err.Error() != codes.GrantRootSlash {
				t.Fatal(err)
			}
		})
	}
	t.Run("unclean", func(t *testing.T) {
		doc := sign(func(g *Grant) { g.Watch = []string{"/tmp/../tmp"} })
		_, err := Verify(doc, pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("dupslash", func(t *testing.T) {
		doc := sign(func(g *Grant) { g.Watch = []string{"/", "/"} })
		_, err := Verify(doc, pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("host", func(t *testing.T) {
		_, err := Verify(sign(func(g *Grant) {}), pub, "otherhost", now)
		wantCode(t, err, codes.GrantHost)
	})
	t.Run("ceiling", func(t *testing.T) {
		doc := sign(func(g *Grant) { g.Entitlements = []string{EntScan} })
		_, err := Verify(doc, pub, "localhost", now)
		wantCode(t, err, codes.GrantPurpose)
	})
	t.Run("unknownent", func(t *testing.T) {
		doc := sign(func(g *Grant) { g.Entitlements = []string{"security.pwn"} })
		_, err := Verify(doc, pub, "localhost", now)
		wantCode(t, err, codes.GrantPurpose)
	})
	t.Run("badent", func(t *testing.T) {
		doc := sign(func(g *Grant) { g.Entitlements = []string{"Bad_Name"} })
		_, err := Verify(doc, pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
		_, err = Verify(flipSig(t, doc), pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("badpurpose", func(t *testing.T) {
		_, err := Verify(sign(func(g *Grant) { g.Purpose = "security:own" }), pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
	t.Run("emptyents", func(t *testing.T) {
		g, err := Verify(sign(func(g *Grant) { g.Entitlements = []string{} }), pub, "localhost", now)
		if err != nil {
			t.Fatal(err)
		}
		if g.Has(EntRead) {
			t.Fatal("empty entitlements authorized a call")
		}
	})
}

func TestHasAndCoversFailClosed(t *testing.T) {
	g := &Grant{Purpose: PurposeOperate, Entitlements: []string{"*"}, Watch: []string{"*"}}
	if g.Has(EntScan) || g.Covers("/var/lib/x") {
		t.Fatal("star grant authorized a call")
	}
	root := &Grant{Purpose: PurposeOperate, Entitlements: []string{EntScan}, Watch: []string{"/"}}
	if root.Covers("/var/lib") || root.Covers("/") {
		t.Fatal("root covers a path")
	}
	over := &Grant{Purpose: PurposeRead, Entitlements: []string{EntScan}, Watch: []string{"/var/lib"}}
	if over.Has(EntScan) {
		t.Fatal("purpose ceiling bypass")
	}
	if (*Grant)(nil).Has(EntRead) || (*Grant)(nil).Covers("/var/lib") {
		t.Fatal("nil grant")
	}
}

func TestNormalizeWire(t *testing.T) {
	s, err := NormalizeWire([]byte("{\"v\":1}\n"))
	if err != nil || s != `{"v":1}` {
		t.Fatalf("%q %v", s, err)
	}
	_, err = NormalizeWire([]byte("a\n\n"))
	wantCode(t, err, codes.GrantBadShape)
	s, err = NormalizeWire(nil)
	if err != nil || s != "" {
		t.Fatalf("%q %v", s, err)
	}
	_, err = NormalizeWire([]byte(strings.Repeat("a", MaxDocument+1)))
	wantCode(t, err, codes.GrantBadShape)
}

func TestKeyFiles(t *testing.T) {
	dir := t.TempDir()
	seed, pub := testKey(t)
	path := filepath.Join(dir, "seed")
	if err := WriteSeed(path, seed); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSeed(path)
	if err != nil || string(got) != string(seed) {
		t.Fatalf("load %v %v", got, err)
	}
	if err := WriteSeed(path, seed); err == nil {
		t.Fatal("overwrote seed")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadSeed(path)
	wantCode(t, err, codes.SeedPerms)

	hexPath := filepath.Join(dir, "pub.hex")
	if err := os.WriteFile(hexPath, []byte(PubHex(pub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPub(hexPath)
	if err != nil || !loaded.Equal(pub) {
		t.Fatal(err)
	}
	rawNL := filepath.Join(dir, "rawnl")
	buf := append(append([]byte{}, seed...), '\n')
	if err := os.WriteFile(rawNL, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadSeed(rawNL)
	wantCode(t, err, codes.BadPub)

	priv := filepath.Join(dir, "priv64")
	if err := os.WriteFile(priv, make([]byte, 64), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadSeed(priv)
	wantCode(t, err, codes.BadPub)

	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	_, err = LoadSeed(link)
	wantCode(t, err, codes.BadPub)
	_, err = LoadPub(link)
	wantCode(t, err, codes.BadPub)

	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, []byte(strings.Repeat("aa", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadSeed(big)
	wantCode(t, err, codes.BadPub)
	_, err = LoadSeed(filepath.Join(dir, "missing"))
	wantCode(t, err, codes.BadPub)
	if _, err := Sign(seed[:16], goodGrant(time.Unix(1, 0))); err == nil {
		t.Fatal("short seed signed")
	}
}

func replaceSig(t *testing.T, doc, sig string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatal(err)
	}
	m["sig"] = sig
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func flipSig(t *testing.T, doc string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(m["sig"].(string))
	if err != nil || len(raw) != ed25519.SignatureSize {
		t.Fatal(err)
	}
	raw[0] ^= 0xff
	m["sig"] = base64.StdEncoding.EncodeToString(raw)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func TestIssuedAt(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	seed, pub := testKey(t)
	sign := func(iat, exp int64) string {
		t.Helper()
		g := goodGrant(now)
		g.Iat, g.Exp = iat, exp
		return mustSign(t, seed, g)
	}
	n := now.Unix()
	cases := []struct {
		name     string
		iat, exp int64
		code     string
	}{
		{"now", n, n + 600, ""},
		{"skew-edge", n + MaxSkew, n + MaxSkew + 1, ""},
		{"future", n + MaxSkew + 1, n + MaxSkew + 2, codes.GrantFuture},
		// Far-future grant in its last minutes: exp is near, but it was cut
		// for longer than the ceiling.
		{"long-lived", n - 3600, n + 60, codes.GrantTTL},
		{"ttl-span", n - 1, n + MaxTTL, codes.GrantTTL},
		{"exp-before-iat", n + 30, n + 20, codes.GrantTTL},
		{"zero", 0, n + 600, codes.GrantBadShape},
		{"negative", -1, n + 600, codes.GrantBadShape},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, err := Verify(sign(tc.iat, tc.exp), pub, "localhost", now)
			wantCode(t, err, tc.code)
			if err == nil && g.Iat != tc.iat {
				t.Fatalf("iat %d", g.Iat)
			}
		})
	}
	t.Run("tamper-iat", func(t *testing.T) {
		doc := sign(n, n+600)
		doc = strings.Replace(doc, `"iat":`+itoa(n), `"iat":`+itoa(n-1), 1)
		_, err := Verify(doc, pub, "localhost", now)
		wantCode(t, err, codes.GrantBadSig)
	})
	t.Run("missing-iat", func(t *testing.T) {
		doc := strings.Replace(sign(n, n+600), `"iat":`+itoa(n)+`,`, ``, 1)
		_, err := Verify(doc, pub, "localhost", now)
		wantCode(t, err, codes.GrantBadShape)
	})
}

// A secsvc/1 grant, signed correctly under the old domain, is refused.
func TestRefusesV1(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	seed, pub := testKey(t)
	type v1 struct {
		V            string   `json:"v"`
		Actor        string   `json:"actor"`
		Host         string   `json:"host"`
		Purpose      string   `json:"purpose"`
		Exp          int64    `json:"exp"`
		LeaseID      string   `json:"lease_id"`
		Entitlements []string `json:"entitlements"`
		Watch        []string `json:"watch"`
	}
	body := v1{"secsvc/1", "ops:ryan", "localhost", PurposeRead, now.Unix() + 600, "lease-0001", []string{EntAudit, EntRead}, []string{"/var/lib"}}
	raw, err := codes.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), append([]byte("secsvc-grant-v1\n"), raw...))
	doc, err := codes.Marshal(struct {
		v1
		Sig string `json:"sig"`
	}{body, base64.StdEncoding.EncodeToString(sig)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(string(doc), pub, "localhost", now)
	wantCode(t, err, codes.GrantBadShape)
	// The same fields with a v2 iat but the old version string are refused too.
	g := goodGrant(now)
	g.V = "secsvc/1"
	_, err = Verify(mustSign(t, seed, g), pub, "localhost", now)
	wantCode(t, err, codes.GrantBadShape)
}

// A v2-shaped grant signed over the v1 domain string is not valid.
func TestDomainIsV2(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	seed, pub := testKey(t)
	g := goodGrant(now)
	body := signed{V: g.V, Actor: g.Actor, Host: g.Host, Purpose: g.Purpose, Iat: g.Iat, Exp: g.Exp,
		LeaseID: g.LeaseID, Entitlements: norm(g.Entitlements), Watch: norm(g.Watch)}
	raw, err := codes.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"secsvc-grant-v1\n", ""} {
		sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), append([]byte(domain), raw...))
		doc, err := codes.Marshal(wire{signed: body, Sig: base64.StdEncoding.EncodeToString(sig)})
		if err != nil {
			t.Fatal(err)
		}
		_, err = Verify(string(doc), pub, "localhost", now)
		wantCode(t, err, codes.GrantBadSig)
	}
	if Domain != "secsvc-grant-v2\n" {
		t.Fatalf("domain %q", Domain)
	}
}
