package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"github.com/afterdarksys/systemapi-security/internal/engine"
	"github.com/afterdarksys/systemapi-security/internal/grant"
)

func TestVerifyRateLimited(t *testing.T) {
	f := newFix(t)
	clock := f.now
	f.srv.Now = func() time.Time { return clock }
	read := f.sign(t, grant.Grant{Purpose: grant.PurposeRead, Entitlements: grant.Fill(grant.PurposeRead), LeaseID: "lease-read1"})
	shell(t, call(f.srv, http.MethodGet, "/v1/audit/verify", read, ""), http.StatusOK)
	rec := call(f.srv, http.MethodGet, "/v1/audit/verify", read, "")
	shell(t, rec, http.StatusTooManyRequests)
	if errOf(t, rec) != codes.RateLimited {
		t.Fatal(rec.Body.String())
	}
	clock = clock.Add(59 * time.Second)
	shell(t, call(f.srv, http.MethodGet, "/v1/audit/verify", read, ""), http.StatusTooManyRequests)
	clock = clock.Add(2 * time.Second)
	shell(t, call(f.srv, http.MethodGet, "/v1/audit/verify", read, ""), http.StatusOK)
	// The tail is not rate-limited.
	shell(t, call(f.srv, http.MethodGet, "/v1/audit", read, ""), http.StatusOK)
	shell(t, call(f.srv, http.MethodGet, "/v1/audit", read, ""), http.StatusOK)
}

func headOf(t *testing.T, f *fix, doc string) (engine.SignedHead, []byte) {
	t.Helper()
	rec := call(f.srv, http.MethodGet, "/v1/audit/head", doc, "")
	shell(t, rec, http.StatusOK)
	var sh engine.SignedHead
	dec := json.NewDecoder(strings.NewReader(rec.Body.String()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sh); err != nil {
		t.Fatal(err)
	}
	b, err := codes.Marshal(sh.Head)
	if err != nil {
		t.Fatal(err)
	}
	return sh, b
}

func anchorPub(t *testing.T, f *fix, doc string) ed25519.PublicKey {
	t.Helper()
	rec := call(f.srv, http.MethodGet, "/v1/status", doc, "")
	shell(t, rec, http.StatusOK)
	var st struct {
		AnchorPub string `json:"anchor_pub"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString(st.AnchorPub)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("anchor_pub %q", st.AnchorPub)
	}
	return pub
}

func TestAuditHeadSigned(t *testing.T) {
	f := newFix(t)
	read := f.sign(t, grant.Grant{Purpose: grant.PurposeRead, Entitlements: grant.Fill(grant.PurposeRead), LeaseID: "lease-read1"})
	for i := 0; i < 3; i++ {
		if err := f.srv.Eng.Store.AppendAudit("a", "", "config.set", nil, f.now); err != nil {
			t.Fatal(err)
		}
	}
	pub := anchorPub(t, f, read)
	sh, msg := headOf(t, f, read)
	if sh.Head.Host != "host1" || sh.Head.Seq != 3 || sh.Head.Segment != 1 || len(sh.Head.Hash) != 64 || sh.Head.Time == "" {
		t.Fatalf("head %+v", sh.Head)
	}
	sig, err := base64.StdEncoding.DecodeString(sh.Sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, append([]byte(engine.HeadDomain), msg...), sig) {
		t.Fatal("head signature does not verify")
	}
	// The domain is part of the signed bytes.
	if ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature verifies without the domain")
	}
	other := sh.Head
	other.Seq = 2
	b, _ := codes.Marshal(other)
	if ed25519.Verify(pub, append([]byte(engine.HeadDomain), b...), sig) {
		t.Fatal("signature covers a different seq")
	}
	// The grant key is not the anchor key.
	if ed25519.PublicKey(pub).Equal(f.srv.Pub) {
		t.Fatal("anchor key is the grant key")
	}
	if err := os.WriteFile(filepath.Join(f.dir, "audit", "000001.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	rec := call(f.srv, http.MethodGet, "/v1/audit/head", read, "")
	shell(t, rec, http.StatusInternalServerError)
	if errOf(t, rec) != codes.AuditTruncated {
		t.Fatal(rec.Body.String())
	}
}

func TestWitnessRoute(t *testing.T) {
	f := newFix(t)
	read := f.sign(t, grant.Grant{Purpose: grant.PurposeRead, Entitlements: grant.Fill(grant.PurposeRead), LeaseID: "lease-read1"})
	if err := f.srv.Eng.Store.AppendAudit("a", "", "config.set", nil, f.now); err != nil {
		t.Fatal(err)
	}
	sh, _ := headOf(t, f, read)
	body := `{"seq":` + itoa(sh.Head.Seq) + `,"hash":"` + sh.Head.Hash + `","witness":"cp-1","time":"2026-11-22T12:00:00Z"}`
	wit := func(lease string) string {
		return f.sign(t, grant.Grant{Purpose: grant.PurposeConfig, Entitlements: []string{grant.EntAudit, grant.EntWitness}, LeaseID: lease})
	}

	// security:read does not carry the entitlement; config without it is forbidden.
	noWit := f.sign(t, grant.Grant{Purpose: grant.PurposeConfig, Entitlements: []string{grant.EntAudit}, LeaseID: "lease-nowit1"})
	rec := call(f.srv, http.MethodPost, "/v1/audit/witness", noWit, body)
	shell(t, rec, http.StatusForbidden)
	if errOf(t, rec) != codes.Forbidden {
		t.Fatal(rec.Body.String())
	}
	rec = call(f.srv, http.MethodPost, "/v1/audit/witness", read, body)
	shell(t, rec, http.StatusForbidden)

	rec = call(f.srv, http.MethodPost, "/v1/audit/witness", wit("lease-wit001"), strings.Replace(body, "{", `{"x":1,`, 1))
	shell(t, rec, http.StatusBadRequest)
	if errOf(t, rec) != codes.BadPath {
		t.Fatal(rec.Body.String())
	}

	doc := wit("lease-wit002")
	shell(t, call(f.srv, http.MethodPost, "/v1/audit/witness", doc, body), http.StatusOK)
	rec = call(f.srv, http.MethodPost, "/v1/audit/witness", doc, body)
	shell(t, rec, http.StatusForbidden)
	if errOf(t, rec) != codes.GrantSpent {
		t.Fatal(rec.Body.String())
	}
	rows, err := f.srv.Eng.Audit(10)
	if err != nil || rows[len(rows)-1].Action != "audit.witness" || rows[len(rows)-1].LeaseID != "lease-wit002" {
		t.Fatalf("%+v %v", rows, err)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "witness.jsonl")); err != nil {
		t.Fatal(err)
	}

	// A witness the chain does not hold is the evidence of a rewrite.
	bad := strings.Replace(body, sh.Head.Hash, strings.Repeat("e", 64), 1)
	rec = call(f.srv, http.MethodPost, "/v1/audit/witness", wit("lease-wit003"), bad)
	shell(t, rec, http.StatusInternalServerError)
	if errOf(t, rec) != codes.AuditTruncated {
		t.Fatal(rec.Body.String())
	}
	rec = call(f.srv, http.MethodGet, "/v1/audit", read, "")
	shell(t, rec, http.StatusInternalServerError)
	if errOf(t, rec) != codes.AuditTruncated {
		t.Fatal(rec.Body.String())
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
