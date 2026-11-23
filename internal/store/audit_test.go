package store

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/systemapi-security/internal/audit"
	"github.com/afterdarksys/systemapi-security/internal/codes"
)

func TestOpenRefusesLegacyChain(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, audit.LegacyName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, nil); codes.Code(err) != codes.AuditLayout {
		t.Fatalf("got %v", err)
	}
}

func TestRetentionFromConfig(t *testing.T) {
	defer func(o audit.Options) { auditOptions = o }(auditOptions)
	auditOptions = audit.Options{SegRows: 2}
	dir := t.TempDir()
	s, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := s.Config()
	c.AuditKeepSegments = 1
	if err := s.PutConfig(c); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if err := s.AppendAudit("a", "", "config.set", nil, time.Unix(int64(i), 0)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, audit.SegDir, "000001.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("oldest segment kept: %v", err)
	}
	if _, err := s.AuditVerify(); err != nil {
		t.Fatal(err)
	}
	if v, err := s.View(); err != nil || v.AuditKeep != 1 {
		t.Fatalf("view %+v %v", v, err)
	}
	for _, n := range []int{-1, keepMax + 1} {
		c.AuditKeepSegments = n
		if err := s.PutConfig(c); codes.Code(err) != codes.BadPath {
			t.Fatalf("keep %d: %v", n, err)
		}
	}
}

func TestAnchorKey(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, anchorKey)
	st, err := os.Lstat(path)
	if err != nil || st.Mode().Perm() != 0o600 || st.Size() != ed25519.SeedSize {
		t.Fatalf("key file %v %v", st, err)
	}
	pub := s.AnchorPub()
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, []byte("m"), s.SignAnchor([]byte("m"))) {
		t.Fatal("sign")
	}
	// A second start loads the same key; it is not regenerated.
	again, err := loadAnchorKey(dir)
	if err != nil || !again.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatalf("reload %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAnchorKey(dir); codes.Code(err) != codes.SeedPerms {
		t.Fatalf("loose mode: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAnchorKey(dir); codes.Code(err) != codes.Failed {
		t.Fatalf("short key: %v", err)
	}
	other := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(other, make([]byte, ed25519.SeedSize), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAnchorKey(dir); codes.Code(err) != codes.Failed {
		t.Fatalf("symlink: %v", err)
	}
}
