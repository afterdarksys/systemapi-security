package grant

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"

	"github.com/afterdarksys/systemapi-security/internal/codes"
	"golang.org/x/sys/unix"
)

// Generate returns a 32-byte seed and its public key from the CSPRNG.
func Generate() (seed []byte, pub ed25519.PublicKey, err error) {
	// rand.Reader is crypto/rand. A nil reader is not a CSPRNG.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, codes.E(codes.Failed)
	}
	s := priv.Seed()
	out := make([]byte, len(s))
	copy(out, s)
	pk, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pk) != ed25519.PublicKeySize {
		return nil, nil, codes.E(codes.Failed)
	}
	return out, pk, nil
}

// PubHex encodes a public key as lowercase hex.
func PubHex(pub ed25519.PublicKey) string { return hex.EncodeToString(pub) }

// WriteSeed creates path with the 32-byte seed. An existing path is left in place.
func WriteSeed(path string, seed []byte) error {
	if len(seed) != ed25519.SeedSize {
		return codes.E(codes.Failed)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return codes.E(codes.Failed)
	}
	_, werr := f.Write(seed)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		os.Remove(path)
		return codes.E(codes.Failed)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		os.Remove(path)
		return codes.E(codes.Failed)
	}
	return nil
}

// LoadSeed reads a 32-byte seed. Group/world bits are seed_perms.
// A symlink is bad_pub and is not followed.
func LoadSeed(path string) ([]byte, error) {
	b, fi, err := readKey(path)
	if err != nil {
		return nil, codes.E(codes.BadPub)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, codes.E(codes.SeedPerms)
	}
	seed, err := parseMaterial(b)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, codes.E(codes.BadPub)
	}
	return seed, nil
}

// LoadPub reads a 32-byte public key. A world-readable file is accepted.
// A symlink is bad_pub and is not followed.
func LoadPub(path string) (ed25519.PublicKey, error) {
	b, _, err := readKey(path)
	if err != nil {
		return nil, codes.E(codes.BadPub)
	}
	raw, err := parseMaterial(b)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, codes.E(codes.BadPub)
	}
	return ed25519.PublicKey(raw), nil
}

func readKey(path string) ([]byte, os.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		return nil, fi, os.ErrInvalid
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fi, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 129))
	if err != nil {
		return nil, fi, err
	}
	if len(b) > 128 {
		return nil, fi, os.ErrInvalid
	}
	return b, fi, nil
}

// parseMaterial accepts exactly 32 raw bytes, or 64 hex chars, or 64 hex chars
// plus one trailing newline. A 64-byte private key is rejected.
func parseMaterial(b []byte) ([]byte, error) {
	if len(b) == ed25519.SeedSize {
		return append([]byte(nil), b...), nil
	}
	s := b
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	if len(s) != 64 || !hexOnly(s) {
		return nil, os.ErrInvalid
	}
	out, err := hex.DecodeString(string(s))
	if err != nil || len(out) != ed25519.SeedSize {
		return nil, os.ErrInvalid
	}
	return out, nil
}

func hexOnly(b []byte) bool {
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
