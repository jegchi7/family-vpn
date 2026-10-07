// Package adminauth implements the separate local administrator MFA boundary.
package adminauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

var ErrKey = errors.New("admin master key unavailable or invalid")

type Vault struct {
	aead cipher.AEAD
	ID   string
}

func NewVault(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, ErrKey
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, ErrKey
	}
	a, e := cipher.NewGCMWithRandomNonce(b)
	if e != nil {
		return nil, e
	}
	id := sha256.Sum256(key)
	return &Vault{a, hex.EncodeToString(id[:])}, nil
}
func (v *Vault) aad(id string) []byte {
	return []byte("family-vpn/admin-totp/v1\x00" + v.ID + "\x00" + id)
}
func (v *Vault) Seal(id, secret string) []byte {
	return v.aead.Seal(nil, nil, []byte(secret), v.aad(id))
}
func (v *Vault) Open(id, keyID string, data []byte) (string, error) {
	if keyID != v.ID {
		return "", ErrKey
	}
	b, e := v.aead.Open(nil, nil, data, v.aad(id))
	if e != nil {
		return "", ErrKey
	}
	defer clear(b)
	return string(b), nil
}

// Keys are never generated on runtime startup. Explicit operator creation is exclusive.
// Windows ACL validation is not implemented: fail closed instead of accepting permissive keys.
func keyPath(path string) (string, error) {
	if runtime.GOOS == "windows" {
		return "", ErrKey
	}
	abs, e := filepath.Abs(path)
	if e != nil {
		return "", ErrKey
	}
	parent := filepath.Dir(abs)
	resolved, e := filepath.EvalSymlinks(parent)
	if e != nil || resolved != parent {
		return "", ErrKey
	}
	st, e := os.Stat(parent)
	if e != nil || st.Mode().Perm()&0077 != 0 || !owned(st) {
		return "", ErrKey
	}
	return abs, nil
}
func CreateKey(path string) error {
	p, e := keyPath(path)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return ErrKey
	}
	good := false
	defer func() {
		f.Close()
		if !good {
			os.Remove(p)
		}
	}()
	b := make([]byte, 32)
	defer clear(b)
	if _, e = rand.Read(b); e != nil {
		return e
	}
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	good = true
	return nil
}
func LoadKey(path string) (*Vault, error) {
	p, e := keyPath(path)
	if e != nil {
		return nil, e
	}
	st, e := os.Lstat(p)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !owned(st) || st.Size() != 32 {
		return nil, ErrKey
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, ErrKey
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(st, actual) || actual.Mode().Perm()&0077 != 0 || !owned(actual) {
		return nil, ErrKey
	}
	b, e := io.ReadAll(io.LimitReader(f, 33))
	defer clear(b)
	if e != nil {
		return nil, ErrKey
	}
	return NewVault(b)
}
