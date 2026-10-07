package profilevault

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type keyFile struct {
	Version int    `json:"version"`
	Purpose string `json:"purpose"`
	Key     string `json:"key"`
}

// Reject aliases even for a not-yet-created path, resolving the nearest existing ancestor.
func canonicalPath(path string) (string, error) {
	abs, e := filepath.Abs(path)
	if e != nil {
		return "", ErrKey
	}
	ancestor := abs
	for {
		_, e = os.Lstat(ancestor)
		if e == nil {
			break
		}
		if !os.IsNotExist(e) {
			return "", ErrKey
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", ErrKey
		}
		ancestor = parent
	}
	real, e := filepath.EvalSymlinks(ancestor)
	if e != nil || real != ancestor {
		return "", ErrKey
	}
	return abs, nil
}

// CheckLocation prevents a DB-state backup from inadvertently including its encryption key.
func CheckLocation(stateRoot, key string) error {
	root, e := canonicalPath(stateRoot)
	if e != nil {
		return e
	}
	p, e := canonicalPath(key)
	if e != nil {
		return e
	}
	rel, e := filepath.Rel(root, p)
	if e != nil || !(rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return ErrKey
	}
	return nil
}
func keyPath(path string) (string, error) {
	p, e := canonicalPath(path)
	if e != nil {
		return "", e
	}
	st, e := os.Stat(filepath.Dir(p))
	if e != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 || !owned(st) {
		return "", ErrKey
	}
	return p, nil
}

// CreateKey is exclusive. Purpose-tagged files cannot be mistaken for an admin TOTP key.
func CreateKey(path string) error {
	p, e := keyPath(path)
	if e != nil {
		return e
	}
	f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
	key := make([]byte, 32)
	defer clear(key)
	if _, e = rand.Read(key); e != nil {
		return ErrKey
	}
	data, e := json.Marshal(keyFile{1, purpose, base64.StdEncoding.EncodeToString(key)})
	if e != nil {
		return ErrKey
	}
	defer clear(data)
	if _, e = f.Write(data); e != nil {
		return ErrKey
	}
	if e = f.Sync(); e != nil {
		return ErrKey
	}
	if e = f.Close(); e != nil {
		return ErrKey
	}
	// Persist the directory entry as well as file contents on supported Unix hosts.
	d, e := os.Open(filepath.Dir(p))
	if e != nil {
		return ErrKey
	}
	defer d.Close()
	if e = d.Sync(); e != nil {
		return ErrKey
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
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !owned(st) || st.Size() > 1024 {
		return nil, ErrKey
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, ErrKey
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(st, actual) || !actual.Mode().IsRegular() || actual.Mode().Perm()&0077 != 0 || !owned(actual) {
		return nil, ErrKey
	}
	data, e := io.ReadAll(io.LimitReader(f, 1025))
	defer clear(data)
	if e != nil || len(data) > 1024 {
		return nil, ErrKey
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var in keyFile
	if e = decoder.Decode(&in); e != nil || in.Version != 1 || in.Purpose != purpose {
		return nil, ErrKey
	}
	if e = decoder.Decode(new(any)); e != io.EOF {
		return nil, ErrKey
	}
	key, e := base64.StdEncoding.Strict().DecodeString(in.Key)
	defer clear(key)
	if e != nil {
		return nil, ErrKey
	}
	return New(key)
}
