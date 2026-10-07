package clientconfig

import (
	"familyvpn.local/platform/internal/profilevault"
	"io"
	"os"
	"path/filepath"
)

func readBounded(r io.Reader) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, profilevault.MaxSize+1))
	if e != nil || len(b) == 0 || len(b) > profilevault.MaxSize {
		clear(b)
		return nil, ErrSource
	}
	return b, nil
}

// ReadInput permits stdin or a private regular file. No path/content is included in errors.
func ReadInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return readBounded(stdin)
	}
	abs, e := filepath.Abs(path)
	if e != nil {
		return nil, ErrSource
	}
	parent := filepath.Dir(abs)
	real, e := filepath.EvalSymlinks(parent)
	if e != nil || real != parent {
		return nil, ErrSource
	}
	dir, e := os.Stat(parent)
	if e != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 || !owned(dir) {
		return nil, ErrSource
	}
	st, e := os.Lstat(abs)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !owned(st) || st.Size() < 1 || st.Size() > profilevault.MaxSize {
		return nil, ErrSource
	}
	f, e := os.Open(abs)
	if e != nil {
		return nil, ErrSource
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(st, actual) || !actual.Mode().IsRegular() || actual.Mode().Perm()&0077 != 0 || !owned(actual) {
		return nil, ErrSource
	}
	return readBounded(f)
}
