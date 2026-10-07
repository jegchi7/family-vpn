package app

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var ErrStandTLS = errors.New("stand TLS certificate/key unavailable, invalid or expired")
var ErrStandAssets = errors.New("stand frontend assets unavailable or invalid")

// Certificate checks are local diagnostics, not system trust or VPN evidence.
func CheckStandTLS(certPath, keyPath, host string, now time.Time) error {
	st, e := os.Lstat(keyPath)
	if e != nil || (runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0) {
		return ErrStandTLS
	}
	cert, e := readStandFile(certPath, 64<<10)
	if e != nil {
		return ErrStandTLS
	}
	key, e := readStandFile(keyPath, 64<<10)
	if e != nil {
		return ErrStandTLS
	}
	defer clear(key)
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil || len(pair.Certificate) == 0 {
		return ErrStandTLS
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.VerifyHostname(host) != nil {
		return ErrStandTLS
	}
	server := len(leaf.ExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		server = server || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
	}
	if !server {
		return ErrStandTLS
	}
	return nil
}

func readStandFile(path string, limit int64) ([]byte, error) {
	if checkedStandDirectory(filepath.Dir(path)) != nil {
		return nil, ErrStandAssets
	}
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > limit {
		return nil, ErrStandAssets
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrStandAssets
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(st, actual) || !actual.Mode().IsRegular() {
		return nil, ErrStandAssets
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || len(b) == 0 || int64(len(b)) > limit {
		clear(b)
		return nil, ErrStandAssets
	}
	return b, nil
}

var assetRef = regexp.MustCompile(`(?:src|href)=["'](/assets/[^"']+)["']`)
var moduleRef = regexp.MustCompile(`<script\b[^>]*type=["']module["'][^>]*src=["'](/assets/[^"']+\.js)["'][^>]*>`)
var appMount = regexp.MustCompile(`<div\b[^>]*id=["']app["'][^>]*>`)
var assetExtension = regexp.MustCompile(`(?i)\.(?:html|js|css|svg|png|jpe?g|gif|webp|avif|ico|woff2?|ttf|otf|wasm)$`)

// Lstat every ancestor as well as resolving it: on Windows EvalSymlinks alone
// may preserve a junction path rather than reporting its target.
func checkedStandDirectory(dir string) error {
	abs, e := filepath.Abs(dir)
	if e != nil {
		return ErrStandAssets
	}
	for current := abs; ; current = filepath.Dir(current) {
		st, e := os.Lstat(current)
		if e != nil || !st.IsDir() || st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return ErrStandAssets
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	real, e := filepath.EvalSymlinks(abs)
	if e != nil || real != abs {
		return ErrStandAssets
	}
	return nil
}

// Only checks the built local shell and its referenced assets. No URL fetches,
// scripts, network/core checks or mutation of the release are performed.
func CheckStandAssets(dir string) error {
	abs, e := filepath.Abs(dir)
	if e != nil {
		return ErrStandAssets
	}
	if checkedStandDirectory(abs) != nil {
		return ErrStandAssets
	}
	// HTTP serves the full tree, so validate also files not referenced by index.
	count, total := 0, int64(0)
	if e = filepath.WalkDir(abs, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return ErrStandAssets
		}
		if path != abs && (strings.HasPrefix(entry.Name(), ".") || strings.ContainsAny(entry.Name(), "\\?#%")) {
			return ErrStandAssets
		}
		if entry.IsDir() {
			return checkedStandDirectory(path)
		}
		st, err := entry.Info()
		if err != nil || !st.Mode().IsRegular() || !assetExtension.MatchString(entry.Name()) {
			return ErrStandAssets
		}
		count++
		total += st.Size()
		if count > 512 || total > 64<<20 {
			return ErrStandAssets
		}
		_, err = readStandFile(path, 8<<20)
		return err
	}); e != nil {
		return ErrStandAssets
	}
	index, e := readStandFile(filepath.Join(abs, "index.html"), 1<<20)
	if e != nil {
		return ErrStandAssets
	}
	refs := assetRef.FindAllSubmatch(index, -1)
	if len(refs) == 0 || len(refs) > 128 || !bytes.Contains(index, []byte("<html")) || !appMount.Match(index) || !moduleRef.Match(index) {
		return ErrStandAssets
	}
	for _, ref := range refs {
		p := string(ref[1])
		if strings.ContainsAny(p, "\\?#%") || strings.Contains(p, "..") {
			return ErrStandAssets
		}
		asset := filepath.Join(abs, filepath.FromSlash(strings.TrimPrefix(p, "/")))
		parent, e := filepath.EvalSymlinks(filepath.Dir(asset))
		if e != nil || parent != filepath.Dir(asset) {
			return ErrStandAssets
		}
		if _, e = readStandFile(asset, 8<<20); e != nil {
			return ErrStandAssets
		}
	}
	return nil
}
