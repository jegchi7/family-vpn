package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func standTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func standTestWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func standTestCertificate(t *testing.T, root string, certificate x509.Certificate) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &certificate, &certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	certPath, keyPath := filepath.Join(root, "local-cert.pem"), filepath.Join(root, "local-key.pem")
	standTestWrite(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	defer clear(encoded)
	standTestWrite(t, keyPath, encoded)
	return certPath, keyPath
}

func TestCheckStandTLSCertificateBoundaries(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	template := func() x509.Certificate {
		return x509.Certificate{
			NotBefore:   now.Add(-time.Hour),
			NotAfter:    now.Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*x509.Certificate)
		host   string
		ok     bool
	}{
		{name: "valid loopback", host: "127.0.0.1", ok: true},
		{name: "valid IPv6 loopback", host: "::1", ok: true},
		{name: "valid at not-before", host: "127.0.0.1", change: func(cert *x509.Certificate) { cert.NotBefore = now }, ok: true},
		{name: "wrong IP SAN", host: "127.0.0.2"},
		{name: "DNS SAN is not IP SAN", host: "127.0.0.1", change: func(cert *x509.Certificate) { cert.IPAddresses = nil; cert.DNSNames = []string{"127.0.0.1"} }},
		{name: "expired", host: "127.0.0.1", change: func(cert *x509.Certificate) { cert.NotAfter = now.Add(-time.Second) }},
		{name: "expired at not-after", host: "127.0.0.1", change: func(cert *x509.Certificate) { cert.NotAfter = now }},
		{name: "future", host: "127.0.0.1", change: func(cert *x509.Certificate) { cert.NotBefore = now.Add(time.Second) }},
		{name: "client-only EKU", host: "127.0.0.1", change: func(cert *x509.Certificate) { cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := template()
			if tc.change != nil {
				tc.change(&cert)
			}
			certPath, keyPath := standTestCertificate(t, standTestRoot(t), cert)
			err := CheckStandTLS(certPath, keyPath, tc.host, now)
			if tc.ok && err != nil {
				t.Fatal("valid stand certificate rejected", err)
			}
			if !tc.ok && !errors.Is(err, ErrStandTLS) {
				t.Fatal("invalid stand certificate did not fail closed", err)
			}
		})
	}
	t.Run("mismatched private key", func(t *testing.T) {
		certPath, _ := standTestCertificate(t, standTestRoot(t), template())
		_, otherKeyPath := standTestCertificate(t, standTestRoot(t), template())
		if err := CheckStandTLS(certPath, otherKeyPath, "127.0.0.1", now); !errors.Is(err, ErrStandTLS) {
			t.Fatal("mismatched certificate and key accepted", err)
		}
	})
	for _, missing := range []string{"certificate", "key"} {
		t.Run("missing "+missing, func(t *testing.T) {
			root := standTestRoot(t)
			certPath, keyPath := standTestCertificate(t, root, template())
			if missing == "certificate" {
				certPath = filepath.Join(root, "missing-cert.pem")
			} else {
				keyPath = filepath.Join(root, "missing-key.pem")
			}
			if err := CheckStandTLS(certPath, keyPath, "127.0.0.1", now); !errors.Is(err, ErrStandTLS) {
				t.Fatal("missing TLS file accepted", err)
			}
		})
	}
	for _, aliased := range []string{"certificate", "key"} {
		t.Run("parent alias for "+aliased, func(t *testing.T) {
			root := standTestRoot(t)
			certPath, keyPath := standTestCertificate(t, root, template())
			alias := filepath.Join(standTestRoot(t), "linked-tls")
			standTestLink(t, root, alias, true)
			if aliased == "certificate" {
				certPath = filepath.Join(alias, filepath.Base(certPath))
			} else {
				keyPath = filepath.Join(alias, filepath.Base(keyPath))
			}
			if err := CheckStandTLS(certPath, keyPath, "127.0.0.1", now); !errors.Is(err, ErrStandTLS) {
				t.Fatal("aliased TLS parent accepted", err)
			}
		})
	}
	t.Run("POSIX key readable by others", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("POSIX mode check does not verify Windows ACL")
		}
		certPath, keyPath := standTestCertificate(t, standTestRoot(t), template())
		if err := os.Chmod(keyPath, 0644); err != nil {
			t.Fatal(err)
		}
		if err := CheckStandTLS(certPath, keyPath, "127.0.0.1", now); !errors.Is(err, ErrStandTLS) {
			t.Fatal("TLS key readable by others accepted", err)
		}
	})
}

func standTestAssets(t *testing.T) string {
	t.Helper()
	root := standTestRoot(t)
	standTestWrite(t, filepath.Join(root, "index.html"), []byte(`<html><head><link href="/assets/app.css" rel="stylesheet"></head><body><div id="app"></div><script type="module" src="/assets/app.js"></script></body></html>`))
	standTestWrite(t, filepath.Join(root, "assets", "app.css"), []byte("body{margin:0}"))
	standTestWrite(t, filepath.Join(root, "assets", "app.js"), []byte("console.log('stand');"))
	return root
}

func TestCheckStandAssetsFileBoundaries(t *testing.T) {
	t.Parallel()
	t.Run("valid shell does not mutate assets", func(t *testing.T) {
		root := standTestAssets(t)
		paths := []string{"index.html", "assets/app.css", "assets/app.js"}
		before := make(map[string][]byte)
		for _, path := range paths {
			var err error
			before[path], err = os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := CheckStandAssets(root); err != nil {
			t.Fatal("valid assets rejected", err)
		}
		for _, path := range paths {
			after, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
			if err != nil || !bytes.Equal(after, before[path]) {
				t.Fatal("asset read changed file")
			}
		}
	})
	for _, missing := range []string{"index.html", "assets/app.css", "assets/app.js"} {
		t.Run("missing "+missing, func(t *testing.T) {
			root := standTestAssets(t)
			if err := os.Remove(filepath.Join(root, filepath.FromSlash(missing))); err != nil {
				t.Fatal(err)
			}
			if err := CheckStandAssets(root); !errors.Is(err, ErrStandAssets) {
				t.Fatal("missing shell/referenced asset accepted", err)
			}
		})
	}
	for _, ref := range []string{
		"/assets/../private.js",
		"/assets/sub/../../private.js",
		"/assets/%2e%2e/private.js",
		`/assets/..\private.js`,
		"/assets/app.js?query=private",
		"/assets/app.js#fragment",
	} {
		t.Run("reject unsafe reference "+ref, func(t *testing.T) {
			root := standTestAssets(t)
			standTestWrite(t, filepath.Join(root, "private.js"), []byte("synthetic-private-data"))
			standTestWrite(t, filepath.Join(root, "index.html"), []byte(`<html><div id="app"></div><script type="module" src="/assets/app.js"></script><link href="`+ref+`"></html>`))
			if err := CheckStandAssets(root); !errors.Is(err, ErrStandAssets) {
				t.Fatal("unsafe referenced path accepted", err)
			}
		})
	}
	for _, tc := range []struct{ name, html string }{
		{name: "empty index", html: ""},
		{name: "not an HTML shell", html: `<div id="app"></div><script type="module" src="/assets/app.js"></script>`},
		{name: "no referenced assets", html: `<html></html>`},
		{name: "missing app mount", html: `<html><script type="module" src="/assets/app.js"></script></html>`},
		{name: "missing module script", html: `<html><div id="app"></div><script src="/assets/app.js"></script></html>`},
		{name: "CSS-only shell", html: `<html><div id="app"></div><link href="/assets/app.css"></html>`},
		{name: "too many referenced assets", html: `<html><div id="app"></div>` + strings.Repeat(`<script type="module" src="/assets/app.js"></script>`, 129) + `</html>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := standTestAssets(t)
			standTestWrite(t, filepath.Join(root, "index.html"), []byte(tc.html))
			if err := CheckStandAssets(root); !errors.Is(err, ErrStandAssets) {
				t.Fatal("invalid built shell accepted", err)
			}
		})
	}
	for _, private := range []string{"private.key", "tls.pem", "state.db", "tokens.json", ".env", "assets/.hidden.js", "assets/app.js.map"} {
		t.Run("unreferenced private asset "+private, func(t *testing.T) {
			root := standTestAssets(t)
			standTestWrite(t, filepath.Join(root, filepath.FromSlash(private)), []byte("synthetic-excluded-file"))
			if err := CheckStandAssets(root); !errors.Is(err, ErrStandAssets) {
				t.Fatal("unreferenced private/unexpected asset accepted", err)
			}
		})
	}
	t.Run("directory instead of referenced file", func(t *testing.T) {
		root := standTestAssets(t)
		path := filepath.Join(root, "assets", "app.js")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := CheckStandAssets(root); !errors.Is(err, ErrStandAssets) {
			t.Fatal("directory used as referenced asset accepted", err)
		}
	})
}

func standTestLink(t *testing.T, target, link string, directory bool) {
	t.Helper()
	err := os.Symlink(target, link)
	if err == nil {
		return
	}
	if runtime.GOOS == "windows" && directory {
		// A junction exercises parent aliases on Windows without granting symlink privileges.
		if e := exec.Command("cmd.exe", "/c", "mklink", "/J", link, target).Run(); e == nil {
			return
		}
	}
	t.Skipf("filesystem links unavailable on this test host: %v", err)
}

func TestCheckStandAssetsRejectsFilesystemAliases(t *testing.T) {
	t.Parallel()
	t.Run("frontend root parent alias", func(t *testing.T) {
		root := standTestAssets(t)
		parent := standTestRoot(t)
		alias := filepath.Join(parent, "linked-root")
		standTestLink(t, root, alias, true)
		if err := CheckStandAssets(alias); !errors.Is(err, ErrStandAssets) {
			t.Fatal("aliased frontend root accepted", err)
		}
	})
	t.Run("frontend root ancestor alias", func(t *testing.T) {
		root := standTestAssets(t)
		parent := standTestRoot(t)
		alias := filepath.Join(parent, "linked-parent")
		standTestLink(t, filepath.Dir(root), alias, true)
		if err := CheckStandAssets(filepath.Join(alias, filepath.Base(root))); !errors.Is(err, ErrStandAssets) {
			t.Fatal("aliased frontend ancestor accepted", err)
		}
	})
	t.Run("referenced asset parent alias", func(t *testing.T) {
		root := standTestAssets(t)
		target := standTestRoot(t)
		standTestWrite(t, filepath.Join(target, "app.js"), []byte("synthetic-linked-asset"))
		alias := filepath.Join(root, "assets", "linked")
		standTestLink(t, target, alias, true)
		stat, err := os.Lstat(alias)
		if err != nil {
			t.Fatal(err)
		}
		if stat.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			t.Fatal("parent alias fixture is not a filesystem link")
		}
		standTestWrite(t, filepath.Join(root, "index.html"), []byte(`<html><div id="app"></div><script type="module" src="/assets/linked/app.js"></script></html>`))
		if err := CheckStandAssets(root); !errors.Is(err, ErrStandAssets) {
			t.Fatal("aliased asset parent accepted", err)
		}
	})
	for _, leaf := range []string{"index.html", "assets/app.js"} {
		t.Run("leaf link "+leaf, func(t *testing.T) {
			root := standTestAssets(t)
			target := filepath.Join(standTestRoot(t), "linked-content")
			standTestWrite(t, target, []byte(`<html><div id="app"></div><script type="module" src="/assets/app.js"></script></html>`))
			path := filepath.Join(root, filepath.FromSlash(leaf))
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			standTestLink(t, target, path, false)
			if err := CheckStandAssets(root); !errors.Is(err, ErrStandAssets) {
				t.Fatal("linked leaf asset accepted", err)
			}
		})
	}
	t.Run("unreferenced directory alias", func(t *testing.T) {
		root := standTestAssets(t)
		target := standTestRoot(t)
		standTestWrite(t, filepath.Join(target, "unreferenced.js"), []byte("synthetic-linked-asset"))
		standTestLink(t, target, filepath.Join(root, "assets", "unreferenced"), true)
		if err := CheckStandAssets(root); !errors.Is(err, ErrStandAssets) {
			t.Fatal("unreferenced aliased directory accepted", err)
		}
	})
	t.Run("unreferenced leaf link", func(t *testing.T) {
		root := standTestAssets(t)
		target := filepath.Join(standTestRoot(t), "unreferenced.js")
		standTestWrite(t, target, []byte("synthetic-linked-asset"))
		standTestLink(t, target, filepath.Join(root, "assets", "unreferenced.js"), false)
		if err := CheckStandAssets(root); !errors.Is(err, ErrStandAssets) {
			t.Fatal("unreferenced linked file accepted", err)
		}
	})
}
