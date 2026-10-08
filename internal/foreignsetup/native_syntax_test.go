package foreignsetup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// This optional regression executes only the independently SHA-pinned Windows
// parser binaries in ignored build/native-check-tools. It is not the production
// native observer, Ubuntu execution, a transport test or client acceptance.
// Source releases: XTLS/Xray-core v26.3.27 and SagerNet/sing-box v1.14.2.
func TestOfficialGeneratedSyntax(t *testing.T) {
	if os.Getenv("FVPN_VERIFY_FOREIGN_SYNTAX") != "1" {
		t.Skip("explicit generated-template parser verification not requested")
	}
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		t.Fatal("this optional parser regression requires pinned Windows amd64 tools")
	}
	xray := syntaxTool(t, "xray.exe", "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1")
	sing := syntaxTool(t, "sing-box.exe", "7bbef1dea9189ee12799ae834ea4b4658355da25c47a21ad8804904c0ccd9410")
	for _, i := range []Inputs{inputs(), {"[2606:4700:4700::1111]:443", "2001:4860:4860::8888", "[2606:4700:4700::1001]:443", "www.cloudflare.com"}} {
		b, e := Generate(i)
		if e != nil {
			t.Fatal("private template generation failed")
		}
		func() {
			defer b.Clear()
			dir := t.TempDir()
			xpath := filepath.Join(dir, "xray.json")
			spath := filepath.Join(dir, "sing-box.json")
			writeSyntaxFile(t, xpath, b.Xray)
			wrapped := syntaxHop(t, b.RUHop)
			defer clear(wrapped)
			writeSyntaxFile(t, spath, wrapped)
			syntaxCommand(t, xray, dir, true, "run", "-test", "-format", "json", "-config", xpath)
			syntaxCommand(t, sing, dir, true, "check", "-c", spath)

			// A zero/no-op executable cannot pass both the positive and rejected
			// configuration cases. Errors and core output never leave this test.
			var x xrayConfig
			if decode(b.Xray, &x) != nil {
				t.Fatal("private template decode failed")
			}
			x.Inbounds[0].Stream.Reality.PrivateKey = "invalid"
			invalid, _ := marshal(x)
			defer clear(invalid)
			writeSyntaxFile(t, xpath, invalid)
			syntaxCommand(t, xray, dir, false, "run", "-test", "-format", "json", "-config", xpath)

			var h ruHop
			if decode(b.RUHop, &h) != nil {
				t.Fatal("private hop decode failed")
			}
			h.TLS.Reality.PublicKey = "invalid"
			invalidHop, _ := marshal(h)
			defer clear(invalidHop)
			invalidWrapped := syntaxHop(t, invalidHop)
			defer clear(invalidWrapped)
			writeSyntaxFile(t, spath, invalidWrapped)
			syntaxCommand(t, sing, dir, false, "check", "-c", spath)
		}()
	}
}

func TestOfficialNamespaceIPv4Syntax(t *testing.T) {
	if os.Getenv("FVPN_VERIFY_FOREIGN_SYNTAX") != "1" {
		t.Skip("explicit generated-template parser verification not requested")
	}
	if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
		t.Fatal("this optional parser regression requires pinned Windows amd64 tools")
	}
	xray := syntaxTool(t, "xray.exe", "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1")
	b := generated(t)
	adapted, e := NamespaceIPv4Config(b.Xray, b.RUHop)
	if e != nil {
		t.Fatal("private IPv4 template generation failed")
	}
	defer clear(adapted)
	dir := t.TempDir()
	xpath := filepath.Join(dir, "xray.json")
	writeSyntaxFile(t, xpath, adapted)
	syntaxCommand(t, xray, dir, true, "run", "-test", "-format", "json", "-config", xpath)
	var x xrayConfig
	if decode(adapted, &x) != nil {
		t.Fatal("private IPv4 template decode failed")
	}
	x.Inbounds[0].Stream.Reality.PrivateKey = "invalid"
	invalid, _ := marshal(x)
	defer clear(invalid)
	writeSyntaxFile(t, xpath, invalid)
	syntaxCommand(t, xray, dir, false, "run", "-test", "-format", "json", "-config", xpath)
}

func syntaxTool(t *testing.T, name, pin string) string {
	t.Helper()
	p, e := filepath.Abs(filepath.Join("..", "..", "build", "native-check-tools", name))
	if e != nil {
		t.Fatal("pinned parser path unavailable")
	}
	st, e := os.Lstat(p)
	if e != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 128<<20 {
		t.Fatal("pinned parser file unavailable")
	}
	f, e := os.Open(p)
	if e != nil {
		t.Fatal("pinned parser file unavailable")
	}
	defer f.Close()
	h := sha256.New()
	if _, e := io.Copy(h, io.LimitReader(f, (128<<20)+1)); e != nil || hex.EncodeToString(h.Sum(nil)) != pin {
		t.Fatal("pinned parser integrity mismatch")
	}
	return p
}

func writeSyntaxFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("private parser input unavailable")
	}
}

func syntaxHop(t *testing.T, fragment []byte) []byte {
	t.Helper()
	// This closed harness supplies no listener, TUN, DNS rules, selector or
	// DIRECT outbound. It is used only by `check`; it is not a RU runtime config.
	config := struct {
		Log struct {
			Disabled bool `json:"disabled"`
		} `json:"log"`
		Inbounds  []json.RawMessage `json:"inbounds"`
		Outbounds []json.RawMessage `json:"outbounds"`
		Route     struct {
			Final string `json:"final"`
		} `json:"route"`
	}{Inbounds: []json.RawMessage{}, Outbounds: []json.RawMessage{fragment}}
	config.Log.Disabled = true
	config.Route.Final = "foreign-primary"
	b, e := json.Marshal(config)
	if e != nil {
		t.Fatal("private parser harness generation failed")
	}
	return b
}

func syntaxCommand(t *testing.T, tool, dir string, valid bool, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Dir = dir
	cmd.Env = []string{"SystemRoot=" + os.Getenv("SystemRoot"), "WINDIR=" + os.Getenv("WINDIR")}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.WaitDelay = 200 * time.Millisecond
	e := cmd.Run()
	if ctx.Err() != nil || (e == nil) != valid {
		t.Fatal("pinned core parser regression failed; private output suppressed")
	}
}
