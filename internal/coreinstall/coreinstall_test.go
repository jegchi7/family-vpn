package coreinstall

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func syntheticELF(arch string) []byte {
	b := make([]byte, 160)
	copy(b, []byte{127, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(b[16:], 2)
	machine := uint16(62)
	if arch == "arm64" {
		machine = 183
	}
	binary.LittleEndian.PutUint16(b[18:], machine)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[32:], 64)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[56:], 1)
	binary.LittleEndian.PutUint32(b[64:], 1)
	binary.LittleEndian.PutUint32(b[68:], 5)
	binary.LittleEndian.PutUint64(b[96:], uint64(len(b)))
	binary.LittleEndian.PutUint64(b[104:], uint64(len(b)))
	return b
}

func testArtifact(format string, b []byte) Artifact {
	return Artifact{Core: "synthetic", Arch: "amd64", Destination: "/usr/bin/synthetic", URL: "https://github.com/XTLS/Xray-core/releases/download/pin/synthetic", BinaryMember: "bin/core", BinarySize: int64(len(b)), BinarySHA256: digest(b), format: format, members: map[string]int64{"bin/": 0, "bin/core": int64(len(b)), "bin/LICENSE": 3}}
}

type entry struct {
	name string
	body []byte
	kind byte
}

func tarBytes(t *testing.T, entries []entry) []byte {
	t.Helper()
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	w := tar.NewWriter(g)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0755, Size: int64(len(e.body)), Typeflag: e.kind, Format: tar.FormatUSTAR}
		if e.kind == tar.TypeSymlink || e.kind == tar.TypeLink {
			h.Linkname = "other"
			h.Size = 0
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := w.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	if e := g.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func zipBytes(t *testing.T, entries []entry) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		h.SetMode(0644)
		if e.kind == tar.TypeSymlink {
			h.SetMode(os.ModeSymlink | 0777)
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write(e.body); err != nil {
			t.Fatal(err)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}

func TestClosedCatalogue(t *testing.T) {
	for _, core := range []string{"xray", "sing-box", "hysteria"} {
		for _, arch := range []string{"amd64", "arm64"} {
			a, e := Lookup(core, arch)
			if e != nil || a.ArchiveSize < 1 || a.BinarySize < 1 || len(a.ArchiveSHA256) != 64 || len(a.BinarySHA256) != 64 || a.Destination != "/usr/bin/"+core {
				t.Fatal("invalid catalogue")
			}
			u, _ := url.Parse(a.URL)
			if !permittedURL(u) || u.Host != "github.com" {
				t.Fatal("invalid source")
			}
			a.Version = "changed"
			a.members["bad"] = 1
			other, _ := Lookup(core, arch)
			if other.Version == "changed" || other.members["bad"] != 0 {
				t.Fatal("mutable catalogue")
			}
		}
	}
	for _, s := range []string{"awg", "../xray", "XRAY", "https://github.com"} {
		if _, e := Lookup(s, "amd64"); e == nil {
			t.Fatal("open core selector")
		}
	}
	if _, e := Lookup("xray", "386"); e == nil {
		t.Fatal("unsupported arch")
	}
}

func TestExtractionClosedMembersAndPins(t *testing.T) {
	b := syntheticELF("amd64")
	for _, format := range []string{"zip", "tar.gz", "raw"} {
		t.Run(format, func(t *testing.T) {
			a := testArtifact(format, b)
			entries := []entry{{"bin/core", b, tar.TypeReg}, {"bin/LICENSE", []byte("abc"), tar.TypeReg}}
			if format == "zip" {
				delete(a.members, "bin/")
			} else {
				entries = append([]entry{{"bin/", nil, tar.TypeDir}}, entries...)
			}
			makeArchive := func(es []entry) []byte {
				if format == "zip" {
					return zipBytes(t, es)
				}
				if format == "tar.gz" {
					return tarBytes(t, es)
				}
				return b
			}
			raw := makeArchive(entries)
			a.ArchiveSize = int64(len(raw))
			var out bytes.Buffer
			if e := extract(a, bytes.NewReader(raw), &out); e != nil || !bytes.Equal(out.Bytes(), b) {
				t.Fatalf("valid extraction: %v", e)
			}
			badPin := a
			badPin.BinarySHA256 = strings.Repeat("0", 64)
			if e := extract(badPin, bytes.NewReader(raw), io.Discard); e == nil {
				t.Fatal("binary pin ignored")
			}
			if format == "raw" {
				if e := extract(a, bytes.NewReader(append(raw, 1)), io.Discard); e == nil {
					t.Fatal("raw overrun")
				}
				return
			}
			cases := map[string][]entry{"duplicate": append(append([]entry{}, entries...), entries[0]), "unexpected": append(append([]entry{}, entries...), entry{"unexpected", []byte("x"), tar.TypeReg}), "traversal": {{"../core", b, tar.TypeReg}}, "symlink": {{"bin/core", nil, tar.TypeSymlink}}, "short": {{"bin/core", b[:len(b)-1], tar.TypeReg}}}
			for name, es := range cases {
				t.Run(name, func(t *testing.T) {
					bad := makeArchive(es)
					copyA := a
					copyA.ArchiveSize = int64(len(bad))
					if e := extract(copyA, bytes.NewReader(bad), io.Discard); e == nil {
						t.Fatal("unsafe archive accepted")
					}
				})
			}
			bad := append(append([]byte{}, raw...), 1)
			copyA := a
			copyA.ArchiveSize = int64(len(bad))
			if format == "tar.gz" && extract(copyA, bytes.NewReader(bad), io.Discard) == nil {
				t.Fatal("compressed trailer accepted")
			}
		})
	}
}

func TestTarRejectsHiddenExtendedHeadersAndBounds(t *testing.T) {
	b := syntheticELF("amd64")
	a := testArtifact("tar.gz", b)
	for _, kind := range []byte{tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNULongName, tar.TypeGNULongLink, tar.TypeGNUSparse} {
		var data bytes.Buffer
		g := gzip.NewWriter(&data)
		header := make([]byte, 512)
		copy(header, "bin/core")
		copy(header[100:], "0000755\x00")
		copy(header[124:], "00000000000\x00")
		header[156] = kind
		copy(header[257:], "ustar\x0000")
		for i := 148; i < 156; i++ {
			header[i] = ' '
		}
		sum := 0
		for _, v := range header {
			sum += int(v)
		}
		s := []byte(strings.Repeat("0", 6))
		text := strconvOctal(sum)
		copy(s[6-len(text):], text)
		copy(header[148:], s)
		header[154] = 0
		header[155] = ' '
		g.Write(header)
		g.Write(make([]byte, 1024))
		g.Close()
		a.ArchiveSize = int64(data.Len())
		if extract(a, bytes.NewReader(data.Bytes()), io.Discard) == nil {
			t.Fatal("extended header accepted")
		}
	}
	entries := []entry{{"bin/", nil, tar.TypeDir}, {"bin/core", b, tar.TypeReg}, {"bin/LICENSE", []byte("abc"), tar.TypeReg}}
	raw := tarBytes(t, entries)
	var decompressed bytes.Buffer
	gr, _ := gzip.NewReader(bytes.NewReader(raw))
	io.Copy(&decompressed, gr)
	gr.Close()
	decompressed.Write(make([]byte, 40000))
	var bomb bytes.Buffer
	g := gzip.NewWriter(&bomb)
	g.Write(decompressed.Bytes())
	g.Close()
	a.ArchiveSize = int64(bomb.Len())
	if extract(a, bytes.NewReader(bomb.Bytes()), io.Discard) == nil {
		t.Fatal("padding bomb accepted")
	}
}

func strconvOctal(n int) []byte {
	const digits = "01234567"
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%8]}, b...)
		n /= 8
	}
	return b
}

func TestStaticELFBoundary(t *testing.T) {
	a := testArtifact("raw", syntheticELF("amd64"))
	for _, arch := range []string{"amd64", "arm64"} {
		b := syntheticELF(arch)
		a.Arch = arch
		if verifyELF(a, bytes.NewReader(b)) != nil {
			t.Fatal("valid ELF rejected")
		}
		a.Arch = "amd64"
		if arch == "arm64" && verifyELF(a, bytes.NewReader(b)) == nil {
			t.Fatal("wrong arch accepted")
		}
	}
	a.Arch = "amd64"
	for _, kind := range []uint32{2, 3} {
		b := syntheticELF("amd64")
		binary.LittleEndian.PutUint32(b[64:], kind)
		if verifyELF(a, bytes.NewReader(b)) == nil {
			t.Fatal("dynamic ELF accepted")
		}
	}
	b := syntheticELF("amd64")
	binary.LittleEndian.PutUint64(b[96:], uint64(len(b)+1))
	if verifyELF(a, bytes.NewReader(b)) == nil {
		t.Fatal("out of bounds program")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDownloadBoundsHashCancellationAndNoProxy(t *testing.T) {
	data := []byte("synthetic artifact bytes")
	a := testArtifact("raw", data)
	a.ArchiveSize = int64(len(data))
	a.ArchiveSHA256 = digest(data)
	for _, c := range []struct {
		name   string
		body   []byte
		length int64
		pin    string
		ok     bool
	}{{"valid", data, int64(len(data)), a.ArchiveSHA256, true}, {"unknown-length", data, -1, a.ArchiveSHA256, true}, {"short", data[:2], -1, a.ArchiveSHA256, false}, {"overrun", append(append([]byte{}, data...), 1), -1, a.ArchiveSHA256, false}, {"wrong-length", data, 1, a.ArchiveSHA256, false}, {"wrong-hash", data, -1, strings.Repeat("0", 64), false}} {
		t.Run(c.name, func(t *testing.T) {
			copyA := a
			copyA.ArchiveSHA256 = c.pin
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(c.body)), ContentLength: c.length, Header: http.Header{}}, nil
			})}
			var dst bytes.Buffer
			e := download(context.Background(), copyA, &dst, client)
			if (e == nil) != c.ok {
				t.Fatal("download boundary")
			}
			if int64(dst.Len()) > a.ArchiveSize+1 {
				t.Fatal("unbounded download")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() })}
	if !errors.Is(download(ctx, a, io.Discard, client), ErrDownload) {
		t.Fatal("cancellation")
	}
	client = downloadClient()
	defer client.CloseIdleConnections()
	if client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("environment proxy enabled")
	}
}

func TestHTTPSRedirectAllowlist(t *testing.T) {
	for _, raw := range []string{"http://github.com/a", "https://github.com.evil/a", "https://u:p@github.com/a", "https://github.com:444/a", "https://127.0.0.1/a", "https://objects.githubusercontent.com/a#fragment"} {
		u, _ := url.Parse(raw)
		if permittedURL(u) {
			t.Fatal("unsafe URL")
		}
	}
	for _, host := range []string{"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"} {
		u, _ := url.Parse("https://" + host + "/asset")
		if !permittedURL(u) || redirect(&http.Request{URL: u}, nil) != nil {
			t.Fatal("official redirect rejected")
		}
		if redirect(&http.Request{URL: u}, make([]*http.Request, 5)) == nil {
			t.Fatal("redirect loop unbounded")
		}
	}
}

// Optional upstream byte compatibility check; normal tests never use network.
// This only downloads/extracts hashes and ELF metadata, never executes a core.
func TestOfficialArtifactBytes(t *testing.T) {
	if os.Getenv("FVPN_VERIFY_CORE_ASSETS") != "1" {
		t.Skip("explicit upstream-byte verification not requested")
	}
	for _, core := range []string{"xray", "sing-box", "hysteria"} {
		for _, arch := range []string{"amd64", "arm64"} {
			t.Run(core+"-"+arch, func(t *testing.T) {
				a, _ := Lookup(core, arch)
				root := t.TempDir()
				archive, e := os.Create(filepath.Join(root, "archive"))
				if e != nil {
					t.Fatal(e)
				}
				defer archive.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()
				client := downloadClient()
				defer client.CloseIdleConnections()
				if e := download(ctx, a, archive, client); e != nil {
					t.Fatal(e)
				}
				archive.Seek(0, io.SeekStart)
				bin, e := os.Create(filepath.Join(root, "binary"))
				if e != nil {
					t.Fatal(e)
				}
				defer bin.Close()
				if e := extract(a, archive, bin); e != nil {
					t.Fatal(e)
				}
				st, _ := bin.Stat()
				if st.Size() != a.BinarySize || verifyELF(a, bin) != nil {
					t.Fatal("upstream ELF boundary")
				}
			})
		}
	}
}
