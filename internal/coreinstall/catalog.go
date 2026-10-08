// Package coreinstall installs a closed catalogue of independently pinned core
// binaries. Installing bytes does not configure or attest a running VPN.
package coreinstall

import "errors"

var (
	ErrArguments   = errors.New("invalid core selection")
	ErrPlatform    = errors.New("core installation requires Linux root")
	ErrDownload    = errors.New("core download failed")
	ErrIntegrity   = errors.New("core integrity check failed")
	ErrProtected   = errors.New("protected core location unavailable")
	ErrConflict    = errors.New("existing core differs from pinned bytes")
	ErrUnavailable = errors.New("pinned core unavailable")
)

type Artifact struct {
	Core          string `json:"core"`
	Version       string `json:"version"`
	Arch          string `json:"arch"`
	Destination   string `json:"destination"`
	URL           string `json:"url"`
	ArchiveSHA256 string `json:"archive_sha256"`
	ArchiveSize   int64  `json:"archive_bytes"`
	BinaryMember  string `json:"binary_member"`
	BinarySHA256  string `json:"binary_sha256"`
	BinarySize    int64  `json:"binary_bytes"`
	format        string
	members       map[string]int64
}

// Lookup returns a copy: caller mutations cannot change the closed catalogue.
func Lookup(core, arch string) (Artifact, error) {
	a, ok := catalogue[core+"/"+arch]
	if !ok {
		return Artifact{}, ErrArguments
	}
	m := make(map[string]int64, len(a.members))
	for k, v := range a.members {
		m[k] = v
	}
	a.members = m
	return a, nil
}

var catalogue = func() map[string]Artifact {
	m := map[string]Artifact{}
	add := func(a Artifact) { m[a.Core+"/"+a.Arch] = a }
	xray := func(arch, asset, sha, bsha string, as, bs int64) {
		add(Artifact{Core: "xray", Version: XrayVersion, Arch: arch, Destination: "/usr/bin/xray", URL: "https://github.com/XTLS/Xray-core/releases/download/v" + XrayVersion + "/" + asset, ArchiveSHA256: sha, ArchiveSize: as, BinaryMember: "xray", BinarySHA256: bsha, BinarySize: bs, format: "zip", members: map[string]int64{"xray": bs, "geoip.dat": 19768301, "geosite.dat": 10491954, "LICENSE": 16725, "README.md": 10813}})
	}
	xray("amd64", "Xray-linux-64.zip", "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae", "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed", 21136402, 36577406)
	xray("arm64", "Xray-linux-arm64-v8a.zip", "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c", "c2d20a7045250497083afea0d79db0672f6c89a25aaaf37c92de034d6b764b04", 19716427, 34209918)
	sing := func(arch, sha, bsha string, as, bs int64) {
		prefix := "sing-box-" + SingBoxVersion + "-linux-" + arch + "-musl"
		add(Artifact{Core: "sing-box", Version: SingBoxVersion, Arch: arch, Destination: "/usr/bin/sing-box", URL: "https://github.com/SagerNet/sing-box/releases/download/v" + SingBoxVersion + "/" + prefix + ".tar.gz", ArchiveSHA256: sha, ArchiveSize: as, BinaryMember: prefix + "/sing-box", BinarySHA256: bsha, BinarySize: bs, format: "tar.gz", members: map[string]int64{prefix + "/": 0, prefix + "/LICENSE": 791, prefix + "/sing-box": bs}})
	}
	sing("amd64", "8f6cb4bcf94d2b33c65d52e0d5b142db29a938336f1ff7267f397ac3758fc297", "4b5cef575df2e5572eddf7c204b4adea03a27d9721c5e39a89df5fb6977643cb", 32525286, 91951072)
	sing("arm64", "675297394f9430cebb72b3c48ba8bce0d6f7c750a9d68a8f7f88c515c8255cd1", "fb9189e2d14f2795aa86adc070f7a61d1c74c299f519e52a021b1bbc720b4769", 29725690, 86012408)
	hy := func(arch, sha string, n int64) {
		add(Artifact{Core: "hysteria", Version: HysteriaVersion, Arch: arch, Destination: "/usr/bin/hysteria", URL: "https://github.com/HyNetworks/hysteria/releases/download/app/v" + HysteriaVersion + "/hysteria-linux-" + arch, ArchiveSHA256: sha, ArchiveSize: n, BinarySHA256: sha, BinarySize: n, format: "raw"})
	}
	hy("amd64", "907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691", 23924898)
	hy("arm64", "a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7", 22151330)
	return m
}()
