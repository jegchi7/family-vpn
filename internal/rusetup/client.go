package rusetup

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"familyvpn.local/platform/internal/clientconfig"
	"net/url"
	"strings"
)

func validClientID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	b, e := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	defer clear(b)
	return e == nil && len(b) == 16 && !bytes.Equal(b, make([]byte, 16))
}

// BindValidatedClient is a pure private configuration operation, not an import,
// ownership check, installation proof or readiness transition. A trusted caller
// must load the exact export through the current vault/profile context and
// repeat its writer-fenced ownership/revision/uniqueness guards separately.
// It never creates a URI, writes a file or returns plaintext in a report.
func BindValidatedClient(b Bundle, client []byte) (Bundle, error) {
	if _, _, e := ValidateBundle(b); e != nil {
		return Bundle{}, ErrConfig
	}
	if _, e := clientconfig.Validate(clientconfig.VLESSRealityURI, client); e != nil {
		return Bundle{}, ErrConfig
	}
	var p plan
	var x xConfig
	if decode(b.Plan, &p) != nil || decode(b.Xray, &x) != nil {
		return Bundle{}, ErrConfig
	}
	u, e := url.Parse(strings.TrimSuffix(strings.TrimSuffix(string(client), "\n"), "\r"))
	if e != nil {
		return Bundle{}, ErrConfig
	}
	r := x.Inbounds[0].Stream.Reality
	k, e := base64.RawURLEncoding.Strict().DecodeString(r.PrivateKey)
	defer clear(k)
	if e != nil {
		return Bundle{}, ErrConfig
	}
	key, e := ecdh.X25519().NewPrivateKey(k)
	if e != nil {
		return Bundle{}, ErrConfig
	}
	q := u.Query()
	if u.Host != p.Inputs.Endpoint || q.Get("sni") != p.Inputs.ServerName || q.Get("pbk") != base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()) || !strings.EqualFold(q.Get("sid"), r.ShortIDs[0]) {
		return Bundle{}, ErrConfig
	}
	id := u.User.Username()
	if !validClientID(id) || len(x.Inbounds[0].Settings.Clients) > 0 && x.Inbounds[0].Settings.Clients[0].ID != id {
		return Bundle{}, ErrConfig
	}
	x.Inbounds[0].Settings.Clients = []xClient{{id, "xtls-rprx-vision"}}
	xray, e := marshal(x)
	if e != nil {
		return Bundle{}, ErrConfig
	}
	return Bundle{Xray: xray, SingBox: bytes.Clone(b.SingBox), Hop: bytes.Clone(b.Hop), Plan: bytes.Clone(b.Plan)}, nil
}
