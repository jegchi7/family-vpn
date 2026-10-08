package foreignsetup

import (
	"bytes"
	"testing"
)

func TestRUHopReceiverClosedCanonicalSubset(t *testing.T) {
	b := generated(t)
	if endpoint, e := ValidateRUHop(b.RUHop); e != nil || endpoint != "8.8.8.8" {
		t.Fatal("canonical hop rejected")
	}
	for _, bad := range [][]byte{nil, append(bytes.Clone(b.RUHop), ' '), bytes.Replace(b.RUHop, []byte(`"insecure": false`), []byte(`"insecure": true`), 1), bytes.Replace(b.RUHop, []byte(`"packet_encoding": "xudp"`), []byte(`"packet_encoding": "none"`), 1), bytes.Replace(b.RUHop, []byte(`"tls":`), []byte(`"detour":"direct","tls":`), 1), bytes.Replace(b.RUHop, []byte(`"server": "8.8.8.8"`), []byte(`"server": "127.0.0.1"`), 1), bytes.Replace(b.RUHop, []byte(`"type": "vless"`), []byte(`"type": "vless", "Type":"vless"`), 1)} {
		if _, e := ValidateRUHop(bad); e == nil {
			t.Fatal("noncanonical or expanded hop accepted")
		}
	}
}
