package clientconfig

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"
)

func awgSessionClient(t testing.TB) ([]byte, string) {
	t.Helper()
	client := awgSample(t)
	validated, e := Validate(AWG31Conf, client)
	if e != nil {
		t.Fatal("synthetic client validation failed")
	}
	return client, base64.StdEncoding.EncodeToString(validated.credential[:])
}

func awgSessionPeer(t testing.TB) string {
	t.Helper()
	private, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
}

func awgSessionHandshake(key string, unix uint64) []byte {
	return []byte(key + "\t" + strconv.FormatUint(unix, 10) + "\n")
}

func awgSessionTransfer(key string, received, sent uint64) []byte {
	return []byte(key + "\t" + strconv.FormatUint(received, 10) + "\t" + strconv.FormatUint(sent, 10) + "\n")
}

func TestAWGSessionSelectedPeerAndHandshakeWindow(t *testing.T) {
	client, selected := awgSessionClient(t)
	measured := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                             string
		stamp                            uint64
		recent                           bool
		received, sent                   bool
		firstRx, firstTx, lastRx, lastTx uint64
	}{
		{name: "never handshaken", stamp: 0},
		{name: "current handshake", stamp: uint64(measured.Unix()), recent: true},
		{name: "exact recent boundary", stamp: uint64(measured.Add(-180 * time.Second).Unix()), recent: true},
		{name: "older than recent boundary", stamp: uint64(measured.Add(-181 * time.Second).Unix())},
		{name: "received advances", stamp: uint64(measured.Unix()), recent: true, firstRx: 900, lastRx: 901, firstTx: 42, lastTx: 42, received: true},
		{name: "sent advances", stamp: uint64(measured.Unix()), recent: true, firstRx: 42, lastRx: 42, firstTx: 900, lastTx: 901, sent: true},
		{name: "maximum counters stay flat", stamp: uint64(measured.Unix()), recent: true, firstRx: math.MaxUint64, lastRx: math.MaxUint64, firstTx: math.MaxUint64, lastTx: math.MaxUint64},
		{name: "maximum counters increase", stamp: uint64(measured.Unix()), recent: true, firstRx: math.MaxUint64 - 1, lastRx: math.MaxUint64, firstTx: math.MaxUint64 - 1, lastTx: math.MaxUint64, received: true, sent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := awgSessionHandshake(selected, tc.stamp)
			result, e := CheckAWGSession(client, h, awgSessionTransfer(selected, tc.firstRx, tc.firstTx), h, awgSessionTransfer(selected, tc.lastRx, tc.lastTx), measured)
			if e != nil || !result.PeerObserved || result.HandshakeRecent != tc.recent || result.ReceivedAdvanced != tc.received || result.SentAdvanced != tc.sent {
				t.Fatal("incorrect selected-peer diagnostics", e)
			}
			if tc.stamp == 0 {
				if result.LastHandshake != nil {
					t.Fatal("never-handshaken timestamp fabricated")
				}
			} else if result.LastHandshake == nil || !result.LastHandshake.Equal(time.Unix(int64(tc.stamp), 0)) {
				t.Fatal("selected handshake timestamp changed")
			}
		})
	}
	t.Run("fractional age above boundary", func(t *testing.T) {
		h := awgSessionHandshake(selected, uint64(measured.Add(-180*time.Second).Unix()))
		result, e := CheckAWGSession(client, h, awgSessionTransfer(selected, 0, 0), h, awgSessionTransfer(selected, 0, 0), measured.Add(time.Nanosecond))
		if e != nil || result.HandshakeRecent {
			t.Fatal("fractional seconds incorrectly kept handshake recent", e)
		}
	})
}

func TestAWGSessionPeerSetsClampingAndOrdering(t *testing.T) {
	client, selected := awgSessionClient(t)
	other := awgSessionPeer(t)
	measured := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	h := awgSessionHandshake(selected, uint64(measured.Unix()))
	tr := awgSessionTransfer(selected, 10, 20)
	t.Run("empty outputs are unobserved", func(t *testing.T) {
		result, e := CheckAWGSession(client, nil, nil, nil, nil, measured)
		if e != nil || result.PeerObserved || result.LastHandshake != nil || result.HandshakeRecent || result.ReceivedAdvanced || result.SentAdvanced {
			t.Fatal("empty readbacks fabricate diagnostics", e)
		}
	})
	t.Run("another peer does not substitute selected client", func(t *testing.T) {
		otherH, otherT := awgSessionHandshake(other, uint64(measured.Unix())), awgSessionTransfer(other, 20, 30)
		result, e := CheckAWGSession(client, otherH, otherT, otherH, awgSessionTransfer(other, 21, 31), measured)
		if e != nil || result.PeerObserved || result.LastHandshake != nil || result.HandshakeRecent || result.ReceivedAdvanced || result.SentAdvanced {
			t.Fatal("extra peer became selected-peer evidence", e)
		}
	})
	t.Run("extra peers and row order do not alter selected diagnosis", func(t *testing.T) {
		firstH := append(bytes.Clone(h), awgSessionHandshake(other, 0)...)
		firstT := append(awgSessionTransfer(other, 40, 50), tr...)
		lastH := append(awgSessionHandshake(other, 0), h...)
		lastT := append(awgSessionTransfer(selected, 11, 20), awgSessionTransfer(other, 41, 51)...)
		result, e := CheckAWGSession(client, firstH, firstT, lastH, lastT, measured)
		if e != nil || !result.PeerObserved || !result.HandshakeRecent || !result.ReceivedAdvanced || result.SentAdvanced {
			t.Fatal("row ordering or extra peers changed selection", e)
		}
	})
	t.Run("new handshake between samples is measured at completion", func(t *testing.T) {
		result, e := CheckAWGSession(client, awgSessionHandshake(selected, 0), tr, h, awgSessionTransfer(selected, 11, 21), measured)
		if e != nil || !result.PeerObserved || !result.HandshakeRecent || !result.ReceivedAdvanced || !result.SentAdvanced {
			t.Fatal("new handshake/counter progress rejected", e)
		}
	})
	t.Run("LF CRLF and final complete row without LF", func(t *testing.T) {
		result, e := CheckAWGSession(client, bytes.ReplaceAll(h, []byte("\n"), []byte("\r\n")), bytes.TrimSuffix(tr, []byte("\n")), bytes.TrimSuffix(h, []byte("\n")), bytes.ReplaceAll(tr, []byte("\n"), []byte("\r\n")), measured)
		if e != nil || !result.PeerObserved || !result.HandshakeRecent {
			t.Fatal("accepted line endings rejected", e)
		}
	})
	t.Run("clamped private key still selects same public identity", func(t *testing.T) {
		var private []byte
		for _, line := range strings.Split(string(client), "\r\n") {
			if strings.HasPrefix(line, "PrivateKey = ") {
				private, _ = base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "PrivateKey = "))
			}
		}
		defer clear(private)
		private[0] ^= 7
		private[31] ^= 192
		alias := awgReplace(client, "PrivateKey", base64.StdEncoding.EncodeToString(private))
		defer clear(alias)
		result, e := CheckAWGSession(alias, h, tr, h, tr, measured)
		if e != nil || !result.PeerObserved {
			t.Fatal("clamping changed peer selection", e)
		}
	})
}

func TestAWGSessionRejectsMalformedRowsAndTime(t *testing.T) {
	client, selected := awgSessionClient(t)
	measured := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	h := awgSessionHandshake(selected, uint64(measured.Unix()))
	tr := awgSessionTransfer(selected, 0, 0)
	zeroKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	// A zeroed unused padding bit produces an alternate encoding only if strict
	// base64 checking is disabled. Make its final data sextet deliberately odd.
	badPadding := selected[:42] + "B="
	for _, invalid := range []struct {
		name  string
		h, tr []byte
	}{
		{name: "pretty output", h: []byte("peer: " + selected + "\n")},
		{name: "all-mode prefix", h: []byte("awg0\t" + selected + "\t0\n")},
		{name: "spaces instead of tab", h: []byte(selected + " 0\n")},
		{name: "unknown extra column", tr: []byte(selected + "\t0\t0\textra\n")},
		{name: "missing transfer column", tr: []byte(selected + "\t0\n")},
		{name: "blank row", h: append(bytes.Clone(h), '\n')},
		{name: "only newline", h: []byte("\n")},
		{name: "lone final CR", h: bytes.ReplaceAll(h, []byte("\n"), []byte("\r"))},
		{name: "duplicate key", h: append(bytes.Clone(h), h...)},
		{name: "duplicate transfer key", tr: append(bytes.Clone(tr), tr...)},
		{name: "zero key", h: []byte(zeroKey + "\t0\n")},
		{name: "bad key padding", h: []byte(badPadding + "\t0\n")},
		{name: "key unpadded", h: []byte(strings.TrimSuffix(selected, "=") + "\t0\n")},
		{name: "negative number", h: []byte(selected + "\t-1\n")},
		{name: "plus number", h: []byte(selected + "\t+1\n")},
		{name: "leading zero", h: []byte(selected + "\t00\n")},
		{name: "decimal number", h: []byte(selected + "\t1.0\n")},
		{name: "unicode digit", h: []byte(selected + "\t１\n")},
		{name: "future handshake", h: awgSessionHandshake(selected, uint64(measured.Unix())+1)},
		{name: "unsafe Unix", h: awgSessionHandshake(selected, math.MaxUint64)},
		{name: "counter overflow", tr: []byte(selected + "\t18446744073709551616\t0\n")},
		{name: "counter leading zero", tr: []byte(selected + "\t01\t0\n")},
		{name: "counter control", tr: []byte(selected + "\t0\t1\x00\n")},
		{name: "oversized handshakes", h: bytes.Repeat([]byte{'a'}, (64<<10)+1)},
		{name: "oversized transfer", tr: bytes.Repeat([]byte{'a'}, (64<<10)+1)},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			badH, badT := h, tr
			if invalid.h != nil {
				badH = invalid.h
			}
			if invalid.tr != nil {
				badT = invalid.tr
			}
			result, e := CheckAWGSession(client, badH, badT, h, tr, measured)
			if !errors.Is(e, ErrAWGSession) || result.PeerObserved || result.LastHandshake != nil {
				t.Fatal("invalid readback did not clear diagnostics", e)
			}
			if strings.Contains(e.Error(), selected) {
				t.Fatal("error leaked selected public identity")
			}
		})
	}
	for _, stamp := range []time.Time{time.Time{}, time.Unix(-1, 0), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		if _, e := CheckAWGSession(client, h, tr, h, tr, stamp); !errors.Is(e, ErrAWGSession) {
			t.Fatal("invalid measurement time accepted", e)
		}
	}
	t.Run("last representable RFC3339 second", func(t *testing.T) {
		last := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
		handshake := awgSessionHandshake(selected, uint64(last.Unix()))
		result, e := CheckAWGSession(client, handshake, tr, handshake, tr, last)
		if e != nil || result.LastHandshake == nil || !result.LastHandshake.Equal(last) || !result.HandshakeRecent {
			t.Fatal("safe maximum Unix second rejected", e)
		}
		if _, e = json.Marshal(result); e != nil {
			t.Fatal("accepted handshake cannot serialize as RFC3339")
		}
	})
	t.Run("measurement timezone normalizes to UTC", func(t *testing.T) {
		zone := measured.In(time.FixedZone("local", 3*60*60))
		result, e := CheckAWGSession(client, h, tr, h, tr, zone)
		if e != nil || result.LastHandshake == nil || result.LastHandshake.Location() != time.UTC || !result.HandshakeRecent {
			t.Fatal("timezone changed session timestamp semantics", e)
		}
	})
	t.Run("malformed final transfer clears earlier valid samples", func(t *testing.T) {
		result, e := CheckAWGSession(client, h, tr, h, []byte(selected+"\t0\tinvalid\n"), measured)
		if !errors.Is(e, ErrAWGSession) || result.PeerObserved || result.LastHandshake != nil || result.HandshakeRecent || result.ReceivedAdvanced || result.SentAdvanced {
			t.Fatal("late malformed sample retained diagnostics", e)
		}
	})
	t.Run("future unselected peer is rejected even without selected peer", func(t *testing.T) {
		other := awgSessionPeer(t)
		otherH, otherT := awgSessionHandshake(other, uint64(measured.Unix())+1), awgSessionTransfer(other, 0, 0)
		if _, e := CheckAWGSession(client, otherH, otherT, otherH, otherT, measured); !errors.Is(e, ErrAWGSession) {
			t.Fatal("unselected future timestamp bypassed validation", e)
		}
	})
	if _, e := CheckAWGSession([]byte("invalid client"), h, tr, h, tr, measured); !errors.Is(e, ErrAWGSession) {
		t.Fatal("unvalidated client accepted", e)
	}
}

func TestAWGSessionRejectsDriftAndRegression(t *testing.T) {
	client, selected := awgSessionClient(t)
	other := awgSessionPeer(t)
	measured := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	h := awgSessionHandshake(selected, uint64(measured.Unix()))
	tr := awgSessionTransfer(selected, 10, 20)
	for _, tc := range []struct {
		name                         string
		firstH, firstT, lastH, lastT []byte
	}{
		{name: "selected disappears", firstH: h, firstT: tr},
		{name: "selected appears", lastH: h, lastT: tr},
		{name: "first sample peer sets differ", firstH: h, lastH: h, lastT: tr},
		{name: "last sample peer sets differ", firstH: h, firstT: tr, lastH: h},
		{name: "handshake regresses", firstH: h, firstT: tr, lastH: awgSessionHandshake(selected, uint64(measured.Unix())-1), lastT: tr},
		{name: "handshake resets zero", firstH: h, firstT: tr, lastH: awgSessionHandshake(selected, 0), lastT: tr},
		{name: "received regresses", firstH: h, firstT: tr, lastH: h, lastT: awgSessionTransfer(selected, 9, 20)},
		{name: "sent regresses", firstH: h, firstT: tr, lastH: h, lastT: awgSessionTransfer(selected, 10, 19)},
		{name: "counter wraps", firstH: h, firstT: awgSessionTransfer(selected, math.MaxUint64, 20), lastH: h, lastT: awgSessionTransfer(selected, 0, 20)},
		{name: "peer identity replaced", firstH: h, firstT: tr, lastH: awgSessionHandshake(other, uint64(measured.Unix())), lastT: awgSessionTransfer(other, 10, 20)},
		{name: "extra peer disappears", firstH: append(bytes.Clone(h), awgSessionHandshake(other, 0)...), firstT: append(bytes.Clone(tr), awgSessionTransfer(other, 10, 20)...), lastH: h, lastT: tr},
		{name: "extra peer handshake regresses", firstH: append(bytes.Clone(h), awgSessionHandshake(other, 1)...), firstT: append(bytes.Clone(tr), awgSessionTransfer(other, 10, 20)...), lastH: append(bytes.Clone(h), awgSessionHandshake(other, 0)...), lastT: append(bytes.Clone(tr), awgSessionTransfer(other, 10, 20)...)},
		{name: "extra peer counter regresses", firstH: append(bytes.Clone(h), awgSessionHandshake(other, 0)...), firstT: append(bytes.Clone(tr), awgSessionTransfer(other, 10, 20)...), lastH: append(bytes.Clone(h), awgSessionHandshake(other, 0)...), lastT: append(bytes.Clone(tr), awgSessionTransfer(other, 9, 20)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, e := CheckAWGSession(client, tc.firstH, tc.firstT, tc.lastH, tc.lastT, measured)
			if !errors.Is(e, ErrAWGSession) || result.PeerObserved || result.LastHandshake != nil || result.HandshakeRecent || result.ReceivedAdvanced || result.SentAdvanced {
				t.Fatal("drift/regression accepted or stale diagnostics retained", e)
			}
		})
	}
}

func TestAWGSessionRowBoundsAndRedaction(t *testing.T) {
	client, selected := awgSessionClient(t)
	measured := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	h, tr := awgSessionHandshake(selected, uint64(measured.Unix())), awgSessionTransfer(selected, 81234567, 71234567)
	for i := 1; i < 256; i++ {
		peer := awgSessionPeer(t)
		h = append(h, awgSessionHandshake(peer, 0)...)
		tr = append(tr, awgSessionTransfer(peer, 0, 0)...)
	}
	result, e := CheckAWGSession(client, h, tr, h, awgSessionTransfer(selected, 81234567, 71234567), measured)
	if !errors.Is(e, ErrAWGSession) || result.PeerObserved {
		t.Fatal("mismatched large peer sets accepted", e)
	}
	result, e = CheckAWGSession(client, h, tr, h, tr, measured)
	if e != nil || !result.PeerObserved {
		t.Fatal("maximum peer count rejected", e)
	}
	peer := awgSessionPeer(t)
	if _, e = CheckAWGSession(client, append(bytes.Clone(h), awgSessionHandshake(peer, 0)...), append(bytes.Clone(tr), awgSessionTransfer(peer, 0, 0)...), h, tr, measured); !errors.Is(e, ErrAWGSession) {
		t.Fatal("excess peers accepted", e)
	}
	encoded, e := json.Marshal(result)
	if e != nil {
		t.Fatal(e)
	}
	for _, output := range []string{string(encoded), fmt.Sprint(result), fmt.Sprintf("%+v", result), fmt.Sprintf("%#v", result)} {
		for _, private := range []string{selected, "81234567", "71234567", "PrivateKey", "credential"} {
			if strings.Contains(output, private) {
				t.Fatal("session diagnostics leaked key/counter/internal fields")
			}
		}
	}
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(encoded, &fields); e != nil || len(fields) != 5 {
		t.Fatal("unexpected diagnostic JSON shape")
	}
}
