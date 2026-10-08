package clientconfig

import (
	"bytes"
	"errors"
	"strconv"
	"time"
)

var ErrAWGSession = errors.New("AWG session readback unavailable, invalid or changed")

// AWGHandshakeRecentAge is a diagnostic window, not a connectivity guarantee.
const AWGHandshakeRecentAge = 180 * time.Second

const awgSessionMaxRows = 256
const awgSessionMaxBytes = 64 << 10
const awgSessionMaxUnix = 253402300799 // Last second representable in RFC3339 year 9999.

// AWGSession contains only selected-peer diagnostics. It retains neither keys
// nor counters, and does not attest a native source, core or Android client.
type AWGSession struct {
	PeerObserved     bool       `json:"peer_observed"`
	LastHandshake    *time.Time `json:"last_handshake"`
	HandshakeRecent  bool       `json:"handshake_recent"`
	ReceivedAdvanced bool       `json:"received_advanced"`
	SentAdvanced     bool       `json:"sent_advanced"`
}

func (s AWGSession) String() string   { return "AWG selected-peer session diagnostics" }
func (s AWGSession) GoString() string { return s.String() }

func awgSessionNumber(value []byte) (uint64, bool) {
	if len(value) == 0 || len(value) > 20 || len(value) > 1 && value[0] == '0' {
		return 0, false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	n, e := strconv.ParseUint(string(value), 10, 64)
	return n, e == nil
}

// The pinned show.c named-interface modes contain exactly a public key and
// decimal numbers, separated by tabs. All-mode interface prefixes are rejected.
func awgSessionRows(data []byte, columns int, latestUnix uint64) (map[[32]byte][2]uint64, error) {
	if len(data) > awgSessionMaxBytes {
		return nil, ErrAWGSession
	}
	rows := make(map[[32]byte][2]uint64)
	if len(data) == 0 {
		return rows, nil
	}
	lines := bytes.Split(data, []byte{'\n'})
	terminated := bytes.HasSuffix(data, []byte{'\n'})
	if len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > awgSessionMaxRows {
		return nil, ErrAWGSession
	}
	for index, line := range lines {
		if index < len(lines)-1 || terminated {
			line = bytes.TrimSuffix(line, []byte{'\r'})
		}
		fields := bytes.Split(line, []byte{'\t'})
		if len(fields) != columns {
			return nil, ErrAWGSession
		}
		key, ok := awgKey(string(fields[0]))
		if !ok {
			return nil, ErrAWGSession
		}
		var identity [32]byte
		copy(identity[:], key)
		clear(key)
		if _, duplicate := rows[identity]; duplicate {
			return nil, ErrAWGSession
		}
		var values [2]uint64
		for i, field := range fields[1:] {
			values[i], ok = awgSessionNumber(field)
			if !ok || columns == 2 && values[i] > latestUnix {
				return nil, ErrAWGSession
			}
		}
		rows[identity] = values
	}
	return rows, nil
}

func sameAWGSessionPeers(a, b map[[32]byte][2]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for key := range a {
		if _, ok := b[key]; !ok {
			return false
		}
	}
	return true
}

// CheckAWGSession compares caller-supplied readbacks only. Native source/scope,
// TTL and profile bindings belong to the observer; this comparator grants no
// readiness or installation permission. The client identity is its derived
// X25519 public key, including the validator's clamping behavior.
func CheckAWGSession(client, firstHandshakes, firstTransfer, lastHandshakes, lastTransfer []byte, measuredAt time.Time) (AWGSession, error) {
	empty := AWGSession{}
	measuredAt = measuredAt.UTC()
	if measuredAt.IsZero() || measuredAt.Unix() < 0 || measuredAt.Unix() > awgSessionMaxUnix {
		return empty, ErrAWGSession
	}
	validated, e := Validate(AWG31Conf, client)
	if e != nil {
		return empty, ErrAWGSession
	}
	firstH, e := awgSessionRows(firstHandshakes, 2, uint64(measuredAt.Unix()))
	if e != nil {
		return empty, ErrAWGSession
	}
	firstT, e := awgSessionRows(firstTransfer, 3, uint64(measuredAt.Unix()))
	if e != nil {
		return empty, ErrAWGSession
	}
	lastH, e := awgSessionRows(lastHandshakes, 2, uint64(measuredAt.Unix()))
	if e != nil {
		return empty, ErrAWGSession
	}
	lastT, e := awgSessionRows(lastTransfer, 3, uint64(measuredAt.Unix()))
	if e != nil || !sameAWGSessionPeers(firstH, firstT) || !sameAWGSessionPeers(lastH, lastT) || !sameAWGSessionPeers(firstH, lastH) {
		return empty, ErrAWGSession
	}
	for key, first := range firstH {
		last := lastH[key]
		before, after := firstT[key], lastT[key]
		if last[0] < first[0] || after[0] < before[0] || after[1] < before[1] {
			return empty, ErrAWGSession
		}
	}
	last, observed := lastH[validated.credential]
	if !observed {
		return empty, nil
	}
	before, after := firstT[validated.credential], lastT[validated.credential]
	result := AWGSession{PeerObserved: true, ReceivedAdvanced: after[0] > before[0], SentAdvanced: after[1] > before[1]}
	if last[0] != 0 {
		stamp := time.Unix(int64(last[0]), 0).UTC()
		result.LastHandshake = &stamp
		result.HandshakeRecent = measuredAt.Sub(stamp) <= AWGHandshakeRecentAge
	}
	return result, nil
}
