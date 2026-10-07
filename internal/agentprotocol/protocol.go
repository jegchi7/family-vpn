// Package agentprotocol defines the bounded local fake-stand contract, not a shell API.
package agentprotocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const MaxBody = 4096
const Ensure = "EnsureDeviceProfiles"
const Revoke = "RevokeDeviceProfiles"
const Read = "ReadState"

var ErrInvalid = errors.New("invalid intent")
var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func ValidID(s string) bool { return identifier.MatchString(s) }

// This stand manages one synthetic profile per target. No keys/configs/endpoints.
type Payload struct {
	Generation int64 `json:"generation"`
}
type Envelope struct {
	SchemaVersion    int     `json:"schema_version"`
	OperationID      string  `json:"operation_id"`
	Type             string  `json:"type"`
	TargetID         string  `json:"target_id"`
	ExpectedRevision int64   `json:"expected_revision"`
	Payload          Payload `json:"payload"`
}
type Result struct {
	OperationID      string `json:"operation_id"`
	State            string `json:"state"`
	ObservedRevision int64  `json:"observed_revision"`
	ResultCode       string `json:"result_code"`
}

func (e Envelope) Validate() error {
	if e.SchemaVersion != 1 || !ValidID(e.OperationID) || !ValidID(e.TargetID) || e.ExpectedRevision < 0 || e.ExpectedRevision > 1<<52 || e.Payload.Generation < 1 || e.Payload.Generation > 1<<31 {
		return ErrInvalid
	}
	if e.Type != Ensure && e.Type != Revoke && e.Type != Read {
		return ErrInvalid
	}
	return nil
}

// Exact JSON keys, no duplicates (including nested objects), nulls or trailing data.
func Decode(r io.Reader) (Envelope, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxBody+1))
	if err != nil || len(b) > MaxBody {
		return Envelope{}, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err = unique(d, 0); err != nil {
		return Envelope{}, ErrInvalid
	}
	if _, err = d.Token(); err != io.EOF {
		return Envelope{}, ErrInvalid
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(b, &obj) != nil || !keys(obj, "schema_version", "operation_id", "type", "target_id", "expected_revision", "payload") {
		return Envelope{}, ErrInvalid
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(obj["payload"], &payload) != nil || !keys(payload, "generation") {
		return Envelope{}, ErrInvalid
	}
	var e Envelope
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&e) != nil || e.Validate() != nil {
		return Envelope{}, ErrInvalid
	}
	return e, nil
}
func keys(m map[string]json.RawMessage, want ...string) bool {
	if len(m) != len(want) {
		return false
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}
func unique(d *json.Decoder, depth int) error {
	if depth > 8 {
		return ErrInvalid
	}
	t, e := d.Token()
	if e != nil || t == nil {
		return ErrInvalid
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	if delim == '{' {
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			s, ok := k.(string)
			if e != nil || !ok || seen[s] {
				return ErrInvalid
			}
			seen[s] = true
			if e = unique(d, depth+1); e != nil {
				return e
			}
		}
		t, e = d.Token()
		if e != nil || t != json.Delim('}') {
			return ErrInvalid
		}
		return nil
	}
	if delim == '[' {
		for d.More() {
			if e = unique(d, depth+1); e != nil {
				return e
			}
		}
		t, e = d.Token()
		if e != nil || t != json.Delim(']') {
			return ErrInvalid
		}
		return nil
	}
	return ErrInvalid
}
