package domain

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrDeviceInput = errors.New("invalid device input")
var ErrDeviceLimit = errors.New("device limit reached")
var ErrDeviceState = errors.New("device state does not allow this action")

// A request reserves a local device slot. It does not provision server access.
type DeviceRequest struct {
	RequestID string `json:"request_id"`
	Name      string `json:"name"`
	OS        string `json:"os"`
}
type DeviceQuota struct {
	Limit     int `json:"limit"`
	Used      int `json:"used"`
	Remaining int `json:"remaining"`
}

func DeviceName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 64 {
		return "", ErrDeviceInput
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", ErrDeviceInput
		}
	}
	return name, nil
}
func (r DeviceRequest) Validate() (DeviceRequest, []byte, error) {
	name, e := DeviceName(r.Name)
	if e != nil {
		return r, nil, e
	}
	r.Name = name
	switch r.OS {
	case "ios", "android", "windows", "macos", "linux", "other":
	default:
		return r, nil, ErrDeviceInput
	}
	if len(r.RequestID) < 16 || len(r.RequestID) > 64 {
		return r, nil, ErrDeviceInput
	}
	for _, c := range r.RequestID {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return r, nil, ErrDeviceInput
		}
	}
	payload, _ := json.Marshal(struct{ Name, OS string }{r.Name, r.OS})
	hash := sha256.Sum256(payload)
	return r, hash[:], nil
}
