// Package runtimeenv identifies a read location, never a responding core or client.
package runtimeenv

import (
	"errors"
	"strings"
)

var ErrScope = errors.New("runtime environment unavailable or changed")

// Scope comes from independently selected current inventory. It is comparable
// and carries no permission. Current observations never choose expected values.
type Scope struct {
	BootID                  string
	NetNSDevice, NetNSInode uint64
}

func ValidBootID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	raw := strings.ReplaceAll(s, "-", "")
	if len(raw) != 32 || raw == strings.Repeat("0", 32) {
		return false
	}
	for _, c := range raw {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (s Scope) Valid() bool { return ValidBootID(s.BootID) && s.NetNSDevice > 0 && s.NetNSInode > 0 }
