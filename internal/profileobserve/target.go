package profileobserve

import (
	"familyvpn.local/platform/internal/clientconfig"
	"familyvpn.local/platform/internal/runtimeenv"
)

// Target is independently selected inventory, never reconstructed from a Result.
// Boot/namespace identify the read location, not a core/config/client attestation.
type Target struct {
	Interface, Endpoint, ToolSHA256, BootID string
	NetNSDevice, NetNSInode                 uint64
}

func lowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validBootID(s string) bool { return runtimeenv.ValidBootID(s) }
func validInterface(s string) bool {
	if len(s) < 1 || len(s) > 15 || s[0] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func (t Target) Valid() bool {
	return validInterface(t.Interface) && clientconfig.ValidAWGEndpoint(t.Endpoint) && lowerHex(t.ToolSHA256, 64) && validBootID(t.BootID) && t.NetNSDevice > 0 && t.NetNSInode > 0
}
func (t Target) validSnapshot() bool {
	return t.Interface == "" && t.ToolSHA256 == "" && t.BootID == "" && t.NetNSDevice == 0 && t.NetNSInode == 0 && clientconfig.ValidAWGEndpoint(t.Endpoint)
}
