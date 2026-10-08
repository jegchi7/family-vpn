//go:build linux

package profileobserve

import (
	"context"
	"familyvpn.local/platform/internal/profilevault"
	"runtime"
)

// ObserveSession reads only the independently selected current namespace and
// interface. Handshake/transfer views are diagnostics, never readiness evidence.
func ObserveSession(ctx context.Context, c profilevault.Context, revision int, client []byte, target Target) (SessionResult, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return observeSession(ctx, c, revision, client, target, readNativeCommand, currentEnvironment, waitSession)
}
