//go:build !linux

package profileobserve

import (
	"context"
	"familyvpn.local/platform/internal/profilevault"
)

func ObserveSession(context.Context, profilevault.Context, int, []byte, Target) (SessionResult, error) {
	return SessionResult{}, ErrRuntime
}
