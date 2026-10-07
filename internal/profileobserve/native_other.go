//go:build !linux

package profileobserve

import (
	"context"
	"familyvpn.local/platform/internal/profilevault"
)

func Observe(context.Context, profilevault.Context, int, []byte, Target) (Result, error) {
	return Result{}, ErrRuntime
}
