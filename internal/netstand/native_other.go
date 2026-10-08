//go:build !linux

package netstand

import (
	"context"
	"familyvpn.local/platform/internal/netguard"
	"os"
)

func Prepare(context.Context, netguard.Inputs, Target) (Summary, error) {
	return Summary{}, ErrPlatform
}
func Check(context.Context) (Summary, error) { return Summary{}, ErrPlatform }

// Native network mutation is unavailable outside the Linux operator CLI.
func Apply(context.Context, netguard.Inputs, Target) (Summary, error) { return Summary{}, ErrPlatform }
func Verify(context.Context, netguard.Inputs, Target) (Proof, Summary, error) {
	return Proof{}, Summary{}, ErrPlatform
}
func (p Proof) OpenNamespace(netguard.Inputs, Target) (*os.File, error) { return nil, ErrPlatform }
