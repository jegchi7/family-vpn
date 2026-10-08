//go:build !linux

package coreinstall

import "context"

func CanApply() bool                                { return false }
func VerifyInstalled(core string) (Artifact, error) { return Artifact{}, ErrPlatform }
func Install(ctx context.Context, core string) (Artifact, bool, error) {
	return Artifact{}, false, ErrPlatform
}
