//go:build !linux

package foreignsetup

import "context"

func Stage(ctx context.Context, i Inputs) (Summary, error) {
	if ValidateInputs(i) != nil {
		return safeSummary(false), ErrInput
	}
	return safeSummary(false), ErrPlatform
}
func Check(ctx context.Context, native bool) (Summary, error) {
	return safeSummary(false), ErrPlatform
}
