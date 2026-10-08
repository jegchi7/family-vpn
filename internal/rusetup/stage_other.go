//go:build !linux

package rusetup

import "context"

func Stage(ctx context.Context, i Inputs) (Summary, error) {
	if ValidateInputs(i) != nil {
		return summary(false), ErrInput
	}
	return summary(false), ErrPlatform
}
func Check(ctx context.Context, native bool) (Summary, Binding, error) {
	return summary(false), Binding{}, ErrPlatform
}
