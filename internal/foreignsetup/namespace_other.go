//go:build !linux

package foreignsetup

import "context"

func ReadNamespaceIPv4Config(ctx context.Context) ([]byte, IPv4Binding, error) {
	return nil, IPv4Binding{}, ErrPlatform
}
