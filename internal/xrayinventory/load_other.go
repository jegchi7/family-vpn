//go:build !linux

package xrayinventory

import "context"

func Require(context.Context, string, Expected) error { return ErrInventory }
