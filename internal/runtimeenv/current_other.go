//go:build !linux

package runtimeenv

func Current() (Scope, error) { return Scope{}, ErrScope }
