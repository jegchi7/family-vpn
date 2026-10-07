//go:build !linux && !darwin

package clientconfig

import "os"

func owned(st os.FileInfo) bool { return false }
