//go:build !linux && !darwin

package adminauth

import "os"

func owned(st os.FileInfo) bool { return false }
