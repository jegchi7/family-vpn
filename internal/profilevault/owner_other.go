//go:build !linux && !darwin

package profilevault

import "os"

func owned(st os.FileInfo) bool { return false }
