//go:build linux || darwin

package adminauth

import (
	"os"
	"syscall"
)

func owned(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid())
}
