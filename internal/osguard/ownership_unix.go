//go:build !windows

package osguard

import (
	"os"
	"syscall"
)

func CurrentUserOwns(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
