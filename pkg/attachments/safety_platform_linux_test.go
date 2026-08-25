//go:build linux

package attachments

import (
	"bytes"
	"os"
	"syscall"
)

func scannerCgroupHardLimitsPresent() bool {
	membership, err := os.ReadFile("/proc/self/cgroup")
	var core syscall.Rlimit
	coreErr := syscall.Getrlimit(syscall.RLIMIT_CORE, &core)
	return err == nil && coreErr == nil && bytes.Contains(membership, []byte("/tos-attachment-scan-")) && core.Cur == 0
}
