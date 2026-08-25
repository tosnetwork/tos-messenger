//go:build !linux

package attachments

func scannerCgroupHardLimitsPresent() bool { return false }
