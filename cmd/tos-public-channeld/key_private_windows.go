//go:build windows

package main

import "os"

func transportKeyFileIsPrivate(info os.FileInfo) bool {
	// Windows ACL validation is performed by the securefile reader and operator
	// preflight; here we additionally reject directories and reparse-point
	// symlinks before any key bytes are parsed.
	return info != nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}
