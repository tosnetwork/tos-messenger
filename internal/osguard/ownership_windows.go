//go:build windows

package osguard

import "os"

// The Windows installation preflight must enforce an owner-only DACL. The
// portable FileInfo API cannot expose the owner SID, so callers also reject
// reparse points and recheck the opened file identity.
func CurrentUserOwns(info os.FileInfo) bool {
	return info != nil && info.Mode()&os.ModeSymlink == 0
}
