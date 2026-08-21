//go:build linux

package attachments

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// newSealedScanInput keeps decrypted content off persistent storage. The
// scanner inherits one read-only sealed memfd; it cannot modify, grow or
// shrink the bytes whose digest its verdict must bind.
func newSealedScanInput(plaintext []byte) (*os.File, error) {
	descriptor, err := unix.MemfdCreate("tos-attachment-scan", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, errors.New("create attachment scan memfd")
	}
	file := os.NewFile(uintptr(descriptor), "tos-attachment-scan")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("open attachment scan memfd")
	}
	if _, err := file.Write(plaintext); err != nil {
		_ = file.Close()
		return nil, errors.New("write attachment scan memfd")
	}
	seals := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		_ = file.Close()
		return nil, errors.New("seal attachment scan memfd")
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = file.Close()
		return nil, errors.New("rewind attachment scan memfd")
	}
	return file, nil
}
