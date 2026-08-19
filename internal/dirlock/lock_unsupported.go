//go:build !linux && !darwin

package dirlock

import (
	"errors"
	"os"
)

// openAndLock fails closed on platforms without a verified exclusive-lock
// implementation. A single-writer store that cannot prove single writership
// must refuse to open rather than pretend.
func openAndLock(string) (*os.File, error) {
	return nil, errors.New("private directory ownership is unsupported on this platform")
}

func unlockAndClose(*os.File) error {
	return errors.New("private directory ownership is unsupported on this platform")
}
