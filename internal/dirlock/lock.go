// Package dirlock gives one process exclusive ownership of one private local
// state directory.
//
// The Messenger runs a single writer per state directory. This is an
// operational consistency boundary, not a security boundary: it is not a
// substitute for filesystem permissions and it does not defend against a
// hostile process running as the same user.
package dirlock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// MaxNameBytes bounds the lock file name.
const MaxNameBytes = 128

// ErrHeld reports that another process already owns the directory.
var ErrHeld = errors.New("private directory is already owned")

// Lock is an acquired ownership handle.
type Lock struct {
	mu     sync.Mutex
	file   *os.File
	closed bool
}

// Acquire takes exclusive ownership of a directory without blocking.
func Acquire(directory string, name string) (*Lock, error) {
	if directory == "" || !filepath.IsAbs(directory) ||
		name == "" || len(name) > MaxNameBytes ||
		filepath.Base(name) != name || name == "." || name == ".." ||
		strings.IndexByte(name, filepath.Separator) >= 0 {
		return nil, errors.New("invalid directory lock configuration")
	}
	file, err := openAndLock(filepath.Join(directory, name))
	if err != nil {
		return nil, err
	}
	return &Lock{file: file}, nil
}

// Close releases ownership. It is safe to call more than once.
func (l *Lock) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	file := l.file
	l.file = nil
	if file == nil {
		return errors.New("invalid directory ownership lock")
	}
	return unlockAndClose(file)
}

// Held reports whether this handle still owns the directory.
func (l *Lock) Held() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.closed && l.file != nil
}
