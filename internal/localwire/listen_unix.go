//go:build !windows

package localwire

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// Listen creates a same-user private Unix socket without displacing a live
// listener at the requested path.
func Listen(path string) (net.Listener, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid local socket path")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, errors.New("create local socket directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("local socket directory must be private")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("local socket directory belongs to another user")
	}
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("local socket path is not a socket")
		}
		if connection, err := net.Dial("unix", path); err == nil {
			_ = connection.Close()
			return nil, errors.New("another daemon is already serving this socket")
		}
		if err := os.Remove(path); err != nil {
			return nil, errors.New("remove stale local socket")
		}
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, errors.New("listen on local socket")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		return nil, errors.New("protect local socket")
	}
	return listener, nil
}
