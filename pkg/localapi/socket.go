package localapi

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// Listen creates the owner-private socket.
//
// The directory is what actually restricts access, so it is created and then
// verified rather than assumed: private mode, owned by this user, and not a
// symlink to somewhere else. The socket file itself is narrowed too, which
// matters on the systems that honour socket permissions and costs nothing on
// the ones that do not.
//
// A stale socket from a process that died is removed. A live one is not: the
// directory lock the journal holds is what decides who owns this state, and
// unlinking a socket another running daemon is serving would take its callers
// away without taking its ownership.
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
