//go:build linux

package localwire

import (
	"errors"
	"net"
	"os"
	"syscall"
)

// PeerCheckAvailable reports whether this platform identifies Unix peers.
const PeerCheckAvailable = true

// VerifyPeer refuses a connection from another local user.
func VerifyPeer(connection net.Conn) error {
	unixConn, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("local API serves unix sockets only")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return errors.New("inspect local peer")
	}
	var credentials *syscall.Ucred
	var credentialsErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, credentialsErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return errors.New("inspect local peer")
	}
	if credentialsErr != nil || credentials == nil {
		return errors.New("local peer could not be identified")
	}
	if credentials.Uid != uint32(os.Geteuid()) {
		return errors.New("local peer belongs to another user")
	}
	return nil
}
