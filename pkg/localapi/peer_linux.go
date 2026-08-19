//go:build linux

package localapi

import (
	"errors"
	"net"
	"os"
	"syscall"
)

// PeerCheckAvailable reports whether this platform can identify the caller.
const PeerCheckAvailable = true

// verifyPeer refuses a connection from another user.
//
// The socket's directory already restricts who can reach it. This is the
// second answer to the same question, and it is worth having because the first
// one depends on a directory mode that a packaging mistake or a helpful
// installer can widen without anyone noticing.
func verifyPeer(connection net.Conn) error {
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
