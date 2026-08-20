//go:build !linux

package localwire

import "net"

// PeerCheckAvailable reports whether this platform identifies Unix peers.
const PeerCheckAvailable = false

// VerifyPeer relies on the private socket directory where peer credentials
// are unavailable.
func VerifyPeer(net.Conn) error { return nil }
