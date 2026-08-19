//go:build !linux

package localapi

import "net"

// PeerCheckAvailable reports whether this platform can identify the caller.
//
// Where it is false the socket's private directory is the only barrier, which
// is a real barrier and a weaker one: it depends on a mode that packaging can
// widen. A deployment on such a platform should know that rather than assume
// the check is happening.
const PeerCheckAvailable = false

func verifyPeer(net.Conn) error { return nil }
