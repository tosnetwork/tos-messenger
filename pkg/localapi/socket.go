package localapi

import (
	"net"

	"github.com/tosnetwork/tos-messenger/internal/localwire"
)

// PeerCheckAvailable reports whether this platform can identify the caller.
// The socket directory remains private on every platform.
const PeerCheckAvailable = localwire.PeerCheckAvailable

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
	return localwire.Listen(path)
}
