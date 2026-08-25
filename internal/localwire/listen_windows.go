//go:build windows

package localwire

import (
	"errors"
	"net"
)

// Listen remains Unix-domain-socket-specific. Windows deployments must select
// an authenticated named-pipe transport instead of silently exposing TCP.
func Listen(string) (net.Listener, error) {
	return nil, errors.New("Unix local authority sockets are unavailable on Windows; configure the named-pipe transport")
}
