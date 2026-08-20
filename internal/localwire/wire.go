// Package localwire owns the common bounded Unix-socket mechanics used by
// local authority-separated APIs. It assigns no operation permissions.
package localwire

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

const headerBytes = 4

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

// Frame prefixes one bounded non-empty JSON body.
func Frame(body []byte, maximum uint32) ([]byte, error) {
	if len(body) == 0 {
		return nil, errors.New("empty frame")
	}
	if len(body) > int(maximum) {
		return nil, errors.New("frame exceeds its bound")
	}
	out := make([]byte, headerBytes, headerBytes+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	return append(out, body...), nil
}

// ReadFrame checks the declared bound before allocating its body.
func ReadFrame(reader io.Reader, maximum uint32) ([]byte, error) {
	var header [headerBytes]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 {
		return nil, errors.New("empty frame")
	}
	if length > maximum {
		return nil, errors.New("frame exceeds its bound")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return body, nil
}

// WriteFrame writes one complete bounded frame.
func WriteFrame(writer io.Writer, body []byte, maximum uint32) error {
	framed, err := Frame(body, maximum)
	if err != nil {
		return err
	}
	for len(framed) > 0 {
		written, err := writer.Write(framed)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(framed) {
			return io.ErrShortWrite
		}
		framed = framed[written:]
	}
	return nil
}
