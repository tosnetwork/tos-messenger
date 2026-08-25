// Package localwire owns the common bounded Unix-socket mechanics used by
// local authority-separated APIs. It assigns no operation permissions.
package localwire

import (
	"encoding/binary"
	"errors"
	"io"
)

const headerBytes = 4

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
