package mssql

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type v4PrefixConn struct {
	net.Conn
	reader io.Reader
}

func (c *v4PrefixConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func v4ReadPacket(r io.Reader) (kind, status byte, payload []byte, err error) {
	var header [8]byte
	if _, err = io.ReadFull(r, header[:]); err != nil {
		return
	}
	kind, status = header[0], header[1]
	size := int(binary.BigEndian.Uint16(header[2:]))
	if size < 8 {
		err = fmt.Errorf("invalid TDS packet length %d", size)
		return
	}
	payload = make([]byte, size-8)
	_, err = io.ReadFull(r, payload)
	return
}

func v4ReadMessage(conn *net.Conn, afterFirst net.Conn, expected byte, limit int) (byte, []byte, error) {
	var message []byte
	for first := true; ; first = false {
		kind, status, payload, err := v4ReadPacket(*conn)
		if err != nil {
			return 0, nil, err
		}
		if kind != expected {
			return 0, nil, fmt.Errorf("expected TDS packet 0x%02x, got 0x%02x", expected, kind)
		}
		if len(message)+len(payload) > limit {
			return 0, nil, fmt.Errorf("TDS message exceeds %d bytes", limit)
		}
		if len(payload) == 0 && status&1 == 0 {
			return 0, nil, fmt.Errorf("empty TDS continuation")
		}
		message = append(message, payload...)
		if first && afterFirst != nil {
			*conn = afterFirst
		}
		if status&1 != 0 {
			return kind, message, nil
		}
	}
}

func v4WriteMessage(w io.Writer, kind byte, payload []byte) error {
	return v4WriteMessageSize(w, kind, payload, 4096)
}

func v4WriteMessageSize(w io.Writer, kind byte, payload []byte, packetSize int) error {
	for seq := byte(1); ; seq++ {
		n := len(payload)
		if n > packetSize-8 {
			n = packetSize - 8
		}
		packet := make([]byte, 8+n)
		packet[0], packet[6] = kind, seq
		if n == len(payload) {
			packet[1] = 1
		}
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
		copy(packet[8:], payload[:n])
		written, err := w.Write(packet)
		if err != nil {
			return err
		}
		if written != len(packet) {
			return io.ErrShortWrite
		}
		payload = payload[n:]
		if len(payload) == 0 {
			return nil
		}
	}
}

// v4TLSConn wraps handshake flights in PRELOGIN packets, then carries raw TLS
// records. Raw reads are bounded to one record to keep crypto/tls read-ahead
// from consuming the plaintext continuation of a login-only LOGIN7 message.
type v4TLSConn struct {
	net.Conn
	pending         bytes.Buffer
	raw             bool
	recordRemaining int
}

func (c *v4TLSConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.pending.Len() > 0 {
		return c.pending.Read(b)
	}
	if !c.raw {
		kind, _, payload, err := v4ReadPacket(c.Conn)
		if err != nil {
			return 0, err
		}
		if (kind != byte(packPrelogin) && kind != byte(packReply)) || len(payload) == 0 {
			return 0, fmt.Errorf("invalid wrapped TLS packet")
		}
		c.pending.Write(payload)
		return c.pending.Read(b)
	}
	if c.recordRemaining == 0 {
		var header [5]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		if header[0] < 0x14 || header[0] > 0x17 {
			return 0, fmt.Errorf("invalid TLS record type")
		}
		c.recordRemaining = int(binary.BigEndian.Uint16(header[3:]))
		if c.recordRemaining > 18432 {
			return 0, fmt.Errorf("oversized TLS record")
		}
		c.pending.Write(header[:])
		return c.pending.Read(b)
	}
	if len(b) > c.recordRemaining {
		b = b[:c.recordRemaining]
	}
	n, err := c.Conn.Read(b)
	c.recordRemaining -= n
	return n, err
}

func (c *v4TLSConn) Write(b []byte) (int, error) {
	if c.raw {
		return c.Conn.Write(b)
	}
	// PRELOGIN does not advertise the client's packet size. Use the minimum
	// supported packet size so drivers with 512-byte receive buffers work.
	if err := v4WriteMessageSize(c.Conn, byte(packPrelogin), b, 512); err != nil {
		return 0, err
	}
	return len(b), nil
}
