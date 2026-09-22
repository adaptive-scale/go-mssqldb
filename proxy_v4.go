package mssql

// V4 is deliberately separate from OpenProxy/internalConnectProxy. Nothing in
// the legacy SQL proxy or database/sql driver opts into these transport rules.

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// ProxyV4 terminates a SQL-authenticated frontend and substitutes its password
// before forwarding to the V4 pod through Adaptive's authenticated local tunnel.
// The caller owns the frontend certificate and audit collector. This function
// owns both connections until return. It never records PRELOGIN/LOGIN credentials.
// TLS-first clients stay TLS-first upstream; all upstream sessions are encrypted,
// independently of the client's Optional/Mandatory/no-TLS choice.
func ProxyV4(ctx context.Context, backendAddress string, client net.Conn, details ProxyDetails) error {
	defer client.Close()
	host, _, err := net.SplitHostPort(backendAddress)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("V4 backend must be a loopback tunnel address")
	}
	if details.Collector == nil {
		return fmt.Errorf("V4 audit collector is required")
	}
	deadline := time.Now().Add(30 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	client.SetDeadline(deadline)
	stopClient := context.AfterFunc(ctx, func() { client.Close() })
	defer stopClient()

	var initial [1]byte
	if _, err := io.ReadFull(client, initial[:]); err != nil {
		return err
	}
	front := net.Conn(&v4PrefixConn{Conn: client, reader: io.MultiReader(bytes.NewReader(initial[:]), client)})
	tlsFirst := initial[0] == 0x16
	frontConfig := &tls.Config{Certificates: []tls.Certificate{details.ClientCert}, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	if tlsFirst {
		frontConfig.MinVersion = tls.VersionTLS12
		frontConfig.NextProtos = []string{"tds/8.0"}
		secure := tls.Server(front, frontConfig)
		if err := secure.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("V4 frontend TLS: %w", err)
		}
		front = secure
	} else if initial[0] != byte(packPrelogin) {
		return fmt.Errorf("V4 expected PRELOGIN or TLS ClientHello")
	} else {
		// Older clients (e.g. upstream go-mssqldb 1.9.2 in sqlcmd) do not
		// flush their final wrapped handshake flight under TLS 1.3. Use
		// TLS <=1.2 for TDS 7.x; TLS-first/TDS 8.0 retains TLS 1.3.
		frontConfig.MaxVersion = tls.VersionTLS12
	}
	_, request, err := v4ReadMessage(&front, nil, byte(packPrelogin), 65535)
	if err != nil {
		return err
	}
	fields, err := v4Prelogin(request)
	if err != nil {
		return err
	}
	clientEncryption := fields[preloginENCRYPTION][0]
	responseEncryption := byte(encryptOn)
	if !tlsFirst {
		switch clientEncryption {
		case encryptOff, encryptNotSup:
			responseEncryption = clientEncryption
		case encryptOn, encryptReq:
		default:
			return fmt.Errorf("V4 unsupported client encryption value 0x%02x", clientEncryption)
		}
	}

	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	backend, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", backendAddress)
	if err != nil {
		return fmt.Errorf("V4 tunnel dial: %w", err)
	}
	defer backend.Close()
	backend.SetDeadline(deadline)
	stopBackend := context.AfterFunc(ctx, func() { backend.Close() })
	defer stopBackend()
	upstream := net.Conn(backend)
	// The backend is the loopback end of Adaptive's authenticated tunnel, not a
	// remote SQL Server. The V4 pod uses a self-signed certificate, like V3.
	backConfig := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS13}
	if tlsFirst {
		backConfig.MinVersion = tls.VersionTLS12
		backConfig.NextProtos = []string{"tds/8.0"}
		secure := tls.Client(upstream, backConfig)
		if err := secure.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("V4 upstream TLS: %w", err)
		}
		if secure.ConnectionState().NegotiatedProtocol != "tds/8.0" {
			return fmt.Errorf("V4 upstream did not negotiate TDS 8.0")
		}
		upstream = secure
	}
	fields[preloginENCRYPTION] = []byte{encryptOn}
	if err := writePrelogin(packPrelogin, newTdsBuffer(defaultPacketSize, upstream), fields); err != nil {
		return err
	}
	_, reply, err := v4ReadMessage(&upstream, nil, byte(packReply), 65535)
	if err != nil {
		return err
	}
	responseFields, err := v4Prelogin(reply)
	if err != nil {
		return err
	}
	if !tlsFirst {
		encryption := responseFields[preloginENCRYPTION][0]
		if encryption != encryptOn && encryption != encryptReq {
			return fmt.Errorf("V4 upstream refused required encryption")
		}
	}
	responseFields[preloginENCRYPTION] = []byte{responseEncryption}
	if err := writePrelogin(packReply, newTdsBuffer(defaultPacketSize, front), responseFields); err != nil {
		return err
	}
	if !tlsFirst {
		adapter := &v4TLSConn{Conn: upstream}
		secure := tls.Client(adapter, backConfig)
		if err := secure.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("V4 upstream wrapped TLS: %w", err)
		}
		adapter.raw = true
		upstream = secure
		if responseEncryption != encryptNotSup {
			adapter := &v4TLSConn{Conn: front}
			secure := tls.Server(adapter, frontConfig)
			if err := secure.HandshakeContext(ctx); err != nil {
				return fmt.Errorf("V4 frontend wrapped TLS: %w", err)
			}
			adapter.raw = true
			front = secure
		}
	}
	var afterFirst net.Conn
	if !tlsFirst && responseEncryption == encryptOff {
		afterFirst = client
	}
	_, login, err := v4ReadMessage(&front, afterFirst, byte(packLogin7), 128*1024-1)
	if err != nil {
		return err
	}
	if err := v4ReplacePassword(login, details.FrontendPassword, details.BackendPassword); err != nil {
		// The response uses the current transport, plaintext for login-only.
		_ = v4WriteLoginError(front)
		return fmt.Errorf("V4 login rejected: %w", err)
	}
	if err := v4WriteMessage(upstream, byte(packLogin7), login); err != nil {
		return err
	}
	_, loginResponse, err := v4ReadMessage(&upstream, nil, byte(packReply), 1024*1024)
	if err != nil {
		return fmt.Errorf("V4 upstream login response: %w", err)
	}
	// The client's LOGIN7 can request a 512-byte receive buffer. Refragment
	// the assembled response conservatively before entering the opaque relay.
	if err := v4WriteMessageSize(front, byte(packReply), loginResponse, 512); err != nil {
		return err
	}
	client.SetDeadline(time.Time{})
	backend.SetDeadline(time.Time{})

	// Forward the upstream login response unchanged. Do not synthesize success.
	// The audit stream starts AFTER LOGIN7 and retains the old raw-TDS format.
	// Audit before forwarding so a collector failure cannot silently bypass it.
	done := make(chan error, 2)
	go func() { _, err := io.Copy(io.MultiWriter(details.Collector, upstream), front); done <- err }()
	go func() { _, err := io.Copy(front, upstream); done <- err }()
	firstErr := <-done
	client.Close()
	backend.Close()
	<-done // join both relay goroutines, including on EOF/cancellation
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(firstErr, net.ErrClosed) {
		return nil
	}
	return firstErr
}

func v4WriteLoginError(w io.Writer) error {
	message := str2ucs2("Login failed.")
	// ERROR: number/state/class/message, empty server/procedure, line number.
	token := make([]byte, 3+14+len(message))
	token[0] = 0xaa
	binary.LittleEndian.PutUint16(token[1:], uint16(len(token)-3))
	binary.LittleEndian.PutUint32(token[3:], 18456)
	token[7], token[8] = 1, 14
	binary.LittleEndian.PutUint16(token[9:], uint16(len(message)/2))
	copy(token[11:], message)
	done := make([]byte, 13)
	done[0], done[1] = 0xfd, 2 // DONE_ERROR, no row count
	return v4WriteMessage(w, byte(packReply), append(token, done...))
}

func v4ReplacePassword(login []byte, expected, replacement string) error {
	if len(login) < 94 || int(binary.LittleEndian.Uint32(login)) != len(login) {
		return fmt.Errorf("invalid LOGIN7 length")
	}
	// This entry point supports SQL authentication only, never SSPI/password change.
	if login[25]&0x80 != 0 || login[27]&1 != 0 {
		return fmt.Errorf("unsupported authentication mode")
	}
	offset := int(binary.LittleEndian.Uint16(login[44:]))
	length := int(binary.LittleEndian.Uint16(login[46:])) * 2
	if offset < 94 || length == 0 || length > 256 || offset+length > len(login) {
		return fmt.Errorf("invalid password bounds")
	}
	// Reject federated authentication rather than silently downgrading it to
	// SQL auth. Other bounded feature extensions remain untouched for the pod.
	if login[27]&0x10 != 0 {
		ext := int(binary.LittleEndian.Uint16(login[56:]))
		extLen := int(binary.LittleEndian.Uint16(login[58:]))
		if ext < 94 || extLen < 4 || ext+extLen > len(login) {
			return fmt.Errorf("invalid extension bounds")
		}
		pos := int(binary.LittleEndian.Uint32(login[ext:]))
		if pos < 94 || pos >= len(login) {
			return fmt.Errorf("invalid feature pointer")
		}
		for {
			if pos >= len(login) {
				return fmt.Errorf("missing feature terminator")
			}
			id := login[pos]
			if id == 0xff {
				break
			}
			if pos+5 > len(login) {
				return fmt.Errorf("truncated feature header")
			}
			size := uint64(binary.LittleEndian.Uint32(login[pos+1:]))
			if size > uint64(len(login)-pos-5) {
				return fmt.Errorf("invalid feature length")
			}
			if id == 2 {
				return fmt.Errorf("federated authentication is not supported")
			}
			pos += 5 + int(size)
		}
	}
	encodedExpected := manglePassword(expected)
	if subtle.ConstantTimeCompare(login[offset:offset+length], encodedExpected) != 1 {
		return fmt.Errorf("invalid password")
	}
	encodedReplacement := manglePassword(replacement)
	// Adaptive's password combo preserves length. Reject otherwise rather than
	// shifting LOGIN7 offsets or corrupting feature extensions.
	if len(encodedReplacement) != length {
		return fmt.Errorf("replacement password length mismatch")
	}
	copy(login[offset:offset+length], encodedReplacement)
	return nil
}

// v4Prelogin parses bounded option offsets without the legacy uint16 addition
// overflow. Unknown options are preserved when forwarding to the V4 endpoint.
func v4Prelogin(payload []byte) (map[byte][]byte, error) {
	if len(payload) < 6 || payload[0] != preloginVERSION {
		return nil, fmt.Errorf("VERSION must be first")
	}
	fields := make(map[byte][]byte)
	type option struct {
		token          byte
		offset, length int
	}
	var options []option
	pos := 0
	for {
		if pos >= len(payload) {
			return nil, fmt.Errorf("missing PRELOGIN terminator")
		}
		token := payload[pos]
		if token == 0xff {
			pos++
			break
		}
		if pos+5 > len(payload) {
			return nil, fmt.Errorf("truncated PRELOGIN option")
		}
		if _, exists := fields[token]; exists {
			return nil, fmt.Errorf("duplicate PRELOGIN option")
		}
		fields[token] = nil
		options = append(options, option{token, int(binary.BigEndian.Uint16(payload[pos+1:])), int(binary.BigEndian.Uint16(payload[pos+3:]))})
		pos += 5
	}
	encodedSize := pos
	for _, opt := range options {
		encodedSize += opt.length
		if encodedSize > 65535 {
			return nil, fmt.Errorf("PRELOGIN options exceed offset range")
		}
		if opt.offset < pos || opt.offset+opt.length > len(payload) {
			return nil, fmt.Errorf("invalid PRELOGIN bounds")
		}
		fields[opt.token] = payload[opt.offset : opt.offset+opt.length]
	}
	if len(fields[preloginVERSION]) != 6 || len(fields[preloginENCRYPTION]) != 1 {
		return nil, fmt.Errorf("invalid PRELOGIN version/encryption")
	}
	return fields, nil
}
