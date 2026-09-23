package mssql

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/microsoft/go-mssqldb/msdsn"
)

func v4TestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func v4TestListener(t *testing.T, serve func(net.Conn) error) (string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(8 * time.Second))
		done <- serve(conn)
	}()
	return ln.Addr().String(), done
}

func v4TestBackend(conn net.Conn, cert tls.Certificate, strict, rejectEncryption bool) error {
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
	if strict {
		cfg.NextProtos = []string{"tds/8.0"}
		secure := tls.Server(conn, cfg)
		if err := secure.Handshake(); err != nil {
			return err
		}
		conn = secure
	}
	_, prelogin, err := v4ReadMessage(&conn, nil, byte(packPrelogin), 65535)
	if err != nil {
		return err
	}
	fields, err := v4Prelogin(prelogin)
	if err != nil {
		return err
	}
	if fields[preloginENCRYPTION][0] != encryptOn {
		return fmt.Errorf("backend encryption not independently required")
	}
	if rejectEncryption {
		fields[preloginENCRYPTION] = []byte{encryptNotSup}
	}
	if err := writePrelogin(packReply, newTdsBuffer(defaultPacketSize, conn), fields); err != nil {
		return err
	}
	if rejectEncryption {
		var b [1]byte
		n, err := conn.Read(b[:])
		if n != 0 || err != io.EOF {
			return fmt.Errorf("credentials sent despite downgrade: %d %v", n, err)
		}
		return nil
	}
	if !strict {
		adapter := &v4TLSConn{Conn: conn}
		secure := tls.Server(adapter, cfg)
		if err := secure.Handshake(); err != nil {
			return err
		}
		adapter.raw = true
		conn = secure
	}
	_, login, err := v4ReadMessage(&conn, nil, byte(packLogin7), 128*1024-1)
	if err != nil {
		return err
	}
	if err := v4ReplacePassword(login, "backend", "backend"); err != nil {
		return fmt.Errorf("password substitution failed: %w", err)
	}
	// Minimal LOGINACK and DONE token streams understood by the actual driver.
	version := uint32(verTDS74)
	if strict {
		version = verTDS80
	}
	ack := make([]byte, 3+10)
	ack[0], ack[3] = 0xad, 1
	binary.LittleEndian.PutUint16(ack[1:], 10)
	binary.BigEndian.PutUint32(ack[4:], version)
	ack[9] = 16 // zero-length name, then product version
	// A long INFO token makes the response exceed the client's 512-byte
	// receive buffer and exercises response refragmentation.
	info := make([]byte, 3+4+1+1+2+512+1+1+4)
	info[0] = 0xab
	binary.LittleEndian.PutUint16(info[1:], uint16(len(info)-3))
	binary.LittleEndian.PutUint16(info[9:], 256)
	for i := 0; i < 256; i++ {
		binary.LittleEndian.PutUint16(info[11+i*2:], 'x')
	}
	done := make([]byte, 13)
	done[0] = 0xfd
	response := append(append(info, ack...), done...)
	if err := v4WriteMessage(conn, byte(packReply), response); err != nil {
		return err
	}
	_, query, err := v4ReadMessage(&conn, nil, byte(packSQLBatch), 65535)
	if err != nil {
		return err
	}
	if len(query) < 4 {
		return fmt.Errorf("missing SQL headers")
	}
	offset := int(binary.LittleEndian.Uint32(query))
	if offset < 4 || offset > len(query) {
		return fmt.Errorf("invalid SQL headers")
	}
	text, err := ucs22str(query[offset:])
	if err != nil || text != "select 1;" {
		return fmt.Errorf("incorrect query: %q %v", text, err)
	}
	if err := v4WriteMessage(conn, byte(packReply), done); err != nil {
		return err
	}
	// Wait until the client has consumed the reply before closing the relay.
	var b [1]byte
	_, err = conn.Read(b[:])
	if err == io.EOF {
		return nil
	}
	return err
}

func TestProxyV4DriverMatrix(t *testing.T) {
	cert := v4TestCertificate(t)
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	for _, version := range []uint16{0, tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
		for _, mode := range []msdsn.Encryption{msdsn.EncryptionOff, msdsn.EncryptionRequired, msdsn.EncryptionStrict, msdsn.EncryptionDisabled} {
			if version == tls.VersionTLS13 && mode != msdsn.EncryptionStrict {
				continue // TLS 1.3 requires TLS-first on the frontend.
			}
			if mode == msdsn.EncryptionStrict && version != 0 && version < tls.VersionTLS12 {
				continue
			}
			if mode == msdsn.EncryptionDisabled && version != 0 {
				continue
			}
			t.Run(fmt.Sprintf("TLS%x/mode%d", version, mode), func(t *testing.T) {
				backend, backendDone := v4TestListener(t, func(conn net.Conn) error { return v4TestBackend(conn, cert, mode == msdsn.EncryptionStrict, false) })
				var audit bytes.Buffer
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				addr, proxyDone := v4TestListener(t, func(conn net.Conn) error {
					return ProxyV4(ctx, backend, conn, ProxyDetails{ClientCert: cert, FrontendPassword: "frontpw", BackendPassword: "backend", Collector: &audit})
				})
				cfg, err := msdsn.Parse("sqlserver://alice:frontpw@" + addr + "?database=master")
				if err != nil {
					t.Fatal(err)
				}
				cfg.Encryption = mode
				cfg.TLSConfig = &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: version, MaxVersion: version}
				// Force LOGIN7 across packet boundaries, including the password.
				cfg.PacketSize = 512
				cfg.Workstation, cfg.AppName, cfg.Database = strings.Repeat("h", 128), strings.Repeat("a", 128), strings.Repeat("d", 128)
				db := sql.OpenDB(NewConnectorConfig(cfg))
				defer db.Close()
				if err := db.PingContext(ctx); err != nil {
					t.Fatal(err)
				}
				db.Close()
				if err := <-proxyDone; err != nil {
					t.Fatal(err)
				}
				if err := <-backendDone; err != nil {
					t.Fatal(err)
				}
				if audit.Len() == 0 || audit.Bytes()[0] != byte(packSQLBatch) {
					t.Fatal("missing query audit")
				}
				if bytes.Contains(audit.Bytes(), manglePassword("frontpw")) || bytes.Contains(audit.Bytes(), manglePassword("backend")) {
					t.Fatal("credentials leaked to audit")
				}
			})
		}
	}
}

func TestProxyV4RejectsBackendDowngrade(t *testing.T) {
	cert := v4TestCertificate(t)
	backend, backendDone := v4TestListener(t, func(conn net.Conn) error { return v4TestBackend(conn, cert, false, true) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, proxyDone := v4TestListener(t, func(conn net.Conn) error {
		return ProxyV4(ctx, backend, conn, ProxyDetails{ClientCert: cert, FrontendPassword: "frontpw", BackendPassword: "backend", Collector: io.Discard})
	})
	db, err := sql.Open("sqlserver", "sqlserver://alice:frontpw@"+addr+"?encrypt=true&trustservercertificate=true")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err == nil {
		t.Fatal("accepted backend downgrade")
	}
	if err := <-proxyDone; err == nil {
		t.Fatal("proxy accepted downgrade")
	}
	if err := <-backendDone; err != nil {
		t.Fatal(err)
	}
}

type v4BrokenAudit struct{}

func (v4BrokenAudit) Write([]byte) (int, error) { return 0, fmt.Errorf("audit unavailable") }

func TestProxyV4RejectsBadPasswordOrAuditFailure(t *testing.T) {
	for _, name := range []string{"password", "audit"} {
		t.Run(name, func(t *testing.T) {
			cert := v4TestCertificate(t)
			backend, backendDone := v4TestListener(t, func(conn net.Conn) error {
				err := v4TestBackend(conn, cert, false, false)
				if !errors.Is(err, io.EOF) {
					return fmt.Errorf("expected close before query, got %v", err)
				}
				return nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			collector := io.Writer(io.Discard)
			password := "invalid"
			if name == "audit" {
				collector, password = v4BrokenAudit{}, "frontpw"
			}
			addr, proxyDone := v4TestListener(t, func(conn net.Conn) error {
				return ProxyV4(ctx, backend, conn, ProxyDetails{ClientCert: cert, FrontendPassword: "frontpw", BackendPassword: "backend", Collector: collector})
			})
			db, err := sql.Open("sqlserver", "sqlserver://alice:"+password+"@"+addr+"?encrypt=false&trustservercertificate=true")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			err = db.PingContext(ctx)
			if err == nil {
				t.Fatal("unexpected successful query")
			}
			if name == "password" {
				var loginErr Error
				if !errors.As(err, &loginErr) || loginErr.Number != 18456 {
					t.Fatalf("expected SQL login failure 18456, got %v", err)
				}
			}
			if err := <-proxyDone; err == nil {
				t.Fatal("expected proxy error")
			}
			if err := <-backendDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProxyV4CancellationDuringLogin(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ProxyV4(ctx, "127.0.0.1:1433", server, ProxyDetails{Collector: io.Discard}) }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected cancellation error")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled login blocked")
	}
}

func TestProxyV4MalformedInput(t *testing.T) {
	for _, payload := range [][]byte{nil, {0xff}, {0, 0xff, 0xff, 0xff, 0xff, 0xff}} {
		if _, err := v4Prelogin(payload); err == nil {
			t.Fatal("accepted malformed PRELOGIN")
		}
	}
	for _, payload := range [][]byte{nil, make([]byte, 94)} {
		if err := v4ReplacePassword(payload, "frontpw", "backend"); err == nil {
			t.Fatal("accepted malformed login")
		}
	}
}
