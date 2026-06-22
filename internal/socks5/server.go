// Package socks5 implements a minimal SOCKS5 server that bridges inbound
// TCP connections through a tunnel.Client.
//
// Only the CONNECT command is supported — that is all modern browsers and
// CLI tools actually use. BIND and UDP ASSOCIATE are intentionally not
// implemented.
//
// Authentication is "NO AUTHENTICATION REQUIRED" — the SOCKS5 listener
// should only be bound to 127.0.0.1 in production. If you need to expose
// it on a LAN, put an SSH tunnel or a real auth scheme in front.
package socks5

import (
        "context"
        "encoding/binary"
        "errors"
        "fmt"
        "io"
        "log/slog"
        "net"
        "strconv"
        "time"

        "github.com/sodas-cheddar/smtp-tunnel-go/internal/tunnel"
)

// SOCKS5 protocol constants (RFC 1928).
const (
        ver5        = 0x05
        authNone    = 0x00
        cmdConnect  = 0x01
        atypIPv4    = 0x01
        atypDomain  = 0x03
        atypIPv6    = 0x04
        repSuccess  = 0x00
        repFailure  = 0x01
        repCmdNotSupp = 0x07
        repAddrNotSupp = 0x08
)

// ServerOptions tunes the SOCKS5 listener.
type ServerOptions struct {
        // Host / Port to listen on. Default 127.0.0.1:1080.
        Host string
        Port int
        // ReadTimeout is the deadline for SOCKS5 handshake reads. After the
        // handshake, the connection is left without deadlines (tunnel data
        // may be sparse). Default 30s.
        ReadTimeout time.Duration
        // Logger receives structured log events.
        Logger *slog.Logger
}

func (o *ServerOptions) defaults() {
        if o.Host == "" {
                o.Host = "127.0.0.1"
        }
        if o.Port == 0 {
                o.Port = 1080
        }
        if o.ReadTimeout <= 0 {
                o.ReadTimeout = 30 * time.Second
        }
        if o.Logger == nil {
                o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
        }
}

// Server is a SOCKS5 listener that bridges each accepted connection
// through a tunnel.Client.
type Server struct {
        opts   ServerOptions
        log    *slog.Logger
        client *tunnel.Client

        listener net.Listener
}

// New constructs a SOCKS5 server. It does NOT start listening — call
// Start.
func New(client *tunnel.Client, opts ServerOptions) *Server {
        opts.defaults()
        return &Server{
                opts:   opts,
                log:    opts.Logger,
                client: client,
        }
}

// Start begins listening and accepting SOCKS5 connections. It blocks
// until ctx is cancelled. The listener is closed on return.
func (s *Server) Start(ctx context.Context) error {
        addr := net.JoinHostPort(s.opts.Host, strconv.Itoa(s.opts.Port))
        lc := net.ListenConfig{
                Control: controlFunc, // SO_REUSEADDR on Unix; no-op on Windows.
        }
        ln, err := lc.Listen(ctx, "tcp", addr)
        if err != nil {
                return fmt.Errorf("socks5: listen on %s: %w", addr, err)
        }
        s.listener = ln
        s.log.Info("socks5 proxy listening", "addr", addr)

        go func() {
                <-ctx.Done()
                _ = ln.Close()
        }()

        for {
                conn, err := ln.Accept()
                if err != nil {
                        if ctx.Err() != nil {
                                return nil
                        }
                        if errors.Is(err, net.ErrClosed) {
                                return nil
                        }
                        s.log.Info("accept failed", "err", err)
                        continue
                }
                if tcp, ok := conn.(*net.TCPConn); ok {
                        _ = tcp.SetNoDelay(true)
                        _ = tcp.SetKeepAlive(true)
                        _ = tcp.SetKeepAlivePeriod(30 * time.Second)
                }
                go s.handle(ctx, conn)
        }
}

// handle services one SOCKS5 client connection.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
        defer func() {
                _ = conn.Close()
        }()

        if s.client.Closed() {
                // Tunnel is down — fail fast so the client retries quickly.
                s.log.Debug("socks5 conn refused: tunnel down")
                return
        }

        // --- SOCKS5 handshake ---
        _ = conn.SetReadDeadline(time.Now().Add(s.opts.ReadTimeout))
        defer conn.SetReadDeadline(time.Time{})

        // 1. Greeting: VER, NMETHODS, METHODS...
        hdr := make([]byte, 2)
        if _, err := io.ReadFull(conn, hdr); err != nil {
                return
        }
        if hdr[0] != ver5 {
                return
        }
        nMethods := int(hdr[1])
        if nMethods == 0 {
                return
        }
        methods := make([]byte, nMethods)
        if _, err := io.ReadFull(conn, methods); err != nil {
                return
        }
        // Reply: no auth.
        if _, err := conn.Write([]byte{ver5, authNone}); err != nil {
                return
        }

        // 2. Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
        reqHdr := make([]byte, 4)
        if _, err := io.ReadFull(conn, reqHdr); err != nil {
                return
        }
        ver, cmd, _ /* rsv */, atyp := reqHdr[0], reqHdr[1], reqHdr[2], reqHdr[3]
        if ver != ver5 {
                return
        }
        if cmd != cmdConnect {
                // Command not supported.
                _, _ = conn.Write([]byte{ver5, repCmdNotSupp, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
                return
        }

        var host string
        switch atyp {
        case atypIPv4:
                buf := make([]byte, 4)
                if _, err := io.ReadFull(conn, buf); err != nil {
                        return
                }
                host = net.IP(buf).String()
        case atypDomain:
                lenBuf := make([]byte, 1)
                if _, err := io.ReadFull(conn, lenBuf); err != nil {
                        return
                }
                l := int(lenBuf[0])
                buf := make([]byte, l)
                if _, err := io.ReadFull(conn, buf); err != nil {
                        return
                }
                host = string(buf)
        case atypIPv6:
                buf := make([]byte, 16)
                if _, err := io.ReadFull(conn, buf); err != nil {
                        return
                }
                host = net.IP(buf).String()
        default:
                _, _ = conn.Write([]byte{ver5, repAddrNotSupp, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
                return
        }

        portBuf := make([]byte, 2)
        if _, err := io.ReadFull(conn, portBuf); err != nil {
                return
        }
        port := binary.BigEndian.Uint16(portBuf)

        // 3. Open a tunnel channel.
        ch, err := s.client.OpenChannel(host, port)
        if err != nil {
                s.log.Info("tunnel connect failed",
                        "host", host, "port", port, "err", err)
                _, _ = conn.Write([]byte{ver5, repFailure, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
                return
        }

        // 4. Register the SOCKS5 conn with the channel and start pumping.
        if !s.client.RegisterChannel(ch, conn) {
                s.log.Info("register channel failed",
                        "host", host, "port", port, "ch", ch.ID())
                _, _ = conn.Write([]byte{ver5, repFailure, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
                return
        }

        // 5. Reply success.
        if _, err := conn.Write([]byte{ver5, repSuccess, 0, atypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
                ch.Close()
                return
        }

        s.log.Info("connect",
                "host", host, "port", port, "ch", ch.ID())

        // 6. Block until the channel is closed. The channel's reader goroutine
        // pumps SOCKS5 -> tunnel; the read pump in tunnel.Client pumps
        // tunnel -> SOCKS5 conn.
        ch.Start()
        ch.Wait()
        s.log.Debug("channel closed", "ch", ch.ID(), "host", host, "port", port)
}
