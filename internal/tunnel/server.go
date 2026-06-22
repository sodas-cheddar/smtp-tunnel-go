package tunnel

import (
        "context"
        "crypto/tls"
        "errors"
        "fmt"
        "io"
        "log/slog"
        "net"
        "strings"
        "time"

        "github.com/sodas-cheddar/smtp-tunnel-go/internal/auth"
        "github.com/sodas-cheddar/smtp-tunnel-go/internal/config"
        "github.com/sodas-cheddar/smtp-tunnel-go/internal/ipwhitelist"
        "github.com/sodas-cheddar/smtp-tunnel-go/internal/protocol"
        "github.com/sodas-cheddar/smtp-tunnel-go/internal/smtp"
)

// ServerOptions tunes the server-side tunnel session.
type ServerOptions struct {
        // ConnectTimeout is how long the server will wait when dialing a
        // destination host on behalf of a CONNECT frame. Default 30s.
        ConnectTimeout time.Duration
        // SendQueueSize is the depth of the per-session outbound frame
        // queue. Default 1024.
        SendQueueSize int
        // ReadBufferSize / WriteBufferSize set the TCP buffer sizes on
        // dialed connections. 0 = use system default.
        ReadBufferSize  int
        WriteBufferSize int
        // Logger receives structured log events.
        Logger *slog.Logger
}

func (o *ServerOptions) defaults() {
        if o.ConnectTimeout <= 0 {
                o.ConnectTimeout = 30 * time.Second
        }
        if o.SendQueueSize <= 0 {
                o.SendQueueSize = 1024
        }
        if o.Logger == nil {
                o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
        }
}

// ServerSession handles one inbound tunnel client connection on the
// server side. Its lifecycle:
//
//  1. RunSMTPHandshake — exchange EHLO/STARTTLS/AUTH/BINARY with the
//     client. On failure the connection is closed and Run returns.
//  2. readPump — read frames and dispatch to channel handlers.
//  3. writePump (started in common) — batch-send outbound frames.
//
// The session ends when the read pump exits (peer closed or fatal
// error). All channels are then torn down.
type ServerSession struct {
        conn   net.Conn
        lr     *smtp.LineReader
        lw     *smtp.LineWriter
        tlsCfg *tls.Config
        users  map[string]*config.UserConfig
        opts   ServerOptions
        log    *slog.Logger

        // Populated after auth.
        username   string
        userCfg    *config.UserConfig
        clientIP   string
        clientPeer string

        // Populated after entering binary mode.
        *common
}

// NewServerSession constructs a session for an accepted connection.
// conn should be the raw TCP conn — TLS is applied during the handshake.
func NewServerSession(conn net.Conn, tlsCfg *tls.Config, users map[string]*config.UserConfig, opts ServerOptions) *ServerSession {
        opts.defaults()
        s := &ServerSession{
                conn:   conn,
                lr:     smtp.NewLineReader(conn),
                lw:     smtp.NewLineWriter(conn),
                tlsCfg: tlsCfg,
                users:  users,
                opts:   opts,
                log:    opts.Logger,
        }
        if tcp, ok := conn.(*net.TCPConn); ok {
                _ = tcp.SetNoDelay(true)
                _ = tcp.SetKeepAlive(true)
                _ = tcp.SetKeepAlivePeriod(30 * time.Second)
                if opts.ReadBufferSize > 0 {
                        _ = tcp.SetReadBuffer(opts.ReadBufferSize)
                }
                if opts.WriteBufferSize > 0 {
                        _ = tcp.SetWriteBuffer(opts.WriteBufferSize)
                }
        }
        if peer, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
                s.clientIP = peer.IP.String()
                s.clientPeer = peer.String()
        } else {
                s.clientPeer = conn.RemoteAddr().String()
                s.clientIP = s.clientPeer
        }
        return s
}

// Run executes the full session lifecycle. It does not return until the
// connection has been fully torn down.
func (s *ServerSession) Run(parentCtx context.Context) {
        s.log.Info("connection accepted", "peer", s.clientPeer)

        // Apply a per-line deadline during the handshake.
        if err := s.conn.SetReadDeadline(time.Now().Add(2 * time.Minute)); err != nil {
                s.log.Debug("set deadline failed", "err", err)
        }

        if !s.runSMTPHandshake() {
                _ = s.conn.Close()
                return
        }

        // Clear the handshake deadline; binary mode uses its own keepalive.
        _ = s.conn.SetReadDeadline(time.Time{})

        s.log.Info("binary mode active",
                "user", s.username,
                "peer", s.clientPeer)

        // Set up the tunnel common state.
        rd := protocol.NewReader(s.conn)
        wr := protocol.NewWriter(s.conn)
        s.common = newCommon(DirServer, rd, wr, parentCtx, s.opts.SendQueueSize)

        // Start the write pump.
        go s.writePump()

        // Start a keepalive watchdog.
        go s.keepaliveWatchdog()

        // Run the read pump on this goroutine.
        s.readPump()

        s.Close()
        s.closeAllChannels()
        _ = s.conn.Close()
        s.log.Info("session ended", "user", s.username, "peer", s.clientPeer)
}

// runSMTPHandshake performs the EHLO -> STARTTLS -> AUTH -> BINARY dance.
// Returns true on success.
func (s *ServerSession) runSMTPHandshake() bool {
        // 1. Greeting.
        if err := s.lw.SendLine(smtp.ServerGreeting(s.tlsCfg.ServerName)); err != nil {
                s.log.Debug("write greeting failed", "err", err)
                return false
        }

        // 2. Wait for EHLO/HELO.
        line, err := s.lr.ReadLine()
        if err != nil || !strings.HasPrefix(strings.ToUpper(line), "EHLO") && !strings.HasPrefix(strings.ToUpper(line), "HELO") {
                if err != nil {
                        s.log.Debug("read EHLO failed", "err", err)
                } else {
                        s.log.Debug("expected EHLO", "got", line)
                }
                return false
        }

        // 3. Capabilities pre-TLS.
        if err := s.lw.SendLines(smtp.ServerCapabilitiesPreTLS(s.tlsCfg.ServerName)); err != nil {
                return false
        }

        // 4. Wait for STARTTLS.
        line, err = s.lr.ReadLine()
        if err != nil || strings.ToUpper(line) != "STARTTLS" {
                s.log.Debug("expected STARTTLS", "got", line, "err", err)
                return false
        }
        if err := s.lw.SendLine("220 2.0.0 Ready to start TLS"); err != nil {
                return false
        }

        // 5. Upgrade to TLS. We must drain any bytes the LineReader has
        // buffered past the STARTTLS line — typically zero, but be safe.
        buffered := s.lr.Buffered().Buffered()
        if buffered > 0 {
                // Should never happen for a well-behaved client, but if it
                // does, those bytes would be part of the TLS handshake.
                extra := make([]byte, buffered)
                _, _ = s.lr.Buffered().Read(extra)
                // We can't push them back into the TLS layer, so bail.
                s.log.Debug("client pipelined bytes after STARTTLS — refusing", "n", buffered)
                return false
        }

        tlsConn := tls.Server(s.conn, s.tlsCfg)
        if err := tlsConn.Handshake(); err != nil {
                s.log.Info("tls handshake failed", "peer", s.clientPeer, "err", err)
                return false
        }
        s.conn = tlsConn
        s.lr = smtp.NewLineReader(tlsConn)
        s.lw = smtp.NewLineWriter(tlsConn)
        s.log.Debug("tls established", "peer", s.clientPeer)

        // 6. EHLO again.
        line, err = s.lr.ReadLine()
        if err != nil || !strings.HasPrefix(strings.ToUpper(line), "EHLO") && !strings.HasPrefix(strings.ToUpper(line), "HELO") {
                return false
        }
        if err := s.lw.SendLines(smtp.ServerCapabilitiesPostTLS(s.tlsCfg.ServerName)); err != nil {
                return false
        }

        // 7. AUTH PLAIN <token>.
        line, err = s.lr.ReadLine()
        if err != nil || !strings.HasPrefix(strings.ToUpper(line), "AUTH ") {
                s.log.Debug("expected AUTH", "got", line, "err", err)
                return false
        }
        parts := strings.SplitN(line, " ", 3)
        if len(parts) < 3 {
                _ = s.lw.SendLine("535 5.7.8 Authentication failed")
                return false
        }
        token := parts[2]

        username, ok := s.verifyToken(token)
        if !ok {
                s.log.Warn("authentication failed", "peer", s.clientPeer)
                _ = s.lw.SendLine("535 5.7.8 Authentication failed")
                return false
        }
        s.username = username
        s.userCfg = s.users[username]

        // Per-user IP whitelist check.
        if s.userCfg != nil && len(s.userCfg.Whitelist) > 0 {
                wl := ipwhitelist.New(s.userCfg.Whitelist)
                if !wl.Allowed(s.clientIP) {
                        s.log.Warn("ip not whitelisted",
                                "user", username, "ip", s.clientIP)
                        _ = s.lw.SendLine("535 5.7.8 Authentication failed")
                        return false
                }
        }

        _ = s.lw.SendLine("235 2.7.0 Authentication successful")

        // 8. BINARY.
        line, err = s.lr.ReadLine()
        if err != nil || line != "BINARY" {
                s.log.Debug("expected BINARY", "got", line, "err", err)
                return false
        }
        _ = s.lw.SendLine("299 Binary mode activated")

        return true
}

// verifyToken checks the auth token against every configured user.
func (s *ServerSession) verifyToken(token string) (string, bool) {
        users := make(map[string]string, len(s.users))
        for name, u := range s.users {
                users[name] = u.Secret
        }
        return auth.VerifyTokenMultiUser(token, users, time.Now(), true)
}

// readPump reads frames from the tunnel and dispatches them. It returns
// when the connection closes or a fatal error occurs.
func (s *ServerSession) readPump() {
        for {
                f, err := s.rd.ReadFrame()
                if err != nil {
                        if err == io.EOF || errors.Is(err, net.ErrClosed) {
                                return
                        }
                        s.log.Debug("read frame failed", "err", err)
                        return
                }
                s.stats.FramesIn.Add(1)
                s.stats.BytesIn.Add(int64(len(f.Payload)))

                if s.userCfg != nil && !s.userCfg.Logging && false {
                        // Per-user logging toggle is checked in the slog calls,
                        // not here — we still need to process the frame.
                }

                switch f.Type {
                case protocol.FrameConnect:
                        s.handleConnect(f)
                case protocol.FrameData:
                        if ch := s.lookupChannel(f.ChannelID); ch != nil {
                                ch.onData(f.Payload)
                        }
                case protocol.FrameClose:
                        if ch := s.lookupChannel(f.ChannelID); ch != nil {
                                ch.closeFromRemote()
                        }
                case protocol.FrameKeepalive:
                        // Echo back as KEEPALIVE_ACK — best-effort.
                        _ = s.enqueueFrame(&protocol.Frame{
                                Type:      protocol.FrameKeepaliveAck,
                                ChannelID: 0,
                        })
                case protocol.FrameKeepaliveAck:
                        // Recorded by the watchdog via lastAckTime.
                        s.lastAckTime.Store(time.Now().UnixNano())
                default:
                        // Unknown frame type — ignore (forward compatibility).
                }
        }
}

// handleConnect dials the requested host:port and starts a channel.
func (s *ServerSession) handleConnect(f *protocol.Frame) {
        host, port, err := protocol.ParseConnectPayload(f.Payload)
        if err != nil {
                _ = s.enqueueFrame(&protocol.Frame{
                        Type:      protocol.FrameConnectFail,
                        ChannelID: f.ChannelID,
                        Payload:   []byte("bad connect payload"),
                })
                return
        }

        // Don't allow channels to be opened before we finish closing a
        // previous one with the same ID. registerChannel will catch a
        // collision.
        if ch := s.lookupChannel(f.ChannelID); ch != nil {
                _ = s.enqueueFrame(&protocol.Frame{
                        Type:      protocol.FrameConnectFail,
                        ChannelID: f.ChannelID,
                        Payload:   []byte("channel id in use"),
                })
                return
        }

        dialer := &net.Dialer{Timeout: s.opts.ConnectTimeout}
        addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
        if s.userCfg != nil && s.userCfg.Logging {
                s.log.Info("connect", "ch", f.ChannelID, "addr", addr)
        }
        conn, err := dialer.Dial("tcp", addr)
        if err != nil {
                s.log.Info("connect failed", "ch", f.ChannelID, "addr", addr, "err", err)
                reason := err.Error()
                if len(reason) > 100 {
                        reason = reason[:100]
                }
                _ = s.enqueueFrame(&protocol.Frame{
                        Type:      protocol.FrameConnectFail,
                        ChannelID: f.ChannelID,
                        Payload:   []byte(reason),
                })
                return
        }

        // Apply TCP tuning on the dialed connection.
        if tcp, ok := conn.(*net.TCPConn); ok {
                _ = tcp.SetNoDelay(true)
                _ = tcp.SetKeepAlive(true)
                _ = tcp.SetKeepAlivePeriod(30 * time.Second)
                if s.opts.ReadBufferSize > 0 {
                        _ = tcp.SetReadBuffer(s.opts.ReadBufferSize)
                }
                if s.opts.WriteBufferSize > 0 {
                        _ = tcp.SetWriteBuffer(s.opts.WriteBufferSize)
                }
        }

        ch := newChannel(s.common, f.ChannelID, conn)
        if !s.registerChannel(ch) {
                // Race: another CONNECT for the same ID arrived first.
                _ = conn.Close()
                _ = s.enqueueFrame(&protocol.Frame{
                        Type:      protocol.FrameConnectFail,
                        ChannelID: f.ChannelID,
                        Payload:   []byte("channel id collision"),
                })
                return
        }

        _ = s.enqueueFrame(&protocol.Frame{
                Type:      protocol.FrameConnectOK,
                ChannelID: f.ChannelID,
        })
        if s.userCfg != nil && s.userCfg.Logging {
                s.log.Info("connected", "ch", f.ChannelID, "addr", addr)
        }

        ch.Start()
}

// keepaliveWatchdog sends periodic KEEPALIVE frames and closes the
// tunnel if no ACK is received within keepaliveTimeout.
//
// Note: the Python server doesn't send keepalives, but it will silently
// ignore unknown frame types. So sending KEEPALIVE to a Python server is
// safe — it just won't ACK. We tolerate that by treating "no ACK" as a
// soft warning rather than an immediate disconnect for the first few
// intervals, then we disconnect.
func (s *ServerSession) keepaliveWatchdog() {
        ticker := time.NewTicker(keepaliveInterval)
        defer ticker.Stop()
        missed := 0
        for {
                select {
                case <-s.ctx.Done():
                        return
                case <-ticker.C:
                        // If the tunnel is busy we don't need to send keepalives —
                        // recent traffic means the peer is alive.
                        if s.channelCount() > 0 {
                                missed = 0
                                continue
                        }
                        _ = s.enqueueFrame(&protocol.Frame{
                                Type:      protocol.FrameKeepalive,
                                ChannelID: 0,
                        })
                        missed++
                        // Only disconnect after 3 consecutive missed ACKs (i.e. ~75s).
                        // This tolerates Python peers that don't ACK.
                        if missed >= 3 {
                                s.log.Info("keepalive timeout, closing tunnel",
                                        "user", s.username, "peer", s.clientPeer)
                                s.Close()
                                return
                        }
                }
        }
}
