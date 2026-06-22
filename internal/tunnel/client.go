package tunnel

import (
        "context"
        "crypto/tls"
        "crypto/x509"
        "errors"
        "fmt"
        "io"
        "log/slog"
        "math/rand"
        "net"
        "os"
        "sync/atomic"
        "time"

        "github.com/sodas-cheddar/smtp-tunnel-go/internal/auth"
        "github.com/sodas-cheddar/smtp-tunnel-go/internal/protocol"
        "github.com/sodas-cheddar/smtp-tunnel-go/internal/smtp"
)

// ClientOptions tunes the client-side tunnel session.
type ClientOptions struct {
        // ServerHost is the FQDN the client connects to. It is also used as
        // the TLS ServerName.
        ServerHost string
        ServerPort int
        // Username + Secret authenticate the tunnel.
        Username string
        Secret   string
        // CACertPath is the path to a PEM-encoded CA cert that signs the
        // server cert. If empty, TLS verification is disabled (NOT
        // recommended — vulnerable to MITM).
        CACertPath string
        // SendQueueSize is the depth of the outbound frame queue. Default 1024.
        SendQueueSize int
        // ReadBufferSize / WriteBufferSize set the TCP buffer sizes on the
        // tunnel socket. 0 = use system default.
        ReadBufferSize  int
        WriteBufferSize int
        // ConnectTimeout is how long we wait for the TCP+SMTP+TLS handshake
        // to complete. Default 30s.
        ConnectTimeout time.Duration
        // Logger receives structured log events.
        Logger *slog.Logger
}

func (o *ClientOptions) defaults() {
        if o.SendQueueSize <= 0 {
                o.SendQueueSize = 1024
        }
        if o.ConnectTimeout <= 0 {
                o.ConnectTimeout = 30 * time.Second
        }
        if o.Logger == nil {
                o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
        }
}

// Client is a single tunnel client connection to the server. It is the
// counterpart of ServerSession. Unlike the server, the client owns its
// own lifecycle and performs automatic reconnection.
type Client struct {
        opts ClientOptions
        log  *slog.Logger

        // nextChannelID is the next channel ID to allocate. Channel IDs from
        // the client must be non-zero (0 is reserved for tunnel-level
        // control frames like KEEPALIVE).
        nextChannelID atomic.Uint32

        // common is the active tunnel session. nil when disconnected.
        // Protected by mu.
        mu     atomic.Pointer[common]
        conn   net.Conn
        tlsCfg *tls.Config
}

// NewClient constructs a client with the given options. It does NOT
// connect — call Connect() (or Run()) to do that.
func NewClient(opts ClientOptions) (*Client, error) {
        opts.defaults()
        if opts.ServerHost == "" {
                return nil, errors.New("tunnel: ServerHost is required")
        }
        if opts.Username == "" {
                return nil, errors.New("tunnel: Username is required")
        }
        if opts.Secret == "" {
                return nil, errors.New("tunnel: Secret is required")
        }

        tlsCfg := &tls.Config{
                ServerName: opts.ServerHost,
                MinVersion: tls.VersionTLS12,
        }
        if opts.CACertPath != "" {
                caCert, err := os.ReadFile(opts.CACertPath)
                if err != nil {
                        return nil, fmt.Errorf("tunnel: read CA cert: %w", err)
                }
                pool := x509.NewCertPool()
                if !pool.AppendCertsFromPEM(caCert) {
                        return nil, fmt.Errorf("tunnel: CA cert %s contains no certificates", opts.CACertPath)
                }
                tlsCfg.RootCAs = pool
        } else {
                // Insecure mode — explicitly disabled verification. This matches
                // the Python client behavior when ca_cert is not set.
                tlsCfg.InsecureSkipVerify = true
        }

        return &Client{
                opts:  opts,
                log:   opts.Logger,
                tlsCfg: tlsCfg,
        }, nil
}

// Connect performs the TCP connect + SMTP handshake + binary-mode switch.
// On success it starts the read/write pumps and returns. The caller can
// then OpenChannel / SendFrame. On error the connection is closed.
func (c *Client) Connect(parentCtx context.Context) error {
        ctx, cancel := context.WithTimeout(parentCtx, c.opts.ConnectTimeout)
        defer cancel()

        dialer := &net.Dialer{Timeout: c.opts.ConnectTimeout}
        addr := net.JoinHostPort(c.opts.ServerHost, fmt.Sprintf("%d", c.opts.ServerPort))
        conn, err := dialer.DialContext(ctx, "tcp", addr)
        if err != nil {
                return fmt.Errorf("dial: %w", err)
        }
        if tcp, ok := conn.(*net.TCPConn); ok {
                _ = tcp.SetNoDelay(true)
                _ = tcp.SetKeepAlive(true)
                _ = tcp.SetKeepAlivePeriod(30 * time.Second)
                if c.opts.ReadBufferSize > 0 {
                        _ = tcp.SetReadBuffer(c.opts.ReadBufferSize)
                }
                if c.opts.WriteBufferSize > 0 {
                        _ = tcp.SetWriteBuffer(c.opts.WriteBufferSize)
                }
        }

        c.conn = conn
        if err := c.runSMTPHandshake(ctx); err != nil {
                _ = conn.Close()
                c.conn = nil
                return err
        }

        // Switch to binary mode. Wire up the tunnel common state.
        // IMPORTANT: use c.conn (not the original `conn`), because
        // runSMTPHandshake upgrades c.conn to a *tls.Conn after STARTTLS.
        rd := protocol.NewReader(c.conn)
        wr := protocol.NewWriter(c.conn)
        cm := newCommon(DirClient, rd, wr, parentCtx, c.opts.SendQueueSize)
        c.mu.Store(cm)

        // Start pumps.
        go cm.writePump()
        go c.keepaliveWatchdog(cm)
        go c.readPump(cm)

        return nil
}

// runSMTPHandshake does the EHLO -> STARTTLS -> EHLO -> AUTH -> BINARY
// dance on the client side.
func (c *Client) runSMTPHandshake(ctx context.Context) error {
        lr := smtp.NewLineReader(c.conn)
        lw := smtp.NewLineWriter(c.conn)

        readLine := func() (string, error) {
                // We can't use ctx directly on a blocking read; set a deadline.
                _ = c.conn.SetReadDeadline(time.Now().Add(smtp.HandshakeTimeout))
                defer c.conn.SetReadDeadline(time.Time{})
                return lr.ReadLine()
        }

        // 1. Wait for greeting.
        line, err := readLine()
        if err != nil || !startsWith(line, "220") {
                return fmt.Errorf("wait greeting: %v (line=%q)", err, line)
        }

        // 2. EHLO.
        if err := lw.SendLine("EHLO tunnel-client.local"); err != nil {
                return fmt.Errorf("send EHLO: %w", err)
        }
        if err := smtp.Expect250(lr); err != nil {
                return fmt.Errorf("EHLO response: %w", err)
        }

        // 3. STARTTLS.
        if err := lw.SendLine("STARTTLS"); err != nil {
                return fmt.Errorf("send STARTTLS: %w", err)
        }
        line, err = readLine()
        if err != nil || !startsWith(line, "220") {
                return fmt.Errorf("STARTTLS response: %v (line=%q)", err, line)
        }

        // 4. TLS upgrade.
        tlsConn := tls.Client(c.conn, c.tlsCfg)
        if err := tlsConn.HandshakeContext(ctx); err != nil {
                return fmt.Errorf("tls handshake: %w", err)
        }
        c.conn = tlsConn
        lr = smtp.NewLineReader(tlsConn)
        lw = smtp.NewLineWriter(tlsConn)

        // 5. EHLO again.
        if err := lw.SendLine("EHLO tunnel-client.local"); err != nil {
                return fmt.Errorf("send EHLO post-tls: %w", err)
        }
        if err := smtp.Expect250(lr); err != nil {
                return fmt.Errorf("post-tls EHLO response: %w", err)
        }

        // 6. AUTH PLAIN.
        token := auth.GenerateToken(c.opts.Secret, c.opts.Username, time.Now())
        if err := lw.SendLine("AUTH PLAIN " + token); err != nil {
                return fmt.Errorf("send AUTH: %w", err)
        }
        line, err = readLine()
        if err != nil || !startsWith(line, "235") {
                return fmt.Errorf("auth failed: %v (line=%q)", err, line)
        }

        // 7. BINARY.
        if err := lw.SendLine("BINARY"); err != nil {
                return fmt.Errorf("send BINARY: %w", err)
        }
        line, err = readLine()
        if err != nil || !startsWith(line, "299") {
                return fmt.Errorf("BINARY response: %v (line=%q)", err, line)
        }

        c.log.Debug("smtp handshake complete")
        return nil
}

// readPump is the client-side frame dispatcher. It exits when the tunnel
// connection is closed; this triggers the supervisor to reconnect.
func (c *Client) readPump(cm *common) {
        for {
                f, err := cm.rd.ReadFrame()
                if err != nil {
                        if err == io.EOF || errors.Is(err, net.ErrClosed) {
                                c.log.Debug("tunnel eof")
                        } else {
                                c.log.Info("tunnel read error", "err", err)
                        }
                        cm.Close()
                        return
                }
                cm.stats.FramesIn.Add(1)
                cm.stats.BytesIn.Add(int64(len(f.Payload)))

                switch f.Type {
                case protocol.FrameConnectOK:
                        if req, ok := c.takeOpenReq(cm, f.ChannelID); ok {
                                req.ok = true
                                close(req.ready)
                        }
                case protocol.FrameConnectFail:
                        if req, ok := c.takeOpenReq(cm, f.ChannelID); ok {
                                req.ok = false
                                req.reason = string(f.Payload)
                                close(req.ready)
                        }
                case protocol.FrameData:
                        if ch := cm.lookupChannel(f.ChannelID); ch != nil {
                                ch.onData(f.Payload)
                        }
                case protocol.FrameClose:
                        if ch := cm.lookupChannel(f.ChannelID); ch != nil {
                                ch.closeFromRemote()
                        }
                case protocol.FrameKeepalive:
                        _ = cm.enqueueFrame(&protocol.Frame{
                                Type:      protocol.FrameKeepaliveAck,
                                ChannelID: 0,
                        })
                case protocol.FrameKeepaliveAck:
                        cm.lastAckTime.Store(time.Now().UnixNano())
                }
        }
}

// keepaliveWatchdog sends KEEPALIVE frames when the tunnel is idle. If no
// ACK arrives within keepaliveTimeout after at least 3 attempts, the
// tunnel is force-closed so the supervisor can reconnect.
func (c *Client) keepaliveWatchdog(cm *common) {
        ticker := time.NewTicker(keepaliveInterval)
        defer ticker.Stop()
        missed := 0
        for {
                select {
                case <-cm.ctx.Done():
                        return
                case <-ticker.C:
                        // If we have active channels, recent traffic means the
                        // peer is alive — skip the keepalive.
                        if cm.channelCount() > 0 {
                                missed = 0
                                continue
                        }
                        _ = cm.enqueueFrame(&protocol.Frame{
                                Type:      protocol.FrameKeepalive,
                                ChannelID: 0,
                        })
                        missed++
                        if missed >= 3 {
                                c.log.Info("keepalive timeout, reconnecting")
                                cm.Close()
                                return
                        }
                }
        }
}

// OpenChannel sends a CONNECT frame and waits for CONNECT_OK / FAIL.
// On success it returns a *Channel that the caller can use to wire up
// its local connection. The caller must call ch.Start() to begin
// pumping data.
//
// On failure returns nil and an error.
func (c *Client) OpenChannel(host string, port uint16) (*Channel, error) {
        cm := c.mu.Load()
        if cm == nil || cm.Closed() {
                return nil, ErrClosed
        }

        // Allocate a non-zero channel ID. Channel ID 0 is reserved for
        // tunnel-level control frames.
        id := uint16(c.nextChannelID.Add(1))
        if id == 0 {
                id = uint16(c.nextChannelID.Add(1))
        }

        // Register an open request so the read pump can wake us up.
        req := &openReq{ready: make(chan struct{})}
        cm.openMu.Lock()
        cm.opens[id] = req
        cm.openMu.Unlock()
        defer func() {
                cm.openMu.Lock()
                delete(cm.opens, id)
                cm.openMu.Unlock()
        }()

        // Send CONNECT.
        if err := cm.enqueueFrame(&protocol.Frame{
                Type:      protocol.FrameConnect,
                ChannelID: id,
                Payload:   protocol.MakeConnectPayload(host, port),
        }); err != nil {
                return nil, err
        }

        // Wait for response.
        select {
        case <-req.ready:
                if !req.ok {
                        return nil, fmt.Errorf("connect refused: %s", req.reason)
                }
                // Note: the caller will register the channel *after* wiring up
                // its local conn. We can't register here because we don't have
                // the conn yet — the caller passes it in via RegisterChannel.
                ch := &Channel{
                        id:             id,
                        c:              cm,
                        done:           make(chan struct{}),
                        sendCloseFrame: atomic.Bool{},
                }
                ch.sendCloseFrame.Store(true)
                return ch, nil
        case <-cm.ctx.Done():
                return nil, ErrClosed
        case <-time.After(30 * time.Second):
                return nil, errors.New("connect timeout")
        }
}

// RegisterChannel attaches a local net.Conn to a channel previously
// created via OpenChannel and starts pumping data. The caller normally
// does:
//
//      ch, err := client.OpenChannel(host, port)
//      if err != nil { ... }
//      client.RegisterChannel(ch, localConn)
//      // ... wait for either side to close ...
func (c *Client) RegisterChannel(ch *Channel, conn net.Conn) bool {
        ch.conn = conn
        ch.sendCloseFrame.Store(true)
        return ch.c.registerChannel(ch)
}

// takeOpenReq atomically removes and returns the open request for id.
func (c *Client) takeOpenReq(cm *common, id uint16) (*openReq, bool) {
        cm.openMu.Lock()
        defer cm.openMu.Unlock()
        req, ok := cm.opens[id]
        if ok {
                delete(cm.opens, id)
        }
        return req, ok
}

// Closed reports whether the tunnel is currently connected.
func (c *Client) Closed() bool {
        cm := c.mu.Load()
        return cm == nil || cm.Closed()
}

// ActiveCommon returns the current common (nil if disconnected). Used by
// the supervisor to wait for tunnel close.
func (c *Client) ActiveCommon() *common { return c.mu.Load() }

// Wait blocks until the tunnel session has ended (read pump returned).
// Used by the supervisor to know when to reconnect.
func (c *Client) Wait() {
        cm := c.mu.Load()
        if cm == nil {
                return
        }
        <-cm.ctx.Done()
}

// Disconnect tears down the active tunnel. Safe to call when already
// disconnected.
func (c *Client) Disconnect() {
        cm := c.mu.Load()
        if cm == nil {
                return
        }
        cm.Close()
        cm.closeAllChannels()
        if c.conn != nil {
                _ = c.conn.Close()
        }
        c.mu.Store(nil)
}

// --- Reconnect supervisor ---

// RunForever connects to the server and automatically reconnects after
// any disconnection. It uses exponential backoff with full jitter to
// avoid thundering-herd reconnect storms.
//
// onConnect is invoked each time a fresh tunnel comes up (after a
// successful Connect). It is the right place to, e.g. log the event.
// onDisconnect is invoked each time the tunnel goes down.
//
// RunForever returns only when ctx is cancelled.
func (c *Client) RunForever(ctx context.Context, onConnect, onDisconnect func()) {
        const (
                initialDelay = 1 * time.Second
                maxDelay     = 30 * time.Second
        )

        delay := initialDelay
        for {
                if ctx.Err() != nil {
                        return
                }

                err := c.Connect(ctx)
                if err != nil {
                        c.log.Info("connect failed", "err", err, "retry_in", delay)
                        jitter := time.Duration(rand.Int63n(int64(delay) + 1))
                        select {
                        case <-ctx.Done():
                                return
                        case <-time.After(jitter):
                        }
                        delay = delay * 2
                        if delay > maxDelay {
                                delay = maxDelay
                        }
                        continue
                }

                // Connected — reset backoff.
                delay = initialDelay
                if onConnect != nil {
                        onConnect()
                }

                // Wait for the tunnel to drop.
                cm := c.mu.Load()
                if cm != nil {
                        <-cm.ctx.Done()
                }

                // Tear down the conn so the next Connect starts clean.
                cm = c.mu.Load()
                if cm != nil {
                        cm.closeAllChannels()
                }
                if c.conn != nil {
                        _ = c.conn.Close()
                        c.conn = nil
                }
                c.mu.Store(nil)

                if onDisconnect != nil {
                        onDisconnect()
                }

                // No artificial delay on disconnect — reconnect immediately.
                // The backoff only kicks in if the *connect* itself fails.
        }
}

// startsWith is a case-insensitive prefix check.
func startsWith(s, prefix string) bool {
        if len(s) < len(prefix) {
                return false
        }
        for i := 0; i < len(prefix); i++ {
                a, b := s[i], prefix[i]
                if 'A' <= a && a <= 'Z' {
                        a += 32
                }
                if 'A' <= b && b <= 'Z' {
                        b += 32
                }
                if a != b {
                        return false
                }
        }
        return true
}
