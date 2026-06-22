package tunnel

import (
        "io"
        "net"
        "sync"
        "sync/atomic"

        "github.com/sodas-cheddar/smtp-tunnel-go/internal/protocol"
)

// Channel represents a single multiplexed stream over the tunnel. It is
// the virtual equivalent of a net.Conn — both ends can Read and Write,
// and Close shuts it down.
//
// On the server side, a Channel is bound to an outbound net.Conn that
// was dialed when CONNECT was received. On the client side, a Channel is
// bound to an inbound net.Conn that came from the SOCKS5 listener.
//
// In both cases the channel runs two goroutines:
//
//   - readFromConn: reads bytes from the local net.Conn and pushes
//     FrameData frames onto the tunnel send queue.
//   - (writes from the tunnel to the local net.Conn are issued directly
//     by the read pump when it receives a FrameData for this channel)
//
// We don't need a separate "write to conn" goroutine because the read
// pump is the only source of inbound frames and it processes them
// serially per tunnel.
type Channel struct {
        id uint16

        // conn is the local TCP connection (SOCKS5 client on the client side,
        // dialed target on the server side). nil after Close.
        conn net.Conn

        // closed protects the one-shot Close path. localReason is the reason
        // string when we closed locally (empty if the peer closed first).
        closed      atomic.Bool
        closeOnce   sync.Once
        localReason string

        // onRemoteClose is invoked when the peer sends a CLOSE frame for this
        // channel. It is set by the channel owner (server or client) so they
        // can react — e.g. the client tears down the SOCKS5 side.
        onRemoteClose func()

        // sendCloseFrame is true when we still owe the peer a CLOSE frame.
        // Set to false once we've sent it.
        sendCloseFrame atomic.Bool

        // done is closed when the channel finishes closing. Allocated in
        // newChannel so Wait() can be called any time.
        done chan struct{}

        c *common // back-pointer for sending frames and stats
}

// newChannel creates a channel. The caller is responsible for
// registering it via c.registerChannel.
func newChannel(c *common, id uint16, conn net.Conn) *Channel {
        ch := &Channel{
                id:             id,
                conn:           conn,
                c:              c,
                done:           make(chan struct{}),
                sendCloseFrame: atomic.Bool{},
        }
        ch.sendCloseFrame.Store(true)
        return ch
}

// ID returns the channel's 16-bit identifier.
func (ch *Channel) ID() uint16 { return ch.id }

// Start launches the reader goroutine that pumps data from the local
// net.Conn into the tunnel. The caller should invoke Start only after
// the channel is fully registered and (on the client side) after
// CONNECT_OK has been received.
//
// The goroutine exits when the local conn returns EOF/error, when the
// tunnel context is cancelled, or when Close() is called. In all cases
// it sends a CLOSE frame (best-effort) and tears down the local conn.
func (ch *Channel) Start() {
        go ch.readFromConn()
}

// readFromConn is the workhorse: read from local conn, send FrameData.
// We use a sync.Pool-backed buffer to avoid per-read allocations.
func (ch *Channel) readFromConn() {
        defer ch.shutdownFromLocal()

        buf := acquireBuf()
        defer releaseBuf(buf)

        for {
                if ch.closed.Load() {
                        return
                }
                n, err := ch.conn.Read(buf)
                if n > 0 {
                        // Copy into a fresh slice — the frame will outlive the buffer.
                        payload := make([]byte, n)
                        copy(payload, buf[:n])

                        frame := &protocol.Frame{
                                Type:      protocol.FrameData,
                                ChannelID: ch.id,
                                Payload:   payload,
                        }
                        if err := ch.c.enqueueFrame(frame); err != nil {
                                // Tunnel is closing — bail out.
                                return
                        }
                }
                if err != nil {
                        if err == io.EOF {
                                return
                        }
                        // Treat any read error as connection termination.
                        return
                }
        }
}

// shutdownFromLocal is invoked when the local conn closes (EOF or error).
// It sends a CLOSE frame to the peer and tears down the channel.
func (ch *Channel) shutdownFromLocal() {
        ch.closeLocal("local eof")
}

// closeLocal closes the channel from the local side. It is idempotent.
// reason is for logging only. If we haven't yet sent a CLOSE frame to
// the peer, one is sent now.
func (ch *Channel) closeLocal(reason string) {
        ch.closeOnce.Do(func() {
                ch.closed.Store(true)
                ch.localReason = reason

                // Send CLOSE to peer if we still owe one.
                if ch.sendCloseFrame.CompareAndSwap(true, false) {
                        frame := &protocol.Frame{
                                Type:      protocol.FrameClose,
                                ChannelID: ch.id,
                        }
                        // Best-effort; tunnel may be already gone.
                        _ = ch.c.enqueueFrame(frame)
                }

                // Close the local conn. Ignore errors — it may already be closed.
                if ch.conn != nil {
                        _ = ch.conn.Close()
                }

                // Unregister from the tunnel.
                ch.c.unregisterChannel(ch.id)

                // Notify owner (e.g. SOCKS5 handler) if they registered a hook.
                if ch.onRemoteClose != nil {
                        ch.onRemoteClose()
                }

                // Wake any goroutine waiting on Wait().
                close(ch.done)
        })
}

// closeFromRemote is invoked when the peer sends a CLOSE frame. We do
// NOT send a CLOSE back — the peer already knows. We just tear down the
// local conn.
func (ch *Channel) closeFromRemote() {
        ch.closeOnce.Do(func() {
                ch.closed.Store(true)
                // Peer already closed — we don't owe a CLOSE frame.
                ch.sendCloseFrame.Store(false)

                if ch.conn != nil {
                        _ = ch.conn.Close()
                }
                ch.c.unregisterChannel(ch.id)

                if ch.onRemoteClose != nil {
                        ch.onRemoteClose()
                }

                close(ch.done)
        })
}

// onData is invoked by the read pump when a FrameData arrives for this
// channel. It writes the payload to the local conn. If the write fails
// the channel is torn down.
func (ch *Channel) onData(payload []byte) {
        if ch.closed.Load() {
                return
        }
        if _, err := ch.conn.Write(payload); err != nil {
                ch.closeLocal("local write error")
        }
}

// SetOnRemoteClose registers a callback invoked once when the channel is
// closed (from either side). Used by the SOCKS5 handler to know when to
// reap the SOCKS5 connection.
func (ch *Channel) SetOnRemoteClose(fn func()) {
        ch.onRemoteClose = fn
}

// Wait blocks until the channel has been closed (from either side). It is
// safe to call concurrently and to call multiple times.
func (ch *Channel) Wait() {
        <-ch.done
}

// Close closes the channel from the local side. Idempotent.
func (ch *Channel) Close() {
        ch.closeLocal("caller closed")
}

// --- Buffer pool ---

// We use 32KB buffers because that's a sweet spot for TCP throughput:
// large enough that the kernel can coalesce, small enough that we don't
// blow the L1 cache. The pool is shared across all channels on all
// tunnels in the process.
const dataBufSize = 32 * 1024

var bufPool = sync.Pool{
        New: func() any {
                b := make([]byte, dataBufSize)
                return &b
        },
}

func acquireBuf() []byte  { return *bufPool.Get().(*[]byte) }
func releaseBuf(b []byte) { bufPool.Put(&b) }
