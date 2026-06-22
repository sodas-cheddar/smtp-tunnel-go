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
// Each channel runs one goroutine:
//
//   - readFromConn: reads bytes from the local net.Conn and pushes
//     FrameData frames onto the tunnel send queue.
//
// Writes from the tunnel to the local net.Conn are issued directly by
// the read pump when it receives a FrameData for this channel. If the
// local conn's Write blocks, the read pump stalls — this is intentional
// backpressure that propagates through TCP flow control to the sender.
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
// net.Conn into the tunnel.
func (ch *Channel) Start() {
	go ch.readFromConn()
}

// readFromConn reads from the local net.Conn and sends FrameData frames
// onto the tunnel send queue.
//
// We read directly into a freshly allocated payload buffer of up to
// protocol.MaxPayloadSize (64 KB). This:
//   - Reads the maximum possible chunk per syscall (halving frame count
//     and TLS write overhead vs the old 32 KB reads).
//   - Eliminates the pool+copy pattern — Go's allocator is fast enough
//     for 64 KB allocations, and avoiding the memcpy saves more than
//     the allocation costs.
func (ch *Channel) readFromConn() {
	defer ch.shutdownFromLocal()

	for {
		if ch.closed.Load() {
			return
		}
		// Allocate the payload buffer directly — no pool, no copy.
		payload := make([]byte, protocol.MaxPayloadSize)
		n, err := ch.conn.Read(payload)
		if n > 0 {
			payload = payload[:n]
			frame := &protocol.Frame{
				Type:      protocol.FrameData,
				ChannelID: ch.id,
				Payload:   payload,
			}
			if err := ch.c.enqueueFrame(frame); err != nil {
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				return
			}
			return
		}
	}
}

// shutdownFromLocal is invoked when the local conn closes (EOF or error).
func (ch *Channel) shutdownFromLocal() {
	ch.closeLocal("local eof")
}

// closeLocal closes the channel from the local side. It is idempotent.
func (ch *Channel) closeLocal(reason string) {
	ch.closeOnce.Do(func() {
		ch.closed.Store(true)
		ch.localReason = reason

		if ch.sendCloseFrame.CompareAndSwap(true, false) {
			frame := &protocol.Frame{
				Type:      protocol.FrameClose,
				ChannelID: ch.id,
			}
			_ = ch.c.enqueueFrame(frame)
		}

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

// closeFromRemote is invoked when the peer sends a CLOSE frame.
func (ch *Channel) closeFromRemote() {
	ch.closeOnce.Do(func() {
		ch.closed.Store(true)
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

// onData is invoked by the tunnel read pump when a FrameData arrives for
// this channel. It writes the payload directly to the local conn. If the
// write blocks (because the local conn's send buffer is full), the read
// pump stalls — this is intentional backpressure that propagates through
// TCP flow control to the sender.
func (ch *Channel) onData(payload []byte) {
	if ch.closed.Load() {
		return
	}
	if _, err := ch.conn.Write(payload); err != nil {
		ch.closeLocal("local write error")
	}
}

// SetOnRemoteClose registers a callback invoked once when the channel is
// closed (from either side).
func (ch *Channel) SetOnRemoteClose(fn func()) {
	ch.onRemoteClose = fn
}

// Wait blocks until the channel has been closed (from either side).
func (ch *Channel) Wait() {
	<-ch.done
}

// Close closes the channel from the local side. Idempotent.
func (ch *Channel) Close() {
	ch.closeLocal("caller closed")
}
