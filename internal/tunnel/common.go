// Package tunnel implements the multiplexed tunnel that runs on top of a
// TLS connection after the SMTP handshake.
//
// A tunnel carries up to 65535 independent channels over a single TCP+TLS
// connection. Each channel is a virtual byte stream identified by a 16-bit
// channel ID.
//
// Two actors live on each side of the tunnel:
//
//   - A single read pump goroutine that reads frames from the TLS
//     connection and dispatches them to the appropriate channel (or to a
//     control handler for CONNECT / CONNECT_OK / CLOSE).
//   - A single write pump goroutine that serializes outbound frames from
//     all channels onto the TLS connection. Having one writer avoids
//     interleaving partial frames and removes the need for a write lock.
//
// Each open channel runs two goroutines (one per direction) for the
// underlying net.Conn it bridges to.
//
// This design is the single biggest reason the Go version is faster and
// more robust than the Python original: there is no GIL, no asyncio event
// loop, no per-frame await/suspend overhead, and writes from concurrent
// goroutines are coalesced by the write pump into a single TLS write per
// scheduling quantum.
package tunnel

import (
        "context"
        "errors"
        "sync"
        "sync/atomic"
        "time"

        "github.com/sodas-cheddar/smtp-tunnel-go/internal/protocol"
)

// Stats tracks throughput counters for a tunnel. Safe for concurrent reads.
type Stats struct {
        BytesIn   atomic.Int64
        BytesOut  atomic.Int64
        FramesIn  atomic.Int64
        FramesOut atomic.Int64
}

// Direction is which side of the tunnel we are on — it only matters for
// logging.
type Direction int

const (
        DirServer Direction = iota
        DirClient
)

// common carries the state shared between the read pump, the write pump,
// and every channel goroutine for one tunnel session.
type common struct {
        dir Direction

        // rw is the underlying TLS connection. Only the read pump reads from
        // it; only the write pump writes to it. After the handshake the
        // caller hands the conn to us by giving us a *protocol.Reader and a
        // *protocol.Writer that wrap it.
        rd *protocol.Reader
        wr *protocol.Writer

        // send is the queue of outbound frames. Every channel writes its
        // outbound frames here; the write pump drains it.
        send chan *protocol.Frame

        // channels maps channelID -> *Channel. Protected by mu.
        mu       sync.RWMutex
        channels map[uint16]*Channel

        // onConnectFail / onConnectOK are synchronous response slots indexed
        // by channel ID. When a client opens a channel it allocates a slot
        // here and waits on the embedded ready channel.
        openMu sync.Mutex
        opens  map[uint16]*openReq

        stats Stats

        // ctx is cancelled when the tunnel session is ending (either side
        // closed the connection, or a fatal error occurred). Channel
        // goroutines select on ctx.Done() to know when to wind down.
        ctx    context.Context
        cancel context.CancelFunc

        // closed is set once by the first close call so we don't double-close
        // the send channel.
        closeOnce sync.Once
        closed    atomic.Bool

        // lastAckTime is the UnixNano of the most recent KEEPALIVE_ACK we
        // received. Used by the keepalive watchdog to detect dead peers.
        lastAckTime atomic.Int64
}

type openReq struct {
        ready  chan struct{}
        ok     bool
        reason string
}

// newCommon allocates the shared state for one tunnel session. The caller
// must have already wrapped the connection in a protocol.Reader /
// protocol.Writer.
func newCommon(dir Direction, rd *protocol.Reader, wr *protocol.Writer, parentCtx context.Context, sendQueueSize int) *common {
        ctx, cancel := context.WithCancel(parentCtx)
        return &common{
                dir:      dir,
                rd:       rd,
                wr:       wr,
                send:     make(chan *protocol.Frame, sendQueueSize),
                channels: make(map[uint16]*Channel),
                opens:    make(map[uint16]*openReq),
                ctx:      ctx,
                cancel:   cancel,
        }
}

// ErrClosed is returned by operations that hit a closed tunnel.
var ErrClosed = errors.New("tunnel: closed")

// enqueueFrame pushes a frame onto the send queue. It honours the tunnel
// context so a stalled write pump doesn't leak a goroutine forever.
func (c *common) enqueueFrame(f *protocol.Frame) error {
        select {
        case c.send <- f:
                return nil
        case <-c.ctx.Done():
                return ErrClosed
        }
}

// Close cancels the tunnel context. The write pump and read pump will
// observe the cancellation and exit. It is safe to call concurrently.
func (c *common) Close() {
        c.closeOnce.Do(func() {
                c.closed.Store(true)
                c.cancel()
        })
}

// Closed reports whether Close has been called.
func (c *common) Closed() bool { return c.closed.Load() }

// Stats returns a snapshot of throughput counters.
func (c *common) Stats() (bytesIn, bytesOut, framesIn, framesOut int64) {
        return c.stats.BytesIn.Load(),
                c.stats.BytesOut.Load(),
                c.stats.FramesIn.Load(),
                c.stats.FramesOut.Load()
}

// registerChannel adds ch to the channel map. Returns false if a channel
// with the same ID was already registered.
func (c *common) registerChannel(ch *Channel) bool {
        c.mu.Lock()
        defer c.mu.Unlock()
        if _, exists := c.channels[ch.id]; exists {
                return false
        }
        c.channels[ch.id] = ch
        return true
}

// lookupChannel returns the channel with the given ID, or nil.
func (c *common) lookupChannel(id uint16) *Channel {
        c.mu.RLock()
        defer c.mu.RUnlock()
        return c.channels[id]
}

// unregisterChannel removes a channel from the map. No-op if absent.
func (c *common) unregisterChannel(id uint16) {
        c.mu.Lock()
        defer c.mu.Unlock()
        delete(c.channels, id)
}

// channelCount returns the current number of open channels.
func (c *common) channelCount() int {
        c.mu.RLock()
        defer c.mu.RUnlock()
        return len(c.channels)
}

// closeAllChannels closes every registered channel. Used during shutdown.
func (c *common) closeAllChannels() {
        c.mu.Lock()
        defer c.mu.Unlock()
        for _, ch := range c.channels {
                ch.closeLocal("tunnel shutdown")
        }
        c.channels = make(map[uint16]*Channel)
}

// writePump drains the send queue and writes each frame to the underlying
// TLS connection. It runs as a single goroutine per tunnel session —
// concurrent writers would interleave partial frames on the wire.
//
// To maximize throughput we batch aggressively: after dequeuing the first
// frame we drain ALL remaining frames in the queue (up to the batch buffer
// capacity) and concatenate them into a single buffer, then issue one
// Write() call. This amortizes TLS record framing + syscall overhead
// across many frames.
//
// The batch buffer is 1 MB — enough for ~15 full-size (64 KB) frames.
// It is allocated once per pump and reused via slice reslicing.
func (c *common) writePump() {
        defer c.Close()

        // 1 MB batch buffer — large enough to hold a full burst of frames
        // without reallocation. Each appendFrame grows the slice in place
        // until cap is reached, at which point we flush and start over.
        batch := make([]byte, 0, 1024*1024)

        for {
                select {
                case <-c.ctx.Done():
                        return
                case f := <-c.send:
                        batch = batch[:0]
                        batch = appendFrame(batch, f)
                        c.stats.FramesOut.Add(1)
                        c.stats.BytesOut.Add(int64(len(f.Payload)))

                        // Drain ALL pending frames — not just a fixed count.
                        // Keep pulling as long as there's data immediately
                        // available and we have room in the batch buffer.
                        // This is the key to high throughput: a single TLS
                        // write can carry an entire burst of frames.
                        for len(batch) < cap(batch)-(protocol.MaxPayloadSize+protocol.FrameHeaderSize) {
                                select {
                                case more := <-c.send:
                                        batch = appendFrame(batch, more)
                                        c.stats.FramesOut.Add(1)
                                        c.stats.BytesOut.Add(int64(len(more.Payload)))
                                default:
                                        // No more frames immediately available.
                                        // Flush what we have rather than waiting.
                                        goto flush
                                }
                        }

                flush:
                        if err := c.wr.WriteRaw(batch); err != nil {
                                return
                        }
                }
        }
}

// appendFrame marshals f into dst and returns the extended slice.
func appendFrame(dst []byte, f *protocol.Frame) []byte {
        n := len(dst)
        dst = append(dst, make([]byte, protocol.FrameHeaderSize+len(f.Payload))...)
        dst[n] = f.Type
        dst[n+1] = byte(f.ChannelID >> 8)
        dst[n+2] = byte(f.ChannelID)
        dst[n+3] = byte(len(f.Payload) >> 8)
        dst[n+4] = byte(len(f.Payload))
        copy(dst[n+5:], f.Payload)
        return dst
}

// keepaliveInterval is how often the client sends a KEEPALIVE frame when
// the tunnel is otherwise idle. It's the cheapest way to detect a dead
// peer (TCP keepalive alone can take 10+ minutes to notice a NAT has
// dropped state).
const keepaliveInterval = 25 * time.Second

// keepaliveTimeout is how long we wait for a KEEPALIVE_ACK before declaring
// the tunnel dead.
const keepaliveTimeout = 60 * time.Second
