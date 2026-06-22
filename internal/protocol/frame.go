// Package protocol implements the binary multiplexed tunnel frame format.
//
// Wire format (5-byte header + variable payload):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	├───────────────┼───────────────────────────────┼───────────────┤
//	│     Type      │          Channel ID            │    Length     │
//	├───────────────┴───────────────────────────────┴───────────────┤
//	│                          Payload                               │
//	└───────────────────────────────────────────────────────────────┘
//
// Type (1 byte): one of FrameData, FrameConnect, FrameConnectOK, ...
// Channel ID (2 bytes, big-endian): identifies a multiplexed stream
// Length (2 bytes, big-endian): payload size in bytes (max 65535)
// Payload (variable): message-specific bytes
//
// This format is identical to the Python implementation so that a Go client
// can talk to a Python server and vice versa.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame type identifiers.
const (
	FrameData        byte = 0x01 // Tunnel data
	FrameConnect     byte = 0x02 // Open new channel (SOCKS CONNECT)
	FrameConnectOK   byte = 0x03 // Connection established
	FrameConnectFail byte = 0x04 // Connection failed
	FrameClose       byte = 0x05 // Close channel

	// Keepalive frames are an optional Go-extension. They are silently
	// ignored by the Python implementation (no handler in its
	// _handle_frame switch), so we can use them safely without breaking
	// compatibility.
	FrameKeepalive     byte = 0x06
	FrameKeepaliveAck  byte = 0x07

	// FramePing / FramePong are reserved for future RTT measurement.
)

// FrameHeaderSize is the fixed size of every frame header.
const FrameHeaderSize = 5

// MaxPayloadSize is the largest payload a single frame can carry.
const MaxPayloadSize = 65535

// Frame represents a single multiplexed tunnel message.
type Frame struct {
	Type      byte
	ChannelID uint16
	Payload   []byte
}

// Marshal writes the frame into a freshly allocated byte slice.
// The returned slice is suitable for writing to a connection.
func (f *Frame) Marshal() []byte {
	buf := make([]byte, FrameHeaderSize+len(f.Payload))
	buf[0] = f.Type
	binary.BigEndian.PutUint16(buf[1:3], f.ChannelID)
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(f.Payload)))
	copy(buf[5:], f.Payload)
	return buf
}

// MarshalInto writes the frame into the given buffer. The buffer must be at
// least FrameHeaderSize + len(payload) bytes. Returns the number of bytes
// written.
func (f *Frame) MarshalInto(buf []byte) (int, error) {
	total := FrameHeaderSize + len(f.Payload)
	if len(buf) < total {
		return 0, fmt.Errorf("buffer too small: need %d, have %d", total, len(buf))
	}
	buf[0] = f.Type
	binary.BigEndian.PutUint16(buf[1:3], f.ChannelID)
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(f.Payload)))
	copy(buf[5:], f.Payload)
	return total, nil
}

// MakeConnectPayload builds the payload for a FrameConnect message:
//
//	host_len(1) + host + port(2, big-endian)
func MakeConnectPayload(host string, port uint16) []byte {
	hb := []byte(host)
	if len(hb) > 255 {
		// Truncate rather than refuse — DNS labels are <=63 chars and
		// full hostnames are essentially always <255.
		hb = hb[:255]
	}
	p := make([]byte, 1+len(hb)+2)
	p[0] = byte(len(hb))
	copy(p[1:], hb)
	binary.BigEndian.PutUint16(p[1+len(hb):], port)
	return p
}

// ParseConnectPayload reverses MakeConnectPayload.
func ParseConnectPayload(p []byte) (host string, port uint16, err error) {
	if len(p) < 1 {
		return "", 0, errors.New("connect payload too short for length byte")
	}
	hostLen := int(p[0])
	if len(p) < 1+hostLen+2 {
		return "", 0, errors.New("connect payload truncated")
	}
	host = string(p[1 : 1+hostLen])
	port = binary.BigEndian.Uint16(p[1+hostLen:])
	return host, port, nil
}

// Reader is a buffered reader that yields whole frames from an underlying
// stream. It is safe for use by a single goroutine (the tunnel read pump).
type Reader struct {
	r   io.Reader
	buf []byte
	n   int // number of valid bytes in buf
}

// NewReader returns a Reader backed by r. The internal buffer is sized so
// that a single full-size frame plus the next header always fits.
func NewReader(r io.Reader) *Reader {
	return &Reader{
		r:   r,
		buf: make([]byte, FrameHeaderSize+MaxPayloadSize+FrameHeaderSize),
	}
}

// ReadFrame reads one complete frame from the underlying stream. It blocks
// until either a full frame is available, the stream returns EOF, or the
// stream returns any other error.
func (r *Reader) ReadFrame() (*Frame, error) {
	for {
		// Do we already have a full frame buffered?
		if r.n >= FrameHeaderSize {
			payloadLen := int(binary.BigEndian.Uint16(r.buf[3:5]))
			total := FrameHeaderSize + payloadLen
			if r.n >= total {
				f := &Frame{
					Type:      r.buf[0],
					ChannelID: binary.BigEndian.Uint16(r.buf[1:3]),
					Payload:   make([]byte, payloadLen),
				}
				copy(f.Payload, r.buf[FrameHeaderSize:total])
				// Compact buffer.
				copy(r.buf, r.buf[total:r.n])
				r.n -= total
				return f, nil
			}
		}

		// Read more data.
		n, err := r.r.Read(r.buf[r.n:])
		if n > 0 {
			r.n += n
		}
		if err != nil {
			if n > 0 && (err == io.ErrUnexpectedEOF || err == io.EOF) {
				// Try once more to parse what we have before giving up.
				if r.n >= FrameHeaderSize {
					payloadLen := int(binary.BigEndian.Uint16(r.buf[3:5]))
					total := FrameHeaderSize + payloadLen
					if r.n >= total {
						f := &Frame{
							Type:      r.buf[0],
							ChannelID: binary.BigEndian.Uint16(r.buf[1:3]),
							Payload:   make([]byte, payloadLen),
						}
						copy(f.Payload, r.buf[FrameHeaderSize:total])
						r.n = 0
						return f, nil
					}
				}
			}
			if err == io.EOF && r.n == 0 {
				return nil, io.EOF
			}
			return nil, err
		}
	}
}

// Writer is a thin wrapper around an io.Writer that serializes frames.
// Concurrent writes are NOT safe — the tunnel write pump is the only
// goroutine that should call WriteFrame on a given Writer.
type Writer struct {
	w io.Writer
}

func NewWriter(w io.Writer) *Writer { return &Writer{w: w} }

// WriteFrame marshals and writes a single frame.
func (w *Writer) WriteFrame(f *Frame) error {
	buf := f.Marshal()
	_, err := w.w.Write(buf)
	return err
}

// WriteRaw writes a pre-marshaled byte slice. Useful when callers have
// already built the frame bytes and want to avoid an allocation.
func (w *Writer) WriteRaw(p []byte) error {
	_, err := w.w.Write(p)
	return err
}
