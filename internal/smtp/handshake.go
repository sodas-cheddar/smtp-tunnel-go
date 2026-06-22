// Package smtp implements the fake-SMTP handshake that disguises the
// tunnel as a legitimate Postfix submission server during DPI inspection.
//
// The handshake is line-oriented (CRLF-terminated) up to and including the
// BINARY marker. After BINARY, the connection switches to raw binary
// frames (see internal/protocol).
//
// Handshake sequence (server side):
//
//	S -> C: 220 <hostname> ESMTP Postfix (Ubuntu)
//	C -> S: EHLO <client>
//	S -> C: 250-<hostname>\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME
//	C -> S: STARTTLS
//	S -> C: 220 2.0.0 Ready to start TLS
//	<TLS handshake>
//	C -> S: EHLO <client>
//	S -> C: 250-<hostname>\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME
//	C -> S: AUTH PLAIN <token>
//	S -> C: 235 2.7.0 Authentication successful
//	C -> S: BINARY
//	S -> C: 299 Binary mode activated
//
// Client side is the mirror image. The handshake is identical to the
// Python implementation so the two are fully interoperable.
package smtp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// HandshakeTimeout is the per-line read deadline during the handshake.
// Five minutes would let a slow attacker hold resources; one minute is
// generous for any legitimate client.
const HandshakeTimeout = 60 * time.Second

// LineReader reads CRLF-terminated SMTP lines from a stream. It is a thin
// wrapper around bufio.Reader so we can read line-by-line during the
// handshake and then hand the buffered reader (and its underlying
// connection) over to the binary frame reader.
type LineReader struct {
	br *bufio.Reader
}

// NewLineReader returns a LineReader with a 64KB buffer — large enough
// that a single EHLO line never causes a partial read.
func NewLineReader(r io.Reader) *LineReader {
	return &LineReader{br: bufio.NewReaderSize(r, 64*1024)}
}

// ReadLine reads one SMTP line, strips the trailing CRLF (or bare LF), and
// returns the trimmed string. Returns io.EOF if the stream closed cleanly.
func (lr *LineReader) ReadLine() (string, error) {
	line, err := lr.br.ReadString('\n')
	if err != nil {
		if len(line) == 0 {
			return "", err
		}
		// Return what we have on EOF/UnexpectedEOF — the caller can
		// decide whether to treat it as a complete line.
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return strings.TrimRight(line, "\r\n"), io.EOF
		}
		return strings.TrimRight(line, "\r\n"), err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// Buffered returns the underlying bufio.Reader so the caller can extract
// any bytes that were already read past the last CRLF (i.e. the start of
// the binary stream). This is critical: after the "299" line, the client
// may immediately start sending binary frames in the same TCP segment.
func (lr *LineReader) Buffered() *bufio.Reader { return lr.br }

// LineWriter writes CRLF-terminated lines to an io.Writer.
type LineWriter struct {
	w io.Writer
}

func NewLineWriter(w io.Writer) *LineWriter { return &LineWriter{w: w} }

// SendLine writes s followed by CRLF.
func (lw *LineWriter) SendLine(s string) error {
	_, err := fmt.Fprintf(lw.w, "%s\r\n", s)
	return err
}

// SendLines writes each string on its own CRLF-terminated line. Useful for
// the multi-line 250- greeting.
func (lw *LineWriter) SendLines(lines []string) error {
	for _, l := range lines {
		if err := lw.SendLine(l); err != nil {
			return err
		}
	}
	return nil
}

// ErrHandshake is returned for any handshake failure. The text is
// suitable for logging; the underlying connection should be closed.
var ErrHandshake = errors.New("smtp: handshake failed")

// Expect250 reads lines until it sees a "250 " (final) response. Lines
// starting with "250-" are treated as continuation. Returns an error if a
// non-250 line is received or the stream ends.
func Expect250(lr *LineReader) error {
	for {
		line, err := lr.ReadLine()
		if err != nil {
			return fmt.Errorf("%w: reading 250 response: %v", ErrHandshake, err)
		}
		switch {
		case strings.HasPrefix(line, "250-"):
			continue
		case strings.HasPrefix(line, "250 "):
			return nil
		default:
			return fmt.Errorf("%w: expected 250, got %q", ErrHandshake, line)
		}
	}
}

// ServerGreeting builds the Postfix-style banner string. It is identical
// to what the Python server emits, so DPI signatures match.
func ServerGreeting(hostname string) string {
	return fmt.Sprintf("220 %s ESMTP Postfix (Ubuntu)", hostname)
}

// ServerCapabilitiesPreTLS returns the EHLO response lines used before
// STARTTLS — they advertise STARTTLS and AUTH.
func ServerCapabilitiesPreTLS(hostname string) []string {
	return []string{
		fmt.Sprintf("250-%s", hostname),
		"250-STARTTLS",
		"250-AUTH PLAIN LOGIN",
		"250 8BITMIME",
	}
}

// ServerCapabilitiesPostTLS returns the EHLO response lines used after
// STARTTLS — STARTTLS is no longer advertised.
func ServerCapabilitiesPostTLS(hostname string) []string {
	return []string{
		fmt.Sprintf("250-%s", hostname),
		"250-AUTH PLAIN LOGIN",
		"250 8BITMIME",
	}
}
