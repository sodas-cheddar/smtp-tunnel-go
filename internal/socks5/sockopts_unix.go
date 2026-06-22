//go:build unix

package socks5

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// controlFunc is the net.ListenConfig.Control callback. On Unix it sets
// SO_REUSEADDR so the SOCKS5 listener can rebind immediately after a
// restart, even if previous connections are still in TIME_WAIT.
func controlFunc(network, address string, c syscall.RawConn) error {
	var setErr error
	err := c.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return setErr
}
