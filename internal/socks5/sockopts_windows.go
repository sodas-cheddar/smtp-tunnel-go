//go:build windows

package socks5

import "syscall"

// controlFunc is a no-op on Windows. Windows defaults to a permissive
// bind semantics for TCP listeners.
func controlFunc(network, address string, c syscall.RawConn) error { return nil }
