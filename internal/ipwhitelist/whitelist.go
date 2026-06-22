// Package ipwhitelist implements per-user IP allow-listing with CIDR support.
package ipwhitelist

import (
	"net"
	"strings"
)

// Whitelist is an allow-list of IPs and CIDR ranges.
// A zero-value Whitelist (or one built from an empty slice) allows every
// source IP — this mirrors the Python semantics.
type Whitelist struct {
	entries []net.IPNet
	enabled bool
}

// New parses a list of "ip" or "cidr" strings into a Whitelist.
// Invalid entries are silently skipped (matching the Python behavior).
func New(entries []string) *Whitelist {
	w := &Whitelist{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			// Treat bare IP as /32 (v4) or /128 (v6).
			ip := net.ParseIP(e)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				e += "/32"
			} else {
				e += "/128"
			}
		}
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			continue
		}
		w.entries = append(w.entries, *n)
	}
	if len(entries) > 0 && len(w.entries) > 0 {
		w.enabled = true
	}
	return w
}

// Active reports whether the whitelist has any entries (i.e. it restricts
// access).
func (w *Whitelist) Active() bool { return w != nil && w.enabled }

// Allowed reports whether ip is permitted. If the whitelist is inactive
// (empty) every IP is allowed.
func (w *Whitelist) Allowed(ipStr string) bool {
	if !w.Active() {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range w.entries {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
