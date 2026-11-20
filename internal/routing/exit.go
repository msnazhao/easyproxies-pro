package routing

import (
	"net/netip"
	"strings"
)

// ExitSessionName generates the canonical suffix, or an empty string for an invalid exit.
func ExitSessionName(ip netip.Addr) string {
	if !isSessionExit(ip) {
		return ""
	}
	return "_ip_" + strings.ReplaceAll(ip.Unmap().String(), ":", "-")
}

// ParseExitSession parses a reserved exit IP suffix. A reserved but malformed
// suffix yields an invalid address, so callers can reject it during auth.
func ParseExitSession(name string) (netip.Addr, bool) {
	address, ok := strings.CutPrefix(name, "_ip_")
	if !ok {
		return netip.Addr{}, false
	}
	// HTTP Basic usernames cannot contain a colon. IPv6 uses hyphens on the wire.
	if strings.Contains(address, ":") {
		return netip.Addr{}, true
	}
	ip, err := netip.ParseAddr(strings.ReplaceAll(address, "-", ":"))
	if err != nil {
		return netip.Addr{}, true
	}
	if !isSessionExit(ip) {
		return netip.Addr{}, true
	}
	return ip.Unmap(), true
}

func isSessionExit(ip netip.Addr) bool {
	return ip.Zone() == "" && ip.IsGlobalUnicast() && !ip.IsPrivate()
}
