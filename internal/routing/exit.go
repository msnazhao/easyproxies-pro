package routing

import (
	"net/netip"
	"strings"
)

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
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, true
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return netip.Addr{}, true
	}
	return ip, true
}
