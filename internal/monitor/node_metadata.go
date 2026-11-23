package monitor

import (
	"net/netip"
	"strings"
	"time"

	"easy_proxies/internal/config"
	"easy_proxies/internal/geoip"
	"easy_proxies/internal/ipmeta"
)

func sameNodeIdentity(a, b NodeInfo) bool {
	return nodeIdentity(a) == nodeIdentity(b)
}

func nodeIdentity(info NodeInfo) string {
	node := config.NodeConfig{URI: info.URI}
	return node.NodeKey()
}

type nodeMeasurements struct {
	info             NodeInfo
	exitIP           netip.Addr
	exitVerifiedAt   time.Time
	exitAttemptedAt  time.Time
	exitProbeFailure string
	lastProbe        time.Duration
	lastProbeAt      time.Time
	lastOK           time.Time
	healthy          bool
	wasAvailable     bool
	blacklisted      bool
	blacklistedUntil time.Time
	lastError        string
}

func (m nodeMeasurements) restore(e *entry) {
	e.exitAttemptedAt = m.exitAttemptedAt
	e.exitProbeFailure = m.exitProbeFailure
	if m.exitIP.IsValid() {
		copyExitMetadata(&e.info, m.info)
		formatNodeName(&e.info)
		e.exitIP, e.exitVerifiedAt = m.exitIP, m.exitVerifiedAt
	}
	if m.blacklisted {
		e.blacklist = true
		e.until = m.blacklistedUntil
		e.lastError = m.lastError
		e.initialCheckDone = true
		e.available = m.wasAvailable
		e.needsRecoveryProbe = !m.wasAvailable
		e.syncFastStateLocked()
		return
	}
	if m.healthy {
		e.lastProbe, e.lastProbeAt, e.lastOK = m.lastProbe, m.lastProbeAt, m.lastOK
		e.initialCheckDone, e.available = true, true
		e.syncFastStateLocked()
	}
}

// Only derived fields are copied. Listen addresses, ports, URI and original
// names remain owned by registration, including during an in-flight lookup.
func copyExitMetadata(dst *NodeInfo, src NodeInfo) {
	dst.ExitIP = src.ExitIP
	dst.CountryCode = src.CountryCode
	dst.Country = src.Country
	dst.Region = src.Region
	dst.Provider = src.Provider
	dst.ASN = src.ASN
	dst.OrgDomain = src.OrgDomain
	dst.OrgShort = src.OrgShort
	dst.NetworkType = src.NetworkType
	dst.Abuse = src.Abuse
}

func (info *NodeInfo) mergeExitLocation(location ipmeta.Location) {
	if iso := geoip.NormalizeCountryCode(location.ISO); iso != geoip.UnknownCountryCode {
		country := strings.TrimSpace(location.Country)
		if info.CountryCode != iso || country != "" {
			info.Country = country
		}
		info.CountryCode = iso
		info.Region = geoip.RegionForISO(iso)
	} else if info.ExitIP != "" && geoip.NormalizeCountryCode(info.CountryCode) == geoip.UnknownCountryCode {
		info.CountryCode = geoip.UnknownCountryCode
		info.Country = ""
		info.Region = ""
	}
	if provider := strings.TrimSpace(location.Org); provider != "" {
		info.Provider = provider
	}
	if asn := strings.TrimSpace(location.ASN); asn != "" {
		info.ASN = asn
	}
	if domain := strings.TrimSpace(location.Domain); domain != "" {
		info.OrgDomain = domain
	}
}

func formatNodeName(info *NodeInfo) {
	if info.OriginalName == "" {
		info.OriginalName = info.Name
	}
	var score *int
	if info.Abuse != nil {
		score = info.Abuse.Score
	}
	info.OrgShort = ipmeta.ShortOrg(info.Provider, info.OrgDomain)
	info.Name = ipmeta.DisplayName(info.OriginalName, info.CountryCode, info.ExitIP, info.Provider, info.OrgDomain, info.NetworkType, score)
}
