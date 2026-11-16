package monitor

import (
	"context"
	"easy_proxies/internal/config"
	"easy_proxies/internal/geoip"
	"easy_proxies/internal/ipmeta"
)

// EnrichExit is called after discovery and when real traffic uses a member.
// API request lanes and successful results are shared across runtime reloads.
func (m *Manager) EnrichExit(ctx context.Context, h *EntryHandle, used bool) {
	if m == nil || m.Metadata == nil || h == nil || h.ref == nil {
		return
	}
	version := m.Metadata.Version()
	h.ref.mu.Lock()
	h.ref.metadataUsed = h.ref.metadataUsed || used
	if h.ref.metadataPending || h.ref.info.ExitIP == "" || h.ref.metadataVersion == version && (!h.ref.metadataUsed || h.ref.metadataUsageDone) {
		h.ref.mu.Unlock()
		return
	}
	h.ref.metadataPending = true
	info := h.ref.info
	h.ref.mu.Unlock()
	go func() {
		defer func() { h.ref.mu.Lock(); h.ref.metadataPending = false; h.ref.mu.Unlock() }()
		if info.OriginalName == "" {
			info.OriginalName = info.Name
		}
		if m.Metadata.HasInfo() {
			if location, err := m.Metadata.Lookup(ctx, info.ExitIP); err == nil {
				info.CountryCode = location.ISO
				info.Country = location.Country
				info.Region = geoip.RegionForISO(location.ISO)
				info.Provider = location.Org
				info.ASN = location.ASN
				info.OrgDomain = location.Domain
			}
		}
		h.ref.mu.RLock()
		wasUsed := h.ref.metadataUsed
		h.ref.mu.RUnlock()
		if m.Metadata.HasAbuse() && (wasUsed || !ipmeta.Hosting(info.Provider)) {
			node := config.NodeConfig{URI: info.URI}
			if abuse, err := m.Metadata.Check(ctx, node.NodeKey(), info.ExitIP); err == nil {
				info.Abuse = &abuse
				info.NetworkType = abuse.NetworkType()
			}
		}
		var score *int
		if info.Abuse != nil {
			score = info.Abuse.Score
		}
		info.OrgShort = ipmeta.ShortOrg(info.Provider, info.OrgDomain)
		info.Name = ipmeta.DisplayName(info.OriginalName, info.CountryCode, info.ExitIP, info.Provider, info.OrgDomain, info.NetworkType, score)
		h.ref.mu.Lock()
		h.ref.info = info
		if ctx.Err() == nil {
			h.ref.metadataVersion = version
			h.ref.metadataUsageDone = wasUsed
		}
		h.ref.mu.Unlock()
	}()
}
