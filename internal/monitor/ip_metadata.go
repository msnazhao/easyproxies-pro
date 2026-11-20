package monitor

import (
	"context"
	"time"

	"easy_proxies/internal/geoip"
	"easy_proxies/internal/ipmeta"
)

// EnrichExit is called after discovery and when real traffic uses a member.
// API request lanes and successful results are shared across runtime reloads.
func (m *Manager) EnrichExit(ctx context.Context, h *EntryHandle, used bool) {
	m.enrichExit(ctx, h, used, false)
}

// RefreshExitMetadata checks the AbuseIPDB cache for an active exit when due.
func (m *Manager) RefreshExitMetadata(ctx context.Context, h *EntryHandle) {
	m.enrichExit(ctx, h, true, true)
}

func (m *Manager) enrichExit(ctx context.Context, h *EntryHandle, used, refresh bool) {
	if m == nil || m.Metadata == nil || h == nil || h.ref == nil {
		return
	}
	version := m.Metadata.Version()
	hasAbuse := m.Metadata.HasAbuse()
	h.ref.mu.Lock()
	h.ref.metadataUsed = h.ref.metadataUsed || used
	needsEnrichment := h.ref.metadataVersion != version || h.ref.metadataUsed && !h.ref.metadataUsageDone
	abuseDue := refresh && hasAbuse && time.Now().After(h.ref.nextAbuseCheck)
	if h.ref.metadataPending || h.ref.info.ExitIP == "" || (!needsEnrichment && !abuseDue) {
		h.ref.mu.Unlock()
		return
	}
	h.ref.metadataPending = true
	info := h.ref.info
	generation := h.ref.exitGeneration
	h.ref.mu.Unlock()
	go func() {
		defer func() {
			h.ref.mu.Lock()
			h.ref.metadataPending = false
			followUp := ctx.Err() == nil && h.ref.info.ExitIP != "" &&
				(h.ref.exitGeneration != generation || h.ref.metadataUsed && !h.ref.metadataUsageDone)
			h.ref.mu.Unlock()
			if followUp {
				m.EnrichExit(ctx, h, false)
			}
		}()
		if info.OriginalName == "" {
			info.OriginalName = info.Name
		}
		if needsEnrichment && m.Metadata.HasInfo() {
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
		if hasAbuse && (wasUsed || !ipmeta.Hosting(info.Provider)) {
			if abuse, err := m.Metadata.Check(ctx, info.ExitIP); err == nil {
				info.Abuse = &abuse
				info.NetworkType = abuse.NetworkType()
			}
		}
		h.ref.mu.Lock()
		if ctx.Err() != nil || h.ref.exitGeneration != generation {
			h.ref.mu.Unlock()
			return
		}
		if needsEnrichment {
			h.ref.info.CountryCode = info.CountryCode
			h.ref.info.Country = info.Country
			h.ref.info.Region = info.Region
			h.ref.info.Provider = info.Provider
			h.ref.info.ASN = info.ASN
			h.ref.info.OrgDomain = info.OrgDomain
		}
		h.ref.info.Abuse = info.Abuse
		h.ref.info.NetworkType = info.NetworkType
		formatNodeName(&h.ref.info)
		h.ref.metadataVersion = version
		h.ref.metadataUsageDone = wasUsed
		h.ref.nextAbuseCheck = time.Now().Add(time.Hour)
		h.ref.mu.Unlock()
	}()
}
