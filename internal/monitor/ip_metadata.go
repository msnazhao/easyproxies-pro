package monitor

import (
	"context"
	"time"

	"easy_proxies/internal/ipmeta"
)

const enrichWorkerCount = 4

// EnrichExit is called after discovery and when real traffic uses a member.
// API request lanes and successful results are shared across runtime reloads.
func (m *Manager) EnrichExit(ctx context.Context, h *EntryHandle, used bool) {
	m.enrichExit(ctx, h, used, false)
}

// RefreshExitMetadata checks the AbuseIPDB cache for an active exit when due.
func (m *Manager) RefreshExitMetadata(ctx context.Context, h *EntryHandle) {
	m.enrichExit(ctx, h, true, true)
}

func (m *Manager) ensureEnrichWorkers() {
	m.enrichOnce.Do(func() {
		m.enrichCh = make(chan enrichTask, 4096)
		for range enrichWorkerCount {
			go m.runEnrichWorker()
		}
	})
}

func (m *Manager) runEnrichWorker() {
	for {
		select {
		case <-m.ctx.Done():
			return
		case task := <-m.enrichCh:
			m.processEnrichTask(task)
		}
	}
}

func (m *Manager) enrichExit(ctx context.Context, h *EntryHandle, used, refresh bool) {
	if m == nil || m.Metadata == nil || h == nil || h.ref == nil {
		return
	}
	if ctx == nil {
		ctx = m.ctx
	}
	if m.ctx.Err() != nil || ctx.Err() != nil {
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

	m.ensureEnrichWorkers()
	task := enrichTask{
		ctx:         ctx,
		handle:      h,
		info:        info,
		generation:  generation,
		needsEnrich: needsEnrichment,
		hasAbuse:    hasAbuse,
		version:     version,
	}
	select {
	case m.enrichCh <- task:
	default:
		h.ref.mu.Lock()
		h.ref.metadataPending = false
		h.ref.mu.Unlock()
	}
}

func (m *Manager) processEnrichTask(task enrichTask) {
	ctx := task.ctx
	h := task.handle
	info := task.info
	generation := task.generation
	needsEnrichment := task.needsEnrich
	hasAbuse := task.hasAbuse
	version := task.version

	defer func() {
		h.ref.mu.Lock()
		h.ref.metadataPending = false
		followUp := m.ctx.Err() == nil && ctx.Err() == nil && h.ref.info.ExitIP != "" &&
			(h.ref.exitGeneration != generation || h.ref.metadataUsed && !h.ref.metadataUsageDone)
		h.ref.mu.Unlock()
		if followUp {
			m.EnrichExit(ctx, h, false)
		}
	}()

	if m.ctx.Err() != nil || ctx.Err() != nil {
		return
	}
	var location ipmeta.Location
	if needsEnrichment && m.Metadata.HasInfo() {
		if result, err := m.Metadata.Lookup(ctx, info.ExitIP); err == nil {
			location = result
			info.mergeExitLocation(location)
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
	if m.ctx.Err() != nil || ctx.Err() != nil || h.ref.exitGeneration != generation {
		h.ref.mu.Unlock()
		return
	}
	h.ref.info.mergeExitLocation(location)
	h.ref.info.Abuse = info.Abuse
	h.ref.info.NetworkType = info.NetworkType
	formatNodeName(&h.ref.info)
	h.ref.metadataVersion = version
	h.ref.metadataUsageDone = wasUsed
	h.ref.nextAbuseCheck = time.Now().Add(time.Hour)
	h.ref.mu.Unlock()
}
