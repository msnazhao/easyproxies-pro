package monitor

import (
	"context"
	"easy_proxies/internal/ipmeta"
	"net/netip"
	"testing"
	"time"
)

func TestExitLookupRunsOnceUntilReload(t *testing.T) {
	m, _ := NewManager(Config{})
	defer m.Stop()
	h := m.Register(NodeInfo{Tag: "a", EntryISO: "JP", EntryCountry: "Japan", Region: "other"})
	h.MarkInitialCheckDone(true)
	h.RecordSuccessWithLatency(time.Millisecond)
	if !h.BeginExitLookup(false) || h.BeginExitLookup(false) {
		t.Fatal("concurrent lookups were not coalesced")
	}
	h.SetExit(ipmeta.Location{IP: "8.8.8.8", ISO: "US", Country: "United States", Org: "Example ISP"})
	h.EndExitLookup("")
	if h.BeginExitLookup(true) {
		t.Fatal("confirmed exit was looked up again")
	}
	snap := m.Snapshot()[0]
	if snap.Region != "us" || snap.EntryISO != "JP" || snap.CountryCode != "US" || snap.Provider != "Example ISP" {
		t.Fatalf("entry/exit location not preserved: %+v", snap.NodeInfo)
	}
	m.ClearNodes()
	h = m.Register(NodeInfo{Tag: "a"})
	h.MarkInitialCheckDone(true)
	h.RecordSuccessWithLatency(time.Millisecond)
	if !h.BeginExitLookup(false) {
		t.Fatal("healthy node with cleared measurements could not start a lookup")
	}
}

func TestIdleExitRemainsCandidateButRequiresFreshIPForDial(t *testing.T) {
	m, _ := NewManager(Config{})
	defer m.Stop()
	h := m.Register(NodeInfo{Tag: "a", Name: "Original"})
	ip := netip.MustParseAddr("8.8.8.8")
	h.SetExit(ipmeta.Location{IP: ip.String(), ISO: "US"})
	h.MarkInitialCheckDone(true)
	h.RecordSuccessWithLatency(time.Millisecond)
	if h.ExitRouteLatency(ip, time.Now()) == 0 {
		t.Fatal("fresh verified exit was excluded")
	}
	h.ref.mu.Lock()
	h.ref.lastProbeAt = time.Now().Add(-exitRoutingTTL)
	h.ref.mu.Unlock()
	h.RecordSuccess()
	if h.ExitRouteLatency(ip, time.Now()) == 0 {
		t.Fatal("idle health measurement hid a still-verified exit")
	}
	h.RecordSuccessWithLatency(time.Millisecond)
	h.ref.mu.Lock()
	h.ref.exitVerifiedAt = time.Now().Add(-exitRoutingTTL)
	h.ref.mu.Unlock()
	if h.ExitCandidateLatency(ip, time.Now()) == 0 || h.ExitRouteLatency(ip, time.Now()) != 0 {
		t.Fatal("stale exit did not require verification before use")
	}
	done, start := h.QueueExitLookup(true)
	shared, duplicate := h.QueueExitLookup(true)
	if !start || duplicate || done == nil || done != shared {
		t.Fatal("concurrent traffic did not share the stale-exit verification")
	}
	h.SetExit(ipmeta.Location{IP: "1.1.1.1", ISO: "AU"})
	h.EndExitLookup("")
	<-done
	if got := m.Snapshot()[0]; got.OriginalName != "Original" || got.ExitIP != "1.1.1.1" {
		t.Fatalf("IP refresh changed identity or failed to publish new address: %+v", got)
	}
	h.InvalidateExit()
	if got := m.Snapshot()[0]; got.ExitIP != "" || !got.ExitVerifiedAt.IsZero() {
		t.Fatalf("disputed address remained published: %+v", got)
	}
}

func TestPeriodicHealthSweepOnlyProbesNodesInUse(t *testing.T) {
	m, _ := NewManager(Config{})
	defer m.Stop()
	var activeCalls, recentCalls, idleCalls int
	active := m.Register(NodeInfo{Tag: "active"})
	active.SetProbe(func(context.Context) (time.Duration, error) {
		activeCalls++
		return time.Millisecond, nil
	})
	recent := m.Register(NodeInfo{Tag: "recent"})
	recent.SetProbe(func(context.Context) (time.Duration, error) {
		recentCalls++
		return time.Millisecond, nil
	})
	idle := m.Register(NodeInfo{Tag: "idle"})
	idle.SetProbe(func(context.Context) (time.Duration, error) {
		idleCalls++
		return time.Millisecond, nil
	})
	active.IncActive()
	recent.IncActive()
	recent.DecActive()
	idle.ref.lastUsedAt.Store(time.Now().Add(-time.Hour).UnixNano())
	m.probeNodes(time.Second, time.Now().Add(-5*time.Minute))
	if activeCalls != 1 || recentCalls != 1 || idleCalls != 0 {
		t.Fatalf("periodic sweep called active=%d, recent=%d, idle=%d", activeCalls, recentCalls, idleCalls)
	}
	active.DecActive()
	m.ProbeAllNow(time.Second)
	if activeCalls != 2 || recentCalls != 2 || idleCalls != 1 {
		t.Fatalf("full sweep called active=%d, recent=%d, idle=%d", activeCalls, recentCalls, idleCalls)
	}
}

func TestUnknownExitRetriesOnlyAfterTrafficAndCooldown(t *testing.T) {
	m, _ := NewManager(Config{})
	defer m.Stop()
	h := m.Register(NodeInfo{Tag: "unknown"})
	h.MarkInitialCheckDone(true)
	h.RecordSuccessWithLatency(time.Millisecond)
	if !h.BeginExitLookup(false) {
		t.Fatal("first lookup required traffic")
	}
	h.EndExitLookup("rate_limited")
	if h.BeginExitLookup(true) {
		t.Fatal("traffic bypassed cooldown")
	}
	h.ref.mu.Lock()
	h.ref.exitAttemptedAt = time.Now().Add(-exitRefreshInterval)
	h.ref.mu.Unlock()
	if h.BeginExitLookup(false) {
		t.Fatal("idle node retried")
	}
	h.MarkAvailable(false)
	if h.BeginExitLookup(true) {
		t.Fatal("unhealthy node retried")
	}
	h.MarkAvailable(true)
	if !h.BeginExitLookup(true) {
		t.Fatal("due exit was not retried after traffic")
	}
}

func TestReloadRetainsExitAttemptsWithoutReusingUnhealthyNodes(t *testing.T) {
	m, _ := NewManager(Config{})
	defer m.Stop()
	failed := NodeInfo{Tag: "failed", URI: "vless://failed@upstream.example:443"}
	verified := NodeInfo{Tag: "verified", URI: "vless://verified@upstream.example:443"}
	h := m.Register(failed)
	h.MarkInitialCheckDone(true)
	h.RecordSuccessWithLatency(time.Millisecond)
	if !h.BeginExitLookup(false) {
		t.Fatal("first lookup did not start")
	}
	h.EndExitLookup("rate_limited")
	m.Register(verified).SetExit(ipmeta.Location{IP: "8.8.8.8", ISO: "US"})

	finish := m.BeginNodeReload()
	defer finish()
	failed.Tag = "renamed"
	h = m.Register(failed)
	h.MarkInitialCheckDone(true)
	h.RecordSuccessWithLatency(time.Millisecond)
	if h.BeginExitLookup(false) || h.ref.snapshot().ExitProbeStatus != "rate_limited" {
		t.Fatal("failed exit lookup was forgotten on reload")
	}
	h = m.Register(verified)
	ip := netip.MustParseAddr("8.8.8.8")
	if h.ref.snapshot().ExitIP != ip.String() || h.ExitRouteLatency(ip, time.Now()) != 0 {
		t.Fatal("reload lost the confirmed exit or allowed routing without healthy status")
	}
	h.MarkInitialCheckDone(true)
	h.RecordSuccessWithLatency(time.Millisecond)
	if h.ExitRouteLatency(ip, time.Now()) == 0 {
		t.Fatal("healthy node could not reuse the confirmed exit after reload")
	}
}
