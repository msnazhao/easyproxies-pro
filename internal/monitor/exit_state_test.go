package monitor

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestExitLookupRunsOnceUntilReload(t *testing.T) {
	m, _ := NewManager(Config{})
	defer m.Stop()
	h := m.Register(NodeInfo{Tag: "a", EntryISO: "JP", EntryCountry: "Japan", Region: "other"})
	if !h.BeginExitLookup() || h.BeginExitLookup() {
		t.Fatal("concurrent lookups were not coalesced")
	}
	h.SetExit("8.8.8.8", "US", "United States", "us", "Example ISP")
	h.EndExitLookup()
	if h.BeginExitLookup() {
		t.Fatal("confirmed exit was looked up again")
	}
	snap := m.Snapshot()[0]
	if snap.Region != "us" || snap.EntryISO != "JP" || snap.CountryCode != "US" || snap.Provider != "Example ISP" {
		t.Fatalf("entry/exit location not preserved: %+v", snap.NodeInfo)
	}
	m.ClearNodes()
	if !m.Register(NodeInfo{Tag: "a"}).BeginExitLookup() {
		t.Fatal("reload should schedule a new exit lookup")
	}
}

func TestExitRouteRequiresRecentHealthAndExitConfirmation(t *testing.T) {
	m, _ := NewManager(Config{})
	defer m.Stop()
	h := m.Register(NodeInfo{Tag: "a", Name: "Original"})
	ip := netip.MustParseAddr("8.8.8.8")
	h.SetExit(ip.String(), "US", "", "", "")
	h.MarkInitialCheckDone(true)
	h.RecordSuccessWithLatency(time.Millisecond)
	if h.ExitRouteLatency(ip, time.Now()) == 0 {
		t.Fatal("fresh verified exit was excluded")
	}
	h.ref.mu.Lock()
	h.ref.lastProbeAt = time.Now().Add(-exitRoutingTTL)
	h.ref.mu.Unlock()
	h.RecordSuccess()
	if h.ExitRouteLatency(ip, time.Now()) != 0 {
		t.Fatal("traffic success revived an expired probe")
	}
	h.RecordSuccessWithLatency(time.Millisecond)
	h.ref.mu.Lock()
	h.ref.exitVerifiedAt = time.Now().Add(-exitRoutingTTL)
	h.ref.mu.Unlock()
	if h.ExitRouteLatency(ip, time.Now()) != 0 || !h.BeginExitLookup() {
		t.Fatal("expired exit was eligible or could not be refreshed")
	}
	h.SetExit("1.1.1.1", "AU", "", "", "")
	h.EndExitLookup()
	if got := m.Snapshot()[0]; got.OriginalName != "Original" || got.ExitIP != "1.1.1.1" {
		t.Fatalf("IP refresh changed identity or failed to publish new address: %+v", got)
	}
	h.InvalidateExit()
	if got := m.Snapshot()[0]; got.ExitIP != "" || !got.ExitVerifiedAt.IsZero() {
		t.Fatalf("disputed address remained published: %+v", got)
	}
}

func TestPeriodicHealthSweepOnlyProbesActiveNodes(t *testing.T) {
	m, _ := NewManager(Config{})
	defer m.Stop()
	var activeCalls, idleCalls int
	active := m.Register(NodeInfo{Tag: "active"})
	active.SetProbe(func(context.Context) (time.Duration, error) {
		activeCalls++
		return time.Millisecond, nil
	})
	idle := m.Register(NodeInfo{Tag: "idle"})
	idle.SetProbe(func(context.Context) (time.Duration, error) {
		idleCalls++
		return time.Millisecond, nil
	})
	active.IncActive()
	m.probeNodes(time.Second, true)
	if activeCalls != 1 || idleCalls != 0 {
		t.Fatalf("periodic sweep called active=%d, idle=%d", activeCalls, idleCalls)
	}
	active.DecActive()
	m.ProbeAllNow(time.Second)
	if activeCalls != 2 || idleCalls != 1 {
		t.Fatalf("full sweep called active=%d, idle=%d", activeCalls, idleCalls)
	}
}
