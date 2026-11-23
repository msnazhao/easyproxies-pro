package monitor

import (
	"context"
	"easy_proxies/internal/ipmeta"
	"errors"
	"net/netip"
	"sync/atomic"
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
	m.probeNodes(time.Second, time.Now().Add(-5*time.Minute), false)
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

func TestReloadRetainsHealthyStatusWithoutExitIP(t *testing.T) {
	m, _ := NewManager(Config{})
	defer m.Stop()
	healthyInfo := NodeInfo{Tag: "healthy-no-ip", URI: "vless://healthy@upstream.example:443"}
	unhealthyInfo := NodeInfo{Tag: "unhealthy-with-ip", URI: "vless://unhealthy@upstream.example:443"}

	h := m.Register(healthyInfo)
	h.MarkInitialCheckDone(true)
	h.RecordSuccessWithLatency(15 * time.Millisecond)

	u := m.Register(unhealthyInfo)
	u.SetExit(ipmeta.Location{IP: "8.8.8.8", ISO: "US"})

	finish := m.BeginNodeReload()
	defer finish()

	healthyInfo.Tag = "healthy-reloaded"
	hReloaded := m.Register(healthyInfo)
	if !hReloaded.AvailableFast(time.Now().UnixNano()) {
		t.Fatal("healthy node without exit IP did not stay immediately available after reload")
	}
	snap := hReloaded.ref.snapshot()
	if !snap.InitialCheckDone || !snap.Available || snap.Blacklisted || snap.LastLatencyMs <= 0 {
		t.Fatalf("unexpected healthy snapshot after reload: %+v", snap)
	}

	uReloaded := m.Register(unhealthyInfo)
	ip := netip.MustParseAddr("8.8.8.8")
	if uReloaded.AvailableFast(time.Now().UnixNano()) || uReloaded.ExitRouteLatency(ip, time.Now()) != 0 {
		t.Fatal("unhealthy node became routable after reload")
	}
}

func TestBeginNodeReloadCancelsActiveSweep(t *testing.T) {
	m, _ := NewManager(Config{ProbeTarget: "https://example.com/generate_204"})
	defer m.Stop()

	started := make(chan struct{})
	probeDone := make(chan struct{})
	var probeErr atomic.Value
	h := m.Register(NodeInfo{Tag: "slow-node"})
	h.SetProbe(func(ctx context.Context) (time.Duration, error) {
		defer close(probeDone)
		close(started)
		<-ctx.Done()
		probeErr.Store(ctx.Err())
		return 0, ctx.Err()
	})

	done := make(chan struct{})
	go func() {
		m.ProbeAllNow(5 * time.Second)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe sweep did not start")
	}

	finish := m.BeginNodeReload()
	finish()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("BeginNodeReload did not cancel in-flight probe sweep")
	}
	select {
	case <-probeDone:
	case <-time.After(time.Second):
		t.Fatal("probe callback did not observe cancellation")
	}
	if err, _ := probeErr.Load().(error); err != context.Canceled {
		t.Fatalf("expected context.Canceled on cancelled sweep, got %v", err)
	}
}

func TestProbeUncheckedNowSkipsAlreadyCheckedNodes(t *testing.T) {
	m, _ := NewManager(Config{ProbeTarget: "https://example.com/generate_204"})
	defer m.Stop()

	var checkedCalls, uncheckedCalls atomic.Int32
	checked := m.Register(NodeInfo{Tag: "checked"})
	checked.MarkInitialCheckDone(true)
	checked.RecordSuccessWithLatency(10 * time.Millisecond)
	checked.SetProbe(func(context.Context) (time.Duration, error) {
		checkedCalls.Add(1)
		return time.Millisecond, nil
	})

	unchecked := m.Register(NodeInfo{Tag: "unchecked"})
	unchecked.SetProbe(func(context.Context) (time.Duration, error) {
		uncheckedCalls.Add(1)
		return time.Millisecond, nil
	})

	m.ProbeUncheckedNow(time.Second)

	if checkedCalls.Load() != 0 || uncheckedCalls.Load() != 1 {
		t.Fatalf("ProbeUncheckedNow calls: checked=%d unchecked=%d, want 0 and 1", checkedCalls.Load(), uncheckedCalls.Load())
	}
}

func TestReloadedCooldownAndExpiredBanRecoverCleanly(t *testing.T) {
	t.Run("healthy node on cooldown recovers after ClearBlacklist", func(t *testing.T) {
		m, _ := NewManager(Config{})
		defer m.Stop()
		info := NodeInfo{Tag: "cd", URI: "vless://cd@upstream.example:443"}
		h := m.Register(info)
		h.MarkInitialCheckDone(true)
		h.RecordSuccessWithLatency(10 * time.Millisecond)
		h.Blacklist(time.Now().Add(time.Minute))

		finish := m.BeginNodeReload()
		defer finish()

		h2 := m.Register(info)
		if h2.AvailableFast(time.Now().UnixNano()) {
			t.Fatal("cooled-down node became routable while still blacklisted")
		}
		h2.ClearBlacklist()
		if !h2.AvailableFast(time.Now().UnixNano()) {
			t.Fatal("reloaded cooldown node failed to become available after ClearBlacklist")
		}
	})

	t.Run("expired failed ban triggers recovery probe in periodic sweep", func(t *testing.T) {
		m, _ := NewManager(Config{ProbeTarget: "https://example.com/generate_204"})
		defer m.Stop()
		info := NodeInfo{Tag: "bad", URI: "vless://bad@upstream.example:443"}
		b := m.Register(info)
		b.ref.applyProbeResult(context.Background(), 0, 0, errors.New("boom"))
		b.Blacklist(time.Now().Add(30 * time.Millisecond))

		finish := m.BeginNodeReload()
		defer finish()

		b2 := m.Register(info)
		if b2.AvailableFast(time.Now().UnixNano()) {
			t.Fatal("failed blacklisted node became routable before recovery probe")
		}
		var calls atomic.Int32
		b2.SetProbe(func(context.Context) (time.Duration, error) {
			calls.Add(1)
			return 5 * time.Millisecond, nil
		})
		b2.ref.lastUsedAt.Store(time.Now().Add(-time.Hour).UnixNano())
		time.Sleep(45 * time.Millisecond)
		m.probeNodes(time.Second, time.Now().Add(-5*time.Minute), false)
		if calls.Load() != 1 || !b2.AvailableFast(time.Now().UnixNano()) {
			t.Fatalf("expired failed ban did not recover via periodic sweep: calls=%d avail=%v", calls.Load(), b2.AvailableFast(time.Now().UnixNano()))
		}
	})
}
