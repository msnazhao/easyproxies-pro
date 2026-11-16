package monitor

import "testing"

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
