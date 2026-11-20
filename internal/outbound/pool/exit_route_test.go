package pool

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"easy_proxies/internal/monitor"
	"easy_proxies/internal/routing"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestExitRouteOnlyRetriesDistinctVerifiedNodes(t *testing.T) {
	other := newSessionTestOutbound("other")
	fast := newSessionTestOutbound("fast", N.NetworkTCP)
	backup := newSessionTestOutbound("backup")
	p := newSessionTestPool(nil, other, fast, backup)
	mgr, _ := monitor.NewManager(monitor.Config{})
	defer mgr.Stop()

	ip := netip.MustParseAddr("8.8.8.8")
	for i, member := range p.members {
		entry := mgr.Register(monitor.NodeInfo{Tag: member.tag})
		entry.MarkInitialCheckDone(true)
		entry.RecordSuccessWithLatency(time.Duration(i+1) * time.Millisecond)
		exit := ip.String()
		if member.tag == "other" {
			exit = "1.1.1.1"
		}
		entry.SetExit(exit, "", "", "", "")
		member.entry = entry
	}
	ctx := routing.WithExitIP(context.Background(), ip)
	mustSessionTestDial(t, ctx, p, "fast")
	packet, err := p.ListenPacket(ctx, M.ParseSocksaddr("example.test:53"))
	if err != nil {
		t.Fatal(err)
	}
	if tag := packet.LocalAddr().String(); tag != "backup" {
		t.Errorf("UDP used %s, want backup", tag)
	}
	packet.Close()

	fast.setDialHook(func(context.Context) error {
		p.members[1].entry.SetExit("1.1.1.1", "", "", "", "")
		return nil
	})
	mustSessionTestDial(t, ctx, p, "backup")
	failure := errors.New("upstream failed")
	backup.setDialHook(func(context.Context) error { return failure })
	if _, err := sessionTestDialTag(ctx, p); !errors.Is(err, errNoExitCandidate) {
		t.Fatalf("after exhausting the requested IP: %v", err)
	}
	if calls, _, _ := other.counts(); calls != 0 {
		t.Fatalf("dialed mismatched IP %d times", calls)
	}
	if calls, _, _ := backup.counts(); calls != 2 {
		t.Fatalf("backup dial count = %d, want one success and one failure", calls)
	}
	if bindings := p.sessionStore.List(); len(bindings) != 0 {
		t.Fatalf("strict exit created a sticky binding: %v", bindings)
	}
	p.options.SessionRouting = false
	if _, err := sessionTestDialTag(ctx, p); !errors.Is(err, errExitSessionDisabled) {
		t.Fatalf("disabled strict route: %v", err)
	}
}
