package prescreen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"easy_proxies/internal/config"
)

func TestFilterStagesAndDeduplication(t *testing.T) {
	liveLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer liveLn.Close()
	go func() {
		for {
			conn, err := liveLn.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	livePort := liveLn.Addr().(*net.TCPAddr).Port

	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := deadLn.Addr().(*net.TCPAddr).Port
	_ = deadLn.Close()

	t.Run("stage0 rejects malformed and private literal IPs by default", func(t *testing.T) {
		nodes := []config.NodeConfig{
			{Name: "empty"},
			{Name: "invalid-scheme", URI: "unsupported://example.com:443#bad"},
			{Name: "private-10", URI: fmt.Sprintf("trojan://pw@10.0.0.1:%d#priv", livePort)},
			{Name: "loopback", URI: fmt.Sprintf("trojan://pw@127.0.0.1:%d#loop", livePort)},
			{Name: "public-tcp", URI: fmt.Sprintf("trojan://pw@1.1.1.1:%d#pub", livePort)},
			{Name: "public-hy2", URI: "hysteria2://pw@1.1.1.1:443#hy2"},
			{Name: "public-tuic", URI: "tuic://00000000-0000-0000-0000-000000000001:pw@1.1.1.1:443#tuic"},
		}
		var tcpCalls atomic.Int32
		res, err := Filter(context.Background(), nodes, Options{
			DialTCP: func(_ context.Context, addr string) error {
				tcpCalls.Add(1)
				if addr == fmt.Sprintf("1.1.1.1:%d", livePort) {
					return nil
				}
				return errors.New("unreachable")
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.Stats.SyntaxOK != 3 || res.Stats.TCPReachable != 1 || res.Stats.UDPPassthrough != 2 || len(res.Nodes) != 3 {
			t.Fatalf("unexpected stats/nodes: %+v len=%d", res.Stats, len(res.Nodes))
		}
		if tcpCalls.Load() != 1 {
			t.Fatalf("expected 1 TCP dial (UDP passthrough skipped), got %d", tcpCalls.Load())
		}
		if res.Nodes[0].Name != "public-tcp" || res.Nodes[1].Name != "public-hy2" || res.Nodes[2].Name != "public-tuic" {
			t.Fatalf("unexpected order: %+v", res.Nodes)
		}
	})

	t.Run("stage1 dedupes DNS prefers IPv4 and filters private resolutions", func(t *testing.T) {
		var mu sync.Mutex
		resolveCounts := map[string]int{}
		dialCounts := map[string]int{}

		nodes := []config.NodeConfig{
			{Name: "domain-a1", URI: fmt.Sprintf("trojan://pw@shared.example:%d#a1", livePort)},
			{Name: "domain-a2", URI: fmt.Sprintf("http://user:pw@shared.example:%d#a2", livePort)},
			{Name: "private-dns", URI: fmt.Sprintf("trojan://pw@internal.example:%d#priv", livePort)},
			{Name: "nxdomain", URI: fmt.Sprintf("trojan://pw@missing.example:%d#nx", livePort)},
		}

		res, err := Filter(context.Background(), nodes, Options{
			ResolveHost: func(_ context.Context, host string) ([]netip.Addr, error) {
				mu.Lock()
				resolveCounts[host]++
				mu.Unlock()
				switch host {
				case "shared.example":
					return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("93.184.216.34")}, nil
				case "internal.example":
					return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
				default:
					return nil, errors.New("nxdomain")
				}
			},
			DialTCP: func(_ context.Context, addr string) error {
				mu.Lock()
				dialCounts[addr]++
				mu.Unlock()
				if addr != fmt.Sprintf("93.184.216.34:%d", livePort) {
					return fmt.Errorf("unexpected endpoint %s", addr)
				}
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if resolveCounts["shared.example"] != 1 || resolveCounts["internal.example"] != 1 || resolveCounts["missing.example"] != 1 {
			t.Fatalf("expected deduplicated DNS lookups, got %+v", resolveCounts)
		}
		if dialCounts[fmt.Sprintf("93.184.216.34:%d", livePort)] != 1 {
			t.Fatalf("expected IPv4 preferred and single TCP dial per endpoint, got %+v", dialCounts)
		}
		if len(res.Nodes) != 2 || res.Nodes[0].Name != "domain-a1" || res.Nodes[1].Name != "domain-a2" {
			t.Fatalf("unexpected surviving nodes: %+v", res.Nodes)
		}
	})

	t.Run("stage2 real loopback dial deduplicates live port and drops dead port", func(t *testing.T) {
		var dialMu sync.Mutex
		dials := map[string]int{}
		nodes := []config.NodeConfig{
			{Name: "live-1", URI: fmt.Sprintf("trojan://p1@127.0.0.1:%d#live1", livePort)},
			{Name: "dead", URI: fmt.Sprintf("trojan://p2@127.0.0.1:%d#dead", deadPort)},
			{Name: "live-2", URI: fmt.Sprintf("http://u:p@127.0.0.1:%d#live2", livePort)},
		}
		res, err := Filter(context.Background(), nodes, Options{
			AllowPrivateIPs: true,
			DNSTimeout:      500 * time.Millisecond,
			TCPTimeout:      500 * time.Millisecond,
			DialTCP: func(ctx context.Context, addr string) error {
				dialMu.Lock()
				dials[addr]++
				dialMu.Unlock()
				conn, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "tcp", addr)
				if err != nil {
					return err
				}
				_ = conn.Close()
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if dials[fmt.Sprintf("127.0.0.1:%d", livePort)] != 1 || dials[fmt.Sprintf("127.0.0.1:%d", deadPort)] != 1 {
			t.Fatalf("unexpected deduplicated dial counts: %+v", dials)
		}
		if len(res.Nodes) != 2 || res.Nodes[0].Name != "live-1" || res.Nodes[1].Name != "live-2" {
			t.Fatalf("unexpected surviving nodes: %+v", res.Nodes)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		started := make(chan struct{})
		nodes := []config.NodeConfig{
			{Name: "block", URI: "trojan://pw@slow.example:443#slow"},
		}
		go func() {
			<-started
			cancel()
		}()
		_, err := Filter(ctx, nodes, Options{
			ResolveHost: func(resolveCtx context.Context, _ string) ([]netip.Addr, error) {
				close(started)
				<-resolveCtx.Done()
				return nil, resolveCtx.Err()
			},
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	})
}
