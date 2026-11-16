package pool

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"easy_proxies/internal/monitor"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func localProbeResponse(t *testing.T, response string) (net.Conn, <-chan struct{}) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		request, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			return
		}
		request.Body.Close()
		_, _ = io.WriteString(server, response)
	}()
	t.Cleanup(func() {
		client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("local response worker leaked")
		}
	})
	return client, done
}
func TestHTTPProbeRequiresValidSuccessfulStatusAndBoundedHeaders(t *testing.T) {
	for _, test := range []struct {
		name, response string
		ok             bool
	}{
		{"204", "HTTP/1.1 204 No Content\r\n\r\n", true},
		{"200", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", true},
		{"redirect", "HTTP/1.1 302 Found\r\nLocation: /\r\nContent-Length: 0\r\n\r\n", true},
		{"authentication", "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n", false},
		{"rate-limit", "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n", false},
		{"unavailable", "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n", false},
		{"garbage", "garbage\r\n\r\n", false},
		{"oversized-header", "HTTP/1.1 200 OK\r\nX-Fixture: " + strings.Repeat("x", maxProbeHeaderBytes) + "\r\n\r\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, _ := localProbeResponse(t, test.response)
			_, err := httpProbe(conn, "fixture.test")
			if (err == nil) != test.ok {
				t.Fatalf("httpProbe error = %v, success want %v", err, test.ok)
			}
		})
	}
}
func TestHTTPProbeDoesNotWaitForBody(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		request, err := http.ReadRequest(bufio.NewReader(server))
		if err != nil {
			return
		}
		request.Body.Close()
		_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n")
		<-stop
	}()
	defer func() { close(stop); <-done }()
	result := make(chan error, 1)
	go func() { _, err := httpProbe(client, "fixture.test"); result <- err }()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("probe waited for response body")
	}
}
func TestManualBlacklistSurvivesProbeAndPoolRecovery(t *testing.T) {
	tag := "fixture-manual-ban"
	state := acquireSharedState(tag)
	defer sharedStateStore.Delete(tag)
	blacklistSharedMember(tag, time.Hour)
	if state.releaseIfPermanent(time.Now()) {
		t.Fatal("automatic health success released an operator ban")
	}
	p := newTestPool(state)
	if p.releaseIfAllBlacklistedLocked(time.Now()) {
		t.Fatal("single-member pool recovery released an operator ban")
	}
	// A concurrent fault must not turn an operator ban into an auto-releasable one.
	state.recordFailure(errors.New("handshake failure"), failurePolicy{Threshold: 1, BlacklistDuration: 2 * time.Hour})
	if state.releaseIfPermanent(time.Now()) {
		t.Fatal("concurrent failure lost operator ban policy")
	}
	state.forceRelease()
	if state.isBlacklisted(time.Now()) {
		t.Fatal("explicit release did not clear operator ban")
	}
	blacklistSharedMember(tag, time.Hour)
	if !state.releaseIfPermanent(time.Now().Add(2 * time.Hour)) {
		t.Fatal("expired operator ban did not recover")
	}
}
func TestBalanceRotatesTiesWithoutSelectingBusierMembers(t *testing.T) {
	p := newSessionTestPool(nil, newSessionTestOutbound("a"), newSessionTestOutbound("b"), newSessionTestOutbound("c"))
	p.mode = modeBalance
	p.members[2].shared.active.Store(5)
	counts := map[string]int{}
	for i := 0; i < 30; i++ {
		counts[p.selectByMode(p.members).tag]++
	}
	if counts["a"] != 15 || counts["b"] != 15 || counts["c"] != 0 {
		t.Fatalf("imbalanced tie selections: %v", counts)
	}
	p.members[0].shared.active.Store(2)
	for i := 0; i < 5; i++ {
		if selected := p.selectByMode(p.members); selected.tag != "b" {
			t.Fatalf("selected busier member: %s", selected.tag)
		}
	}
}

func TestBalanceRotatesDistinctExitsAndNodesWithinExit(t *testing.T) {
	p := newSessionTestPool(nil, newSessionTestOutbound("a1"), newSessionTestOutbound("a2"), newSessionTestOutbound("a3"), newSessionTestOutbound("b"))
	p.mode = modeBalance
	mgr, _ := monitor.NewManager(monitor.Config{})
	defer mgr.Stop()
	for i, member := range p.members {
		entry := mgr.Register(monitor.NodeInfo{Tag: member.tag})
		ip := "8.8.8.8"
		if i == 3 {
			ip = "1.1.1.1"
		}
		entry.SetExit(ip, "US", "United States", "us", "ISP")
		member.entry = entry
	}
	counts := map[string]int{}
	previous := ""
	for i := 0; i < 60; i++ {
		member := p.selectByMode(p.members)
		ip := member.entry.ExitIP()
		if ip == previous {
			t.Fatalf("consecutive requests reused exit %s via %s", ip, member.tag)
		}
		previous = ip
		counts[member.tag]++
	}
	if counts["b"] != 30 || counts["a1"] != 10 || counts["a2"] != 10 || counts["a3"] != 10 {
		t.Fatalf("exit/node distribution: %v", counts)
	}
	// Load still takes precedence over exit rotation.
	p.members[3].shared.active.Store(2)
	for i := 0; i < 10; i++ {
		if p.selectByMode(p.members).tag == "b" {
			t.Fatal("exit rotation selected a busier node")
		}
	}
}
func TestSessionIdentityIndexRespectsTriedHealthAndProtocol(t *testing.T) {
	a, b := newSessionTestOutbound("a", N.NetworkTCP), newSessionTestOutbound("b", N.NetworkTCP, N.NetworkUDP)
	p := newSessionTestPool(nil, a, b)
	p.indexMembersLocked()
	member, err := p.pickMemberForSession(N.NetworkTCP, nil, "identity-a")
	if err != nil || member.tag != "a" {
		t.Fatalf("healthy indexed pin = %v, %v", member, err)
	}
	for _, test := range []struct {
		name, network string
		tried         map[string]bool
		ban           bool
	}{
		{"tried", N.NetworkTCP, map[string]bool{"a": true}, false}, {"udp-unsupported", N.NetworkUDP, nil, false}, {"manual-ban", N.NetworkTCP, nil, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.ban {
				p.members[0].shared.mu.Lock()
				p.members[0].shared.blacklisted = true
				p.members[0].shared.blacklistedUntil = time.Now().Add(time.Hour)
				p.members[0].shared.manualUntil = p.members[0].shared.blacklistedUntil
				p.members[0].shared.mu.Unlock()
			}
			member, err := p.pickMemberForSession(test.network, test.tried, "identity-a")
			if err != nil || member.tag != "b" {
				t.Fatalf("ineligible indexed pin was used: %v, %v", member, err)
			}
		})
	}
}

type localProbeOutbound struct {
	*sessionTestOutbound
	conn net.Conn
}

type tlsProbeOutbound struct {
	*sessionTestOutbound
	address string
}

func (o *tlsProbeOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", o.address)
}

func TestHTTPSProbeBlacklistAndExplicitCertificateOverride(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	for _, skipVerify := range []bool{false, true} {
		t.Run(fmt.Sprint("skip=", skipVerify), func(t *testing.T) {
			mgr, err := monitor.NewManager(monitor.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer mgr.Stop()
			entry := mgr.Register(monitor.NodeInfo{Tag: "fixture"})
			entry.SetExit("8.8.8.8", "US", "United States", "us", "Fixture")
			state := &sharedMemberState{}
			state.attachEntry(entry)
			p := newSessionTestPool(nil)
			p.options.BlacklistDuration = time.Hour
			member := &memberState{tag: "fixture", outbound: &tlsProbeOutbound{
				sessionTestOutbound: newSessionTestOutbound("fixture"), address: server.Listener.Addr().String(),
			}, entry: entry, shared: state}
			p.members = []*memberState{member}
			_, err = p.probeMember(context.Background(), member, M.ParseSocksaddr("localhost:443"), "localhost", true, skipVerify)
			if !skipVerify {
				if err == nil || !state.isBlacklisted(time.Now()) || !mgr.Snapshot()[0].Blacklisted {
					t.Fatalf("strict TLS accepted self-signed certificate: err=%v snapshot=%+v", err, mgr.Snapshot()[0])
				}
				if state.releaseIfPermanent(time.Now()) || p.releaseIfAllBlacklistedLocked(time.Now()) {
					t.Fatal("HTTPS failure ban was automatically released")
				}
				state.forceRelease()
				if state.isBlacklisted(time.Now()) {
					t.Fatal("explicit release did not clear HTTPS failure ban")
				}
			} else if err != nil || state.isBlacklisted(time.Now()) {
				t.Fatalf("explicit skip still failed HTTPS handshake: %v", err)
			}
		})
	}
}

func TestHTTPSProbeBadResponseBlacklistsImmediately(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	state := &sharedMemberState{}
	member := &memberState{tag: "bad-response", outbound: &tlsProbeOutbound{
		sessionTestOutbound: newSessionTestOutbound("bad-response"), address: server.Listener.Addr().String(),
	}, shared: state}
	p := newSessionTestPool(nil)
	p.options.BlacklistDuration = time.Hour
	if _, err := p.probeMember(context.Background(), member, M.ParseSocksaddr("localhost:443"), "localhost", true, true); err == nil || !state.isBlacklisted(time.Now()) {
		t.Fatalf("bad HTTPS response did not blacklist: %v", err)
	}
}

func TestExpiredHTTPSBlacklistStillNeedsSuccessfulProbe(t *testing.T) {
	mgr, _ := monitor.NewManager(monitor.Config{})
	defer mgr.Stop()
	entry := mgr.Register(monitor.NodeInfo{Tag: "fixture"})
	entry.MarkInitialCheckDone(true)
	p := newSessionTestPool(nil, newSessionTestOutbound("fixture"))
	member := p.members[0]
	member.entry = entry
	member.shared.attachEntry(entry)
	member.shared.blacklistNow(errors.New("TLS verification failed"), p.failurePolicy(), true)
	entry.MarkAvailable(false)
	member.shared.mu.Lock()
	member.shared.blacklistedUntil = time.Now().Add(-time.Second)
	member.shared.httpsUntil = member.shared.blacklistedUntil
	member.shared.mu.Unlock()
	if _, err := p.pickMemberFiltered(N.NetworkTCP, nil, ""); err == nil {
		t.Fatal("ordinary pool selected a node without a successful HTTPS recheck")
	}
	if _, err := p.pickMemberForSession(N.NetworkTCP, nil, p.memberIdentity(member)); err == nil {
		t.Fatal("named session selected a node without a successful HTTPS recheck")
	}
	entry.MarkAvailable(true)
	if _, err := p.pickMemberFiltered(N.NetworkTCP, nil, ""); err != nil {
		t.Fatalf("successful HTTPS recheck did not restore node: %v", err)
	}
}

func (o *localProbeOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return o.conn, nil
}
func TestCancelledProbeDoesNotRecordNodeFailure(t *testing.T) {
	mgr, err := monitor.NewManager(monitor.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Stop()
	entry := mgr.Register(monitor.NodeInfo{Tag: "fixture"})
	client, server := net.Pipe()
	defer server.Close()
	outbound := &localProbeOutbound{sessionTestOutbound: newSessionTestOutbound("fixture"), conn: client}
	member := &memberState{outbound: outbound, tag: "fixture", entry: entry, shared: &sharedMemberState{}}
	p := newSessionTestPool(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.probeMember(ctx, member, M.ParseSocksaddr("fixture.test:80"), "fixture.test", false, false); err == nil {
		t.Fatal("cancelled probe succeeded")
	}
	if snapshot := mgr.Snapshot()[0]; snapshot.FailureCount != 0 || snapshot.SuccessCount != 0 || snapshot.LastError != "" {
		t.Fatalf("cancelled probe changed node counters: %+v", snapshot)
	}
}

func BenchmarkSessionIdentitySelection(b *testing.B) {
	for _, count := range []int{32, 1024, 8192} {
		b.Run(fmt.Sprintf("nodes=%d", count), func(b *testing.B) {
			nodes := make([]*sessionTestOutbound, count)
			for i := range nodes {
				nodes[i] = newSessionTestOutbound(fmt.Sprintf("node-%d", i))
			}
			p := newSessionTestPool(nil, nodes...)
			p.indexMembersLocked()
			identity := p.memberIdentity(p.members[count-1])
			for _, indexed := range []bool{false, true} {
				name := "normal-scan"
				pin := ""
				if indexed {
					name = "named-session-index"
					pin = identity
				}
				b.Run(name, func(b *testing.B) {
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						if _, err := p.pickMemberForSession(N.NetworkTCP, nil, pin); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func TestClosingPoolCannotRemoveReplacementDialer(t *testing.T) {
	old := newSessionTestPool(nil, newSessionTestOutbound("old"))
	replacement := newSessionTestPool(nil, newSessionTestOutbound("new"))
	tag := old.Tag()
	registerDialer(tag, old)
	registerDialer(tag, replacement)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	dialer, exists := GetDialer(tag)
	if !exists || dialer.(*poolDialerAdapter).pool != replacement {
		t.Fatal("closing old pool removed its replacement")
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if _, exists := GetDialer(tag); exists {
		t.Fatal("closed pool retained a registered dialer")
	}
}
