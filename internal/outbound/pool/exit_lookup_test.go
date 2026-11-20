package pool

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"easy_proxies/internal/ipmeta"
	"easy_proxies/internal/monitor"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

func TestLookupExitRequiresAgreement(t *testing.T) {
	const ipify = `{"ip":"8.8.8.8"}`
	const ipapi = `{"ip":"8.8.8.8","country_code":"us","country_name":"United States","org":"Example ISP"}`
	const ipinfo = `{"ip":"8.8.8.8","country_code":"US","country":"United States","as_name":"Example ISP","asn":"AS1234"}`
	for _, tc := range []struct {
		name, echo, fallback, keyed, wantASN, wantError, wantFirst string
		addressOnly                                                bool
	}{
		{name: "no-key", echo: ipify, fallback: ipapi, wantFirst: "/echo"},
		{name: "valid-key", echo: ipify, keyed: ipinfo, wantASN: "AS1234", wantFirst: "/lite/me"},
		{name: "address-only-keyed", echo: ipify, keyed: ipify, wantFirst: "/lite/me", addressOnly: true},
		{name: "address-only-keyless", echo: ipify, fallback: ipify, wantFirst: "/echo", addressOnly: true},
		{name: "unknown-country", echo: ipify, fallback: `{"ip":"8.8.8.8","country_code":"ZZ"}`, wantFirst: "/echo", addressOnly: true},
		{name: "unavailable-key", echo: ipify, fallback: ipapi, keyed: "unauthorized", wantFirst: "/lite/me"},
		{name: "keyed-mismatch", echo: ipify, fallback: ipapi, keyed: strings.Replace(ipinfo, "8.8.8.8", "1.1.1.1", 1), wantError: "exit probes disagree"},
		{name: "no-key-mismatch", echo: ipify, fallback: strings.Replace(ipapi, "8.8.8.8", "1.1.1.1", 1), wantError: "exit probes disagree"},
		{name: "private-echo", echo: `{"ip":"10.1.2.3"}`, wantError: "invalid IPify exit address"},
		{name: "unavailable-echo", fallback: ipapi, wantError: "IPify exit probe"},
		{name: "unavailable-location", echo: ipify, wantError: "ipapi.co exit probe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case requests <- r.URL.Path:
				default:
				}
				var body string
				switch r.URL.Path {
				case "/echo":
					body = tc.echo
				case "/location":
					body = tc.fallback
				case "/lite/me":
					if r.Header.Get("Authorization") != "Bearer test-key" || tc.keyed == "unauthorized" {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					body = tc.keyed
				}
				if body == "" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			var metadata *ipmeta.Service
			if tc.keyed != "" {
				metadata = ipmeta.New()
				defer metadata.Close()
				metadata.InfoURL = server.URL + "/lite/"
				metadata.Configure(ipmeta.Config{IPinfoKeys: []string{"test-key"}})
			}
			location, err := lookupExitFrom(context.Background(), server.Client(), server.URL+"/echo", server.URL+"/location", metadata)
			if tc.wantFirst != "" {
				select {
				case first := <-requests:
					if first != tc.wantFirst {
						t.Fatalf("first request = %q, want %q", first, tc.wantFirst)
					}
				default:
					t.Fatal("no probe request received")
				}
			}
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) || location.IP != "" {
					t.Fatalf("lookup = %+v, %v; want unclassified exit with error %q", location, err, tc.wantError)
				}
				return
			}
			want := ipmeta.Location{IP: "8.8.8.8", ASN: tc.wantASN}
			if !tc.addressOnly {
				want.ISO, want.Country, want.Org = "US", "United States", "Example ISP"
			}
			if err != nil || location != want {
				t.Fatalf("lookup = %+v, %v", location, err)
			}
		})
	}
}

type exitDiscoveryTestOutbound struct {
	*sessionTestOutbound
	healthConn net.Conn
	exitDial   chan struct{}
}

func (o *exitDiscoveryTestOutbound) DialContext(_ context.Context, _ string, destination M.Socksaddr) (net.Conn, error) {
	if destination.Fqdn == "health.test" {
		return o.healthConn, nil
	}
	select {
	case o.exitDial <- struct{}{}:
	default:
	}
	return nil, errors.New("fixture exit discovery failure")
}

func TestFirstExitLookupRequiresSuccessfulHealthProbe(t *testing.T) {
	for _, tc := range []struct {
		name, response string
		wantLookup     bool
	}{
		{name: "healthy", response: "HTTP/1.1 204 No Content\r\n\r\n", wantLookup: true},
		{name: "unhealthy", response: "HTTP/1.1 503 Service Unavailable\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, _ := monitor.NewManager(monitor.Config{ProbeTarget: "http://health.test"})
			defer manager.Stop()
			node := newSessionTestOutbound(tc.name)
			conn, _ := localProbeResponse(t, tc.response)
			exitDial := make(chan struct{}, 1)
			p := newSessionTestPool(nil, node)
			p.monitor = manager
			member := p.members[0]
			member.outbound = &exitDiscoveryTestOutbound{node, conn, exitDial}
			member.entry = manager.Register(monitor.NodeInfo{Tag: member.tag})
			p.setMemberProbe(member)
			if err := p.Start(adapter.StartStateStarted); err != nil {
				t.Fatal(err)
			}
			member.entry.MarkInitialCheckDone(true)
			p.scheduleExitLookup(member, true)
			if status := manager.Snapshot()[0].ExitProbeStatus; status != "" {
				t.Fatalf("exit scheduled without a successful health check: %s", status)
			}
			_, err := manager.Probe(context.Background(), member.tag)
			if (err == nil) != tc.wantLookup {
				t.Fatalf("health check returned %v", err)
			}
			if !tc.wantLookup {
				if status := manager.Snapshot()[0].ExitProbeStatus; status != "" {
					t.Fatalf("failed health check scheduled an exit lookup: %s", status)
				}
				return
			}
			select {
			case <-exitDial:
			case <-time.After(time.Second):
				t.Fatal("successful health check did not start discovery without traffic")
			}
		})
	}
}

func TestExitLookupIdentifiesProviderRateLimits(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusOK} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/echo" {
					_, _ = w.Write([]byte(`{"ip":"8.8.8.8"}`))
					return
				}
				w.WriteHeader(code)
				_, _ = w.Write([]byte(`{"error":true,"reason":"RateLimited"}`))
			}))
			defer server.Close()
			_, err := lookupExitFrom(context.Background(), server.Client(), server.URL+"/echo", server.URL+"/location", nil)
			if !errors.Is(err, errExitProbeRateLimited) {
				t.Fatalf("provider rate limit returned %v", err)
			}
		})
	}
}
