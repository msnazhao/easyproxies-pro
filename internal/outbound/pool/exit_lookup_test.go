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
		{name: "invalid-country", echo: ipify, fallback: `{"ip":"8.8.8.8","country_code":"__"}`, wantFirst: "/echo", addressOnly: true},
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
			} else {
				want.ISO = "ZZ"
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

func TestCloudflarePriorityAndDualStackVerification(t *testing.T) {
	const (
		ipv4A = "1.2.3.4"
		ipv4B = "5.6.7.8"
		ipv6A = "2605:6400::1"
		ipv6B = "2605:6400::2"
	)

	t.Run("cloudflare v4 is first priority and plain-text verifier confirms", func(t *testing.T) {
		var order []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, r.URL.Path)
			switch r.URL.Path {
			case "/cf-v4":
				_, _ = w.Write([]byte("fl=1\nip=" + ipv4A + "\nloc=US\n"))
			case "/checkip":
				_, _ = w.Write([]byte(ipv4A + "\n"))
			default:
				w.WriteHeader(http.StatusInternalServerError)
			}
		}))
		defer srv.Close()

		cfg := exitProbeConfig{
			CFTraceV4URL:        srv.URL + "/cf-v4",
			CFTraceV6URL:        srv.URL + "/cf-v6",
			CFTraceDualURL:      srv.URL + "/cf-dual",
			VerifyV4URLs:        []string{srv.URL + "/checkip"},
			VerifyV6URLs:        []string{srv.URL + "/v6-verify"},
			FallbackEchoURL:     srv.URL + "/fallback-echo",
			FallbackLocationURL: srv.URL + "/fallback-loc",
		}
		loc, err := lookupExitWithConfig(context.Background(), srv.Client(), cfg, nil)
		if err != nil {
			t.Fatalf("lookupExitWithConfig failed: %v", err)
		}
		if loc.IP != ipv4A || loc.ISO != "US" {
			t.Fatalf("unexpected location: %+v", loc)
		}
		if len(order) != 2 || order[0] != "/cf-v4" || order[1] != "/checkip" {
			t.Fatalf("unexpected request order: %v", order)
		}
	})

	t.Run("ipv6-only falls back from cf-v4 to cf-v6 and verifies with v6 verifier", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/cf-v4":
				w.WriteHeader(http.StatusBadGateway)
			case "/cf-v6":
				_, _ = w.Write([]byte("ip=" + ipv6A + "\nloc=JP\n"))
			case "/v6-verify":
				_, _ = w.Write([]byte(`{"ip":"` + ipv6A + `"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		cfg := exitProbeConfig{
			CFTraceV4URL: srv.URL + "/cf-v4",
			CFTraceV6URL: srv.URL + "/cf-v6",
			VerifyV4URLs: []string{srv.URL + "/v4-verify"},
			VerifyV6URLs: []string{srv.URL + "/v6-verify"},
		}
		loc, err := lookupExitWithConfig(context.Background(), srv.Client(), cfg, nil)
		if err != nil || loc.IP != ipv6A || loc.ISO != "JP" {
			t.Fatalf("ipv6 lookup = %+v, %v", loc, err)
		}
	})

	t.Run("dual-stack cross-family observation does not trigger false mismatch", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/cf-v4":
				_, _ = w.Write([]byte("ip=" + ipv4A + "\nloc=US\n"))
			case "/lite/me":
				// Keyed endpoint connected via IPv6 on a dual-stack proxy
				_, _ = w.Write([]byte(`{"ip":"` + ipv6A + `","country_code":"US","country":"United States","as_name":"DualISP","asn":"AS1"}`))
			case "/checkip":
				_, _ = w.Write([]byte(ipv4A + "\n"))
			case "/cf-v6":
				_, _ = w.Write([]byte("ip=" + ipv6A + "\nloc=DE\n"))
			case "/v6-dual-returns-v4":
				_, _ = w.Write([]byte(`{"ip":"` + ipv4A + `"}`))
			case "/v6-match":
				_, _ = w.Write([]byte(`{"ip":"` + ipv6A + `"}`))
			default:
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		}))
		defer srv.Close()

		meta := ipmeta.New()
		defer meta.Close()
		meta.InfoURL = srv.URL + "/lite/"
		meta.Configure(ipmeta.Config{IPinfoKeys: []string{"test-key"}})

		cfg := exitProbeConfig{
			CFTraceV4URL: srv.URL + "/cf-v4",
			VerifyV4URLs: []string{srv.URL + "/checkip"},
		}
		loc, err := lookupExitWithConfig(context.Background(), srv.Client(), cfg, meta)
		if err != nil || loc.IP != ipv4A || loc.ISO != "US" {
			t.Fatalf("dual-stack IPv4 with IPv6 ipinfo = %+v, %v", loc, err)
		}

		cfgV6 := exitProbeConfig{
			CFTraceV6URL: srv.URL + "/cf-v6",
			VerifyV6URLs: []string{srv.URL + "/v6-dual-returns-v4", srv.URL + "/v6-match"},
		}
		locV6, err := lookupExitWithConfig(context.Background(), srv.Client(), cfgV6, nil)
		if err != nil || locV6.IP != ipv6A || locV6.ISO != "DE" {
			t.Fatalf("dual-stack IPv6 ignoring v4 echo = %+v, %v", locV6, err)
		}
	})

	t.Run("genuine same-family mismatch rejects both v4 and v6", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/cf-v4":
				_, _ = w.Write([]byte("ip=" + ipv4A + "\nloc=US\n"))
			case "/checkip":
				_, _ = w.Write([]byte(ipv4B))
			case "/cf-v6":
				_, _ = w.Write([]byte("ip=" + ipv6A + "\nloc=US\n"))
			case "/v6-verify":
				_, _ = w.Write([]byte(`{"ip":"` + ipv6B + `"}`))
			}
		}))
		defer srv.Close()

		if _, err := lookupExitWithConfig(context.Background(), srv.Client(), exitProbeConfig{
			CFTraceV4URL: srv.URL + "/cf-v4",
			VerifyV4URLs: []string{srv.URL + "/checkip"},
		}, nil); !errors.Is(err, errExitProbeMismatch) {
			t.Fatalf("expected IPv4 mismatch error, got %v", err)
		}

		if _, err := lookupExitWithConfig(context.Background(), srv.Client(), exitProbeConfig{
			CFTraceV6URL: srv.URL + "/cf-v6",
			VerifyV6URLs: []string{srv.URL + "/v6-verify"},
		}, nil); !errors.Is(err, errExitProbeMismatch) {
			t.Fatalf("expected IPv6 mismatch error, got %v", err)
		}
	})

	t.Run("verifier fallback, rate limit propagation, and non-cf fallback", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/cf-v4":
				_, _ = w.Write([]byte("ip=" + ipv4A + "\nloc=SG\n"))
			case "/rl":
				w.WriteHeader(http.StatusTooManyRequests)
			case "/v4-ok":
				_, _ = w.Write([]byte(`{"ip":"` + ipv4A + `"}`))
			case "/cf-down":
				w.WriteHeader(http.StatusServiceUnavailable)
			case "/fallback-echo":
				_, _ = w.Write([]byte(`{"ip":"` + ipv4A + `"}`))
			case "/fallback-loc":
				_, _ = w.Write([]byte(`{"ip":"` + ipv4A + `","country_code":"SG","country_name":"Singapore","org":"Cloud"}`))
			}
		}))
		defer srv.Close()

		loc, err := lookupExitWithConfig(context.Background(), srv.Client(), exitProbeConfig{
			CFTraceV4URL: srv.URL + "/cf-v4",
			VerifyV4URLs: []string{srv.URL + "/rl", srv.URL + "/v4-ok"},
		}, nil)
		if err != nil || loc.IP != ipv4A || loc.ISO != "SG" {
			t.Fatalf("fallback after 429 verifier failed: %+v, %v", loc, err)
		}

		if _, err := lookupExitWithConfig(context.Background(), srv.Client(), exitProbeConfig{
			CFTraceV4URL: srv.URL + "/cf-v4",
			VerifyV4URLs: []string{srv.URL + "/rl"},
		}, nil); !errors.Is(err, errExitProbeRateLimited) {
			t.Fatalf("expected errExitProbeRateLimited when all verifiers return 429, got %v", err)
		}

		locFallback, err := lookupExitWithConfig(context.Background(), srv.Client(), exitProbeConfig{
			CFTraceV4URL:        srv.URL + "/cf-down",
			CFTraceV6URL:        srv.URL + "/cf-down",
			CFTraceDualURL:      srv.URL + "/cf-down",
			FallbackEchoURL:     srv.URL + "/fallback-echo",
			FallbackLocationURL: srv.URL + "/fallback-loc",
		}, nil)
		if err != nil || locFallback.IP != ipv4A || locFallback.Org != "Cloud" {
			t.Fatalf("non-CF legacy fallback failed: %+v, %v", locFallback, err)
		}
	})
}
