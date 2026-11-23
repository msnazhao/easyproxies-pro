package monitor

import (
	"context"
	"easy_proxies/internal/ipmeta"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"easy_proxies/internal/config"
)

func registerHealthySubscriptionNode(m *Manager, node NodeInfo) *EntryHandle {
	entry := m.Register(node)
	entry.RecordSuccessWithLatency(time.Millisecond)
	entry.MarkInitialCheckDone(true)
	return entry
}

func TestProxySubscriptionMultipleCountriesAndTypes(t *testing.T) {
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	for _, node := range []NodeInfo{
		{Tag: "ss-us", URI: "ss://us", CountryCode: "US", ExitIP: "8.8.8.8"},
		{Tag: "vless-gb", URI: "vless://gb", CountryCode: "GB", ExitIP: "1.1.1.1"},
		{Tag: "trojan-us", URI: "trojan://us", CountryCode: "US", ExitIP: "9.9.9.9"},
		{Tag: "ss-tr", URI: "ss://tr", CountryCode: "TR", ExitIP: "8.8.4.4"},
		{Tag: "hy2-gb", URI: "hy2://gb", CountryCode: "GB", ExitIP: "1.0.0.1"},
	} {
		registerHealthySubscriptionNode(s.mgr, node)
	}
	for _, query := range []string{"c=us,gb&t=ss,vless", "c=us&c=gb&t=ss&t=vless"} {
		r := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies?"+query, "")
		decoded, err := base64.StdEncoding.DecodeString(r.Body.String())
		if r.Code != 200 || err != nil || len(strings.Split(string(decoded), "\n")) != 2 || !strings.Contains(string(decoded), "vless://gb") || !strings.Contains(string(decoded), "ss://us") {
			t.Fatalf("%s: %d %q %v", query, r.Code, decoded, err)
		}
	}
	s.SetOutboundConverter(func(tag, uri string, _ bool) ([]byte, error) {
		return json.Marshal(map[string]string{"tag": tag, "uri": uri})
	})
	r := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies?c=GB&t=hysteria2&f=sing-box", "")
	if r.Code != 200 || !strings.Contains(r.Body.String(), "hy2://gb") || strings.Contains(r.Body.String(), "vless://gb") {
		t.Fatalf("hysteria2 alias filter: %d %s", r.Code, r.Body)
	}
}

func TestProxySubscriptionFiltersMeasuredExitWithoutAuth(t *testing.T) {
	cfg := proxySessionTestConfig()
	cfg.Management = config.ManagementConfig{Password: "secret"}
	s, _ := newProxySessionTestServer(t, cfg)
	registerHealthySubscriptionNode(s.mgr, NodeInfo{Tag: "us", URI: "vless://u@host:443", CountryCode: "US", ExitIP: "8.8.8.8"})
	registerHealthySubscriptionNode(s.mgr, NodeInfo{Tag: "server-only", URI: "trojan://p@host:443", EntryISO: "US"})
	s.mgr.Register(NodeInfo{Tag: "dead", URI: "ss://x@host:443", CountryCode: "US", ExitIP: "1.1.1.1"}).MarkInitialCheckDone(false)
	if r := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies?c=US", ""); r.Code != http.StatusOK {
		t.Fatalf("public subscription status = %d", r.Code)
	}
	s.SetOutboundConverter(func(tag, uri string, skip bool) ([]byte, error) {
		return []byte(`{"type":"vless","tag":"` + tag + `","server":"example.com"}`), nil
	})
	r := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies?c=1", "")
	if r.Code != http.StatusBadRequest {
		t.Fatalf("invalid country status = %d", r.Code)
	}
	// Subscription clients use no credentials even with a management password.
	for _, tc := range []struct{ path, want string }{
		{"/sub/proxies?c=US", "vless://u@host:443"},
		{"/sub/proxies?c=US&f=sing-box", `"proxy-auto"`},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		s.srv.Handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body)
		}
		body := w.Body.String()
		if strings.Contains(tc.path, "sing-box") {
			if !strings.Contains(body, tc.want) || strings.Contains(body, "server-only") {
				t.Fatalf("sing-box: %s", body)
			}
		} else {
			decoded, err := base64.StdEncoding.DecodeString(body)
			if err != nil || string(decoded) != tc.want {
				t.Fatalf("v2ray: %q, %v", decoded, err)
			}
		}
	}
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/sub/proxies?c=USA", http.StatusBadRequest},
		{"/sub/proxies?c=JP", http.StatusServiceUnavailable},
		{"/sub/proxies?f=invalid", http.StatusBadRequest},
		{"/sub/proxies?t=invalid", http.StatusBadRequest},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		s.srv.Handler.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Errorf("%s: status=%d, want %d", tc.path, w.Code, tc.status)
		}
	}
}

func TestProxySubscriptionRejectsUnsupportedExports(t *testing.T) {
	cfg := proxySessionTestConfig()
	s, _ := newProxySessionTestServer(t, cfg)
	registerHealthySubscriptionNode(s.mgr, NodeInfo{Tag: "unknown", URI: "unknown://proxy", ExitIP: "8.8.8.8", CountryCode: "US"})
	s.SetOutboundConverter(func(string, string, bool) ([]byte, error) { return nil, nil })
	for _, path := range []string{"/sub/proxies?c=US", "/sub/proxies?c=US&f=sing-box"} {
		r := proxyAPIRequest(t, s, http.MethodGet, path, "")
		if r.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status = %d, body = %s", path, r.Code, r.Body)
		}
	}
}

func TestExitProxySubscriptionSOCKS5WithoutAuth(t *testing.T) {
	cfg := proxySessionTestConfig()
	cfg.Management.Password = "management-secret"
	cfg.ExternalIP = "relay.example"
	cfg.Listener.Password = "password:@#"
	s, store := newProxySessionTestServer(t, cfg)
	for _, node := range []NodeInfo{
		{Tag: "a", Name: "美国 A", URI: "vless://upstream-secret@a:443", CountryCode: "US", NetworkType: "isp", ExitIP: "8.8.8.8"},
		{Tag: "b", Name: "美国 B #1", URI: "ss://upstream-secret@b:443", CountryCode: "US", NetworkType: "mobile", ExitIP: "::ffff:8.8.8.8"},
		{Tag: "c", Name: "英国 IPv6", URI: "hy2://upstream-secret@c:443", CountryCode: "GB", NetworkType: "isp", ExitIP: "2606:4700:0:0:0:0:0:1111"},
		{Tag: "hosting", Name: "Hosting", URI: "vless://u@d:443", CountryCode: "US", NetworkType: "hosting", ExitIP: "8.8.4.4"},
		{Tag: "country", Name: "Country", URI: "vless://u@e:443", CountryCode: "JP", NetworkType: "isp", ExitIP: "1.1.1.1"},
		{Tag: "protocol", Name: "Protocol", URI: "trojan://u@f:443", CountryCode: "US", NetworkType: "isp", ExitIP: "1.0.0.1"},
		{Tag: "unknown", Name: "Unknown exit", URI: "vmess://u@g:443", NetworkType: "isp"},
		{Tag: "offline", Name: "Offline", URI: "vless://u@h:443", CountryCode: "US", NetworkType: "isp", ExitIP: "8.8.8.8"},
		{Tag: "stale-exit", Name: "Stale exit", URI: "vless://u@i:443", CountryCode: "US", NetworkType: "isp", ExitIP: "9.9.9.9"},
		{Tag: "stale-probe", Name: "Stale health probe", URI: "vless://u@j:443", CountryCode: "US", NetworkType: "isp", ExitIP: "149.112.112.112"},
	} {
		entry := registerHealthySubscriptionNode(s.mgr, node)
		entry.SetExit(ipmeta.Location{IP: node.ExitIP, ISO: node.CountryCode})
		entry.ref.mu.Lock()
		entry.ref.info.NetworkType = node.NetworkType
		entry.ref.info.Name = node.Name
		switch node.Tag {
		case "stale-exit":
			entry.ref.exitVerifiedAt = time.Now().Add(-exitRoutingTTL)
		case "stale-probe":
			entry.ref.lastProbeAt = time.Now().Add(-exitRoutingTTL)
		}
		entry.ref.mu.Unlock()
		entry.MarkInitialCheckDone(node.Tag != "offline")
		switch node.Tag {
		case "a":
			entry.RecordSuccessWithLatency(1900 * time.Microsecond)
		case "b":
			entry.RecordSuccessWithLatency(1100 * time.Microsecond)
		case "offline":
			entry.RecordSuccessWithLatency(time.Microsecond)
		}
	}
	path := "/sub/proxies2?c=us,gb&t=vless,ss,hysteria2&n=isp&f=socks5"
	req := httptest.NewRequest(http.MethodGet, "http://dashboard.example:9091"+path, nil)
	w := httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v", w.Code, w.Header())
	}
	want := map[string]string{
		"美国 B #1":            "wang._ip_8.8.8.8",
		"英国 IPv6":            "wang._ip_2606-4700--1111",
		"Stale exit":         "wang._ip_9.9.9.9",
		"Stale health probe": "wang._ip_149.112.112.112",
	}
	for _, line := range strings.Split(strings.TrimSpace(w.Body.String()), "\n") {
		link, err := url.Parse(line)
		if err != nil || link.Scheme != "socks5" || link.Host != "relay.example:2323" || link.User == nil {
			t.Fatal("subscription contains an invalid SOCKS5 link")
		}
		password, _ := link.User.Password()
		if want[link.Fragment] != link.User.Username() || password != cfg.Listener.Password {
			t.Fatalf("wrong credentials or display name: %q", link.Fragment)
		}
		delete(want, link.Fragment)
	}
	if len(want) != 0 || len(store.List()) != 0 || strings.Contains(w.Body.String(), "upstream-secret") {
		t.Fatal("subscription omitted nodes, created bindings, or exposed upstream credentials")
	}

	// Protocol filtering can match a node that has no IP for the generated session.
	unknown := httptest.NewRequest(http.MethodGet, "/sub/proxies2?t=vmess", nil)
	w = httptest.NewRecorder()
	s.srv.Handler.ServeHTTP(w, unknown)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no matching exits returned %d", w.Code)
	}
}

func TestSubscriptionsRequireSuccessfulHealthProbe(t *testing.T) {
	cfg := proxySessionTestConfig()
	s, _ := newProxySessionTestServer(t, cfg)
	for tag, ip := range map[string]string{
		"healthy": "8.8.8.8", "unchecked": "8.8.4.4", "failed": "9.9.9.9",
		"blacklisted": "1.1.1.1", "unprobed": "1.0.0.1",
	} {
		entry := s.mgr.Register(NodeInfo{Tag: tag, Name: tag, URI: "vless://fixture@" + tag + ".example:443"})
		entry.SetExit(ipmeta.Location{IP: ip, ISO: "US"})
		switch tag {
		case "healthy", "blacklisted":
			entry.RecordSuccessWithLatency(time.Millisecond)
			entry.MarkInitialCheckDone(true)
		case "failed":
			entry.RecordSuccessWithLatency(2 * time.Millisecond)
			entry.MarkInitialCheckDone(false)
		case "unprobed":
			// Matches the scheduler's optimistic state when a probe is unavailable.
			entry.MarkInitialCheckDone(true)
		}
		if tag == "blacklisted" {
			entry.Blacklist(time.Now().Add(time.Hour))
		}
	}
	s.SetOutboundConverter(func(tag, uri string, _ bool) ([]byte, error) {
		return json.Marshal(map[string]string{"tag": tag, "uri": uri})
	})
	for _, path := range []string{"/sub/proxies", "/sub/proxies?f=sing-box", "/sub/proxies2"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			s.srv.Handler.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d", w.Code)
			}
			body := w.Body.String()
			if path == "/sub/proxies" {
				decoded, err := base64.StdEncoding.DecodeString(body)
				if err != nil {
					t.Fatal(err)
				}
				body = string(decoded)
			}
			if !strings.Contains(body, "healthy") {
				t.Fatal("healthy node was missing")
			}
			for _, tag := range []string{"unchecked", "failed", "blacklisted", "unprobed"} {
				if strings.Contains(body, tag) {
					t.Fatalf("included %s node", tag)
				}
			}
		})
	}
}

func TestExitSubscriptionRetainsFreshMeasurementsAcrossReload(t *testing.T) {
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	info := NodeInfo{Tag: "original", Name: "Original", URI: "vless://fixture@upstream.example:443#original"}
	old := registerHealthySubscriptionNode(s.mgr, info)
	old.SetExit(ipmeta.Location{IP: "8.8.8.8", ISO: "US"})
	verifiedAt := s.mgr.Snapshot()[0].ExitVerifiedAt

	finish := s.mgr.BeginNodeReload()
	defer finish()
	info.Tag, info.Name, info.URI = "renamed", "Renamed", "vless://fixture@upstream.example:443#renamed"
	newEntry := s.mgr.Register(info)
	s.mgr.Register(NodeInfo{Tag: "different", URI: "vless://other@upstream.example:443"})
	old.InvalidateExit()
	if newEntry.ref == old.ref || !newEntry.ref.snapshot().ExitVerifiedAt.Equal(verifiedAt) {
		t.Fatal("reload reused old callbacks or renewed an existing observation")
	}
	result := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies2?c=US", "")
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), "._ip_8.8.8.8") ||
		!strings.Contains(result.Body.String(), "Renamed") {
		t.Fatalf("valid exit disappeared or retained the old name after reload: status=%d", result.Code)
	}
}

func TestPartialExitLookupPreservesCountryFilterForTheSameAddress(t *testing.T) {
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	h := registerHealthySubscriptionNode(s.mgr, NodeInfo{Tag: "fixture", URI: "vless://fixture@upstream.example:443"})
	h.SetExit(ipmeta.Location{IP: "8.8.8.8", ISO: "US", Country: "United States", Org: "Example ISP", ASN: "AS123", Domain: "example.com"})
	h.SetExit(ipmeta.Location{IP: "::ffff:8.8.8.8", ISO: "ZZ"})
	info := s.mgr.Snapshot()[0].NodeInfo
	if info.CountryCode != "US" || info.Country != "United States" || info.Region != "us" ||
		info.Provider != "Example ISP" || info.ASN != "AS123" || info.OrgDomain != "example.com" {
		t.Fatalf("partial response erased metadata: %+v", info)
	}
	result := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies2?c=US", "")
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), "._ip_8.8.8.8") {
		t.Fatalf("country filter lost same-IP exit: %d %s", result.Code, result.Body)
	}
	h.SetExit(ipmeta.Location{IP: "1.1.1.1"})
	info = s.mgr.Snapshot()[0].NodeInfo
	if info.CountryCode != "ZZ" || info.Country != "" || info.Region != "" || info.Provider != "" || info.ASN != "" || info.OrgDomain != "" {
		t.Fatalf("new IP inherited old metadata: %+v", info)
	}
	result = proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies2", "")
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), "._ip_1.1.1.1") {
		t.Fatalf("address-only exit disappeared from unfiltered subscription: %d %s", result.Code, result.Body)
	}
	result = proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies2?c=US", "")
	if strings.Contains(result.Body.String(), "._ip_1.1.1.1") {
		t.Fatalf("unclassified exit passed country filter: %s", result.Body)
	}
	for _, path := range []string{"/sub/proxies?c=zz", "/sub/proxies2?c=zz"} {
		result = proxyAPIRequest(t, s, http.MethodGet, path, "")
		if result.Code != http.StatusOK {
			t.Fatalf("ZZ filter failed for %s: %d %s", path, result.Code, result.Body)
		}
	}
}

func TestExitSubscriptionIncludesNodeAfterTrafficTriggersRecheck(t *testing.T) {
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	m := s.mgr
	known := registerHealthySubscriptionNode(m, NodeInfo{Tag: "known", Name: "Known"})
	known.SetExit(ipmeta.Location{IP: "8.8.8.8", ISO: "US"})
	known.SetProbe(func(context.Context) (time.Duration, error) {
		t.Error("already verified idle node was probed")
		return time.Millisecond, nil
	})

	pending := registerHealthySubscriptionNode(m, NodeInfo{Tag: "pending", Name: "Recovered"})
	if !pending.BeginExitLookup(false) {
		t.Fatal("could not queue initial exit discovery")
	}
	pending.EndExitLookup("failed")
	pending.ref.mu.Lock()
	pending.ref.exitAttemptedAt = time.Now().Add(-exitRefreshInterval)
	pending.ref.mu.Unlock()
	attempts := 1
	pending.SetProbe(func(ctx context.Context) (time.Duration, error) {
		if !pending.BeginExitLookup(pending.UsedSince(PeriodicProbeSince(ctx))) {
			t.Error("recovery probe did not start exit discovery")
			return time.Millisecond, nil
		}
		attempts++
		pending.SetExit(ipmeta.Location{IP: "1.1.1.1", ISO: "US"})
		pending.EndExitLookup("")
		return time.Millisecond, nil
	})
	read := func() string {
		t.Helper()
		result := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies2?c=US", "")
		if result.Code != http.StatusOK {
			t.Fatalf("subscription status = %d", result.Code)
		}
		return result.Body.String()
	}
	since := time.Now().Add(-5 * time.Minute)
	m.probeNodes(time.Second, since, false)
	if attempts != 1 || strings.Contains(read(), "._ip_1.1.1.1") {
		t.Fatal("unverified exit appeared in the subscription")
	}
	pending.IncActive()
	pending.DecActive()
	m.probeNodes(time.Second, since, false)
	if attempts != 2 || !strings.Contains(read(), "._ip_1.1.1.1") {
		t.Fatalf("exit did not recover after traffic: attempts=%d", attempts)
	}
}

func TestExitSubscriptionUnavailableIncludesReason(t *testing.T) {
	cfg := proxySessionTestConfig()
	cfg.Listener.Username = ""
	s, _ := newProxySessionTestServer(t, cfg)
	result := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies2", "")
	if result.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", result.Code)
	}
	body := result.Body.String()
	if !strings.Contains(body, "exit IP sessions unavailable:") || !strings.Contains(body, "用户名") {
		t.Fatalf("expected actionable reason in body, got %q", body)
	}
}
