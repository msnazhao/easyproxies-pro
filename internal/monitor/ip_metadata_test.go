package monitor

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"easy_proxies/internal/config"
	"easy_proxies/internal/ipmeta"
)

func waitMetadata(t *testing.T, h *EntryHandle) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		h.ref.mu.RLock()
		pending := h.ref.metadataPending
		h.ref.mu.RUnlock()
		if !pending {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("metadata did not complete")
}

func TestMetadataAuthorityHostingUsageAndReloadCache(t *testing.T) {
	var abuseCalls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/info/") {
			fmt.Fprint(w, `{"ip":"1.1.1.1","country_code":"NL","country":"Netherlands","as_name":"Amazon LLC","as_domain":"amazon.com","asn":"AS123"}`)
			return
		}
		abuseCalls.Add(1)
		fmt.Fprint(w, `{"data":{"ipAddress":"1.1.1.1","countryCode":"US","isp":"Other ISP","usageType":"Fixed Line ISP","abuseConfidenceScore":0}}`)
	}))
	defer api.Close()
	m, _ := NewManager(Config{})
	defer m.Stop()
	m.Metadata.InfoURL = api.URL + "/info/"
	m.Metadata.AbuseURL = api.URL + "/abuse"
	m.Metadata.Configure(ipmeta.Config{IPinfoKeys: []string{"info"}, AbuseKeys: []string{"abuse"}})
	node := NodeInfo{Tag: "a", Name: "Original", URI: "vless://uuid@proxy:443", ExitIP: "1.1.1.1", CountryCode: "JP", Provider: "Fallback"}
	h := m.Register(node)
	m.EnrichExit(context.Background(), h, false)
	waitMetadata(t, h)
	if abuseCalls.Load() != 0 {
		t.Fatal("hosting queried before use")
	}
	m.EnrichExit(context.Background(), h, true)
	waitMetadata(t, h)
	snap := h.ref.snapshot()
	if snap.CountryCode != "NL" || snap.Provider != "Amazon LLC" || snap.Name != "ISP|0|NL|1.1.1.1|AWS|Original" {
		t.Fatalf("wrong authority/name: %+v", snap)
	}
	m.ClearNodes()
	h = m.Register(node)
	m.EnrichExit(context.Background(), h, true)
	waitMetadata(t, h)
	if abuseCalls.Load() != 1 {
		t.Fatal("reload repeated check")
	}
}

func TestSubscriptionNetworkFilterAndRenamedLinks(t *testing.T) {
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	for _, network := range []string{"isp", "mobile", "hosting", ""} {
		s.mgr.Register(NodeInfo{Tag: network + "-node", Name: "ISP|0|GB|1.1.1.1|Org|Original", URI: "vless://uuid@" + network + "proxy:443#old", NetworkType: network, CountryCode: "GB", ExitIP: "1.1.1.1"}).MarkInitialCheckDone(true)
	}
	r := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies?n=isp&c=GB", "")
	body, err := base64.StdEncoding.DecodeString(r.Body.String())
	if r.Code != 200 || err != nil || len(strings.Split(string(body), "\n")) != 2 || strings.Contains(string(body), "hostingproxy") || strings.Contains(string(body), "#old") {
		t.Fatalf("filter/export: %d %s %v", r.Code, body, err)
	}
	if r := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies?n=invalid", ""); r.Code != 400 {
		t.Fatal("invalid filter accepted")
	}
}

func TestMetadataKeysSettingsRoundTrip(t *testing.T) {
	cfg, path := loadProxySettingsFixture(t)
	s, _ := newProxySessionTestServer(t, cfg)
	r := proxyAPIRequest(t, s, http.MethodPut, "/api/settings", `{"ip_metadata":{"ipinfo_keys":["test-info-a","test-info-b"],"abuseipdb_keys":["test-abuse"]}}`)
	if r.Code != 200 {
		t.Fatalf("save: %d %s", r.Code, r.Body)
	}
	if !s.mgr.Metadata.HasInfo() || !s.mgr.Metadata.HasAbuse() {
		t.Fatal("live keys not configured")
	}
	content, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(content), "test-info-b") {
		t.Fatalf("keys not persisted: %v", err)
	}
	saved, err := config.Load(path)
	if err != nil || len(saved.IPMetadata.IPinfoKeys) != 2 {
		t.Fatalf("keys not restored: %v", err)
	}
	r = proxyAPIRequest(t, s, http.MethodGet, "/api/settings", "")
	if r.Code != 200 || !strings.Contains(r.Body.String(), "test-abuse") {
		t.Fatal("GET keys missing")
	}
	r = proxyAPIRequest(t, s, http.MethodPut, "/api/settings", `{"ip_metadata":{"ipinfo_keys":[],"abuseipdb_keys":[]}}`)
	if r.Code != 200 || s.mgr.Metadata.HasInfo() || s.mgr.Metadata.HasAbuse() {
		t.Fatal("clearing keys failed")
	}
}
