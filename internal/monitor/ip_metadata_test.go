package monitor

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	"easy_proxies/internal/ssuri"
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

func TestISPSubscriptionScoreAndOtherExclusions(t *testing.T) {
	for _, tc := range []struct {
		name, usage, score                  string
		unavailable, unchecked, blacklisted bool
		want                                bool
	}{
		{name: "fixed-zero", usage: "Fixed Line ISP", score: "0", want: true},
		{name: "fixed-58", usage: "Fixed Line ISP", score: "58", want: true},
		{name: "fixed-100", usage: "Fixed Line ISP", score: "100", want: true},
		{name: "fixed-no-score", usage: "Fixed Line ISP", score: "null", want: true},
		{name: "mobile-58", usage: "Mobile ISP", score: "58", want: true},
		{name: "hosting-zero", usage: "Data Center/Web Hosting/Transit", score: "0"},
		{name: "hosting-58", usage: "Data Center/Web Hosting/Transit", score: "58"},
		{name: "unknown-58", usage: "Commercial", score: "58"},
		{name: "unavailable-58", usage: "Fixed Line ISP", score: "58", unavailable: true},
		{name: "unchecked-58", usage: "Fixed Line ISP", score: "58", unchecked: true},
		{name: "blacklisted-58", usage: "Fixed Line ISP", score: "58", blacklisted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `{"data":{"ipAddress":"1.1.1.1","usageType":%q,"abuseConfidenceScore":%s}}`, tc.usage, tc.score)
			}))
			defer api.Close()
			s.mgr.Metadata.AbuseURL = api.URL
			s.mgr.Metadata.Configure(ipmeta.Config{AbuseKeys: []string{"fixture-key"}})
			h := s.mgr.Register(NodeInfo{Tag: tc.name, Name: "Original", URI: "vless://uuid@fixture.example:443#Original", ExitIP: "1.1.1.1", CountryCode: "GB", Provider: "Example Network"})
			if !tc.unchecked {
				h.MarkInitialCheckDone(!tc.unavailable)
			}
			if tc.blacklisted {
				h.Blacklist(time.Now().Add(time.Hour))
			}
			s.mgr.EnrichExit(context.Background(), h, false)
			waitMetadata(t, h)
			s.SetOutboundConverter(func(tag, uri string, _ bool) ([]byte, error) {
				return json.Marshal(map[string]string{"type": "vless", "tag": tag, "uri": uri})
			})
			for _, format := range []string{"v2ray", "sing-box"} {
				r := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies?n=isp&c=GB&f="+format, "")
				if !tc.want {
					if r.Code != http.StatusServiceUnavailable {
						t.Fatalf("%s excluded node exported: %d %s", format, r.Code, r.Body)
					}
					continue
				}
				if r.Code != http.StatusOK {
					t.Fatalf("%s omitted %s-score ISP: %d %s", format, tc.score, r.Code, r.Body)
				}
				body := r.Body.String()
				if format == "v2ray" {
					decoded, err := base64.StdEncoding.DecodeString(body)
					if err != nil {
						t.Fatal(err)
					}
					body = string(decoded)
				}
				if !strings.Contains(body, "fixture.example") {
					t.Fatalf("%s missing node: %s", format, body)
				}
			}
		})
	}
}

func TestISPSubscriptionReportedSSURI(t *testing.T) {
	uri := os.Getenv("EASYPROXIES_TEST_SS_URI")
	if uri == "" {
		uri = "ss://" + base64.RawStdEncoding.EncodeToString([]byte("aes-256-cfb:test-password")) + "@211.178.105.134:6123#%F0%9F%87%B0%F0%9F%87%B7KR_79"
	}
	original, err := ssuri.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	for _, score := range []int{0, 58, 100} {
		s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
		name := ipmeta.DisplayName(original.Fragment, "KR", original.Server, "Example ISP", "example.com", "isp", &score)
		s.mgr.Register(NodeInfo{Tag: "reported", Name: name, URI: uri, ExitIP: original.Server, CountryCode: "KR", NetworkType: "isp", Abuse: &ipmeta.Abuse{Score: &score, Usage: "Fixed Line ISP"}}).MarkInitialCheckDone(true)
		r := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies?n=isp&t=ss&c=KR", "")
		if r.Code != 200 {
			t.Fatalf("score %d: export status %d", score, r.Code)
		}
		decoded, err := base64.StdEncoding.DecodeString(r.Body.String())
		if err != nil {
			t.Fatal(err)
		}
		exported, err := ssuri.Parse(string(decoded))
		if err != nil {
			t.Fatal("exported SS URI is invalid")
		}
		if exported.Method != original.Method || exported.Password != original.Password || exported.Server != original.Server || exported.Port != original.Port || exported.Fragment != name {
			t.Fatal("export changed SS connection settings or display name")
		}
		t.Logf("SS export and reparse passed: score=%d, ISP=true, credentials preserved", score)
	}
}
