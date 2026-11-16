package monitor

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"easy_proxies/internal/config"
)

func TestProxySubscriptionMultipleCountriesAndTypes(t *testing.T) {
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	for _, node := range []NodeInfo{
		{Tag: "ss-us", URI: "ss://us", CountryCode: "US", ExitIP: "8.8.8.8"},
		{Tag: "vless-gb", URI: "vless://gb", CountryCode: "GB", ExitIP: "1.1.1.1"},
		{Tag: "trojan-us", URI: "trojan://us", CountryCode: "US", ExitIP: "9.9.9.9"},
		{Tag: "ss-tr", URI: "ss://tr", CountryCode: "TR", ExitIP: "8.8.4.4"},
		{Tag: "hy2-gb", URI: "hy2://gb", CountryCode: "GB", ExitIP: "1.0.0.1"},
	} {
		s.mgr.Register(node).MarkInitialCheckDone(true)
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
	s.mgr.Register(NodeInfo{Tag: "us", URI: "vless://u@host:443", CountryCode: "US", ExitIP: "8.8.8.8"}).MarkInitialCheckDone(true)
	s.mgr.Register(NodeInfo{Tag: "server-only", URI: "trojan://p@host:443", EntryISO: "US"}).MarkInitialCheckDone(true)
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
	s.mgr.Register(NodeInfo{Tag: "unknown", URI: "unknown://proxy", ExitIP: "8.8.8.8", CountryCode: "US"}).MarkInitialCheckDone(true)
	s.SetOutboundConverter(func(string, string, bool) ([]byte, error) { return nil, nil })
	for _, path := range []string{"/sub/proxies?c=US", "/sub/proxies?c=US&f=sing-box"} {
		r := proxyAPIRequest(t, s, http.MethodGet, path, "")
		if r.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status = %d, body = %s", path, r.Code, r.Body)
		}
	}
}
