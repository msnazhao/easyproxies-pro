package config

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestSubscriptionBase64Variants(t *testing.T) {
	content := "trojan://password@fixture.invalid:443#名字\nvmess://uuid@fixture.invalid:443?type=grpc#URL%20Node\n"
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		encoded := encoding.EncodeToString([]byte(content))
		encoded = encoded[:12] + "\r\n" + encoded[12:]
		nodes, err := ParseSubscriptionContent(encoded)
		if err != nil || len(nodes) != 2 {
			t.Fatalf("base64 variant lost nodes: count=%d err=%v", len(nodes), err)
		}
	}
	if name := ExtractNodeName("vmess://uuid@fixture.invalid:443#URL%20Node"); name != "URL Node" {
		t.Fatalf("URL VMess name=%q", name)
	}
}

func TestClashURIIPv6AndCredentials(t *testing.T) {
	for _, scheme := range []string{"vmess", "vless", "trojan", "anytls", "hysteria2", "tuic", "http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			proxy := clashProxy{Type: scheme, Server: "2001:db8::1", Port: 443, UUID: "uuid", Username: "user", Password: "p@ss:word/?#%+秘密", Name: "Name + 空格"}
			uri := convertClashProxyToURI(proxy)
			u, err := url.Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			if u.Hostname() != proxy.Server || u.Port() != "443" || u.Fragment != proxy.Name {
				t.Fatalf("URI data changed: %s", uri)
			}
			if name := ExtractNodeName(uri); name != proxy.Name {
				t.Fatalf("roundtrip node name changed: %q", name)
			}
			switch scheme {
			case "trojan", "anytls", "hysteria2":
				if u.User.Username() != proxy.Password {
					t.Fatal("password changed")
				}
			case "tuic", "http", "https":
				pass, _ := u.User.Password()
				if pass != proxy.Password {
					t.Fatal("password changed")
				}
			}
		})
	}
	uri := buildVMessURI(clashProxy{Server: "fixture.invalid", Port: 443, UUID: "uuid", AlterId: 64, Cipher: "aes-128-gcm"})
	u, _ := url.Parse(uri)
	if u.Query().Get("alterId") != "64" || u.Query().Get("encryption") != "aes-128-gcm" {
		t.Fatal("VMess authentication options lost")
	}
}

func TestValidateSettingsRejectsInvalidValues(t *testing.T) {
	for _, mutate := range []func(*Config){func(c *Config) { c.Mode = "invalid" }, func(c *Config) { c.Pool.Mode = "invalid" }, func(c *Config) { c.Listener.Address = "host.invalid" }, func(c *Config) { c.Management.Listen = "127.0.0.1:65536" }, func(c *Config) { c.Pool.BlacklistDuration = -1 }, func(c *Config) { c.Management.ProbeConcurrency = 9999 }} {
		cfg := &Config{Mode: "pool"}
		mutate(cfg)
		if cfg.ValidateManagementSettings() == nil {
			t.Fatal("invalid setting accepted")
		}
	}
	if mode, err := normalizePoolMode("round-robin"); err != nil || mode != "sequential" {
		t.Fatal("legacy round-robin alias not normalized")
	}
	if strings.Contains(buildTrojanURI(clashProxy{Password: "x#secret", Server: "fixture.invalid", Port: 443}), "x#secret") {
		t.Fatal("password must be encoded")
	}
}

func TestDNSConfigAndPreScreenDefaultsAndValidation(t *testing.T) {
	raw := `
mode: pool
dns:
  server: https://1.1.1.1/dns-query
  fallback_servers:
    - 8.8.8.8
    - local
  port: 53
  strategy: prefer_ipv4
subscription_refresh:
  prescreen_enabled: false
  prescreen_threshold: 80
  prescreen_concurrency: 512
  prescreen_timeout: 3s
`
	var cfg Config
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.Server != "https://1.1.1.1/dns-query" || len(cfg.DNS.FallbackServers) != 2 || cfg.DNS.Strategy != "prefer_ipv4" {
		t.Fatalf("unexpected DNS config: %+v", cfg.DNS)
	}
	if err := cfg.ValidateManagementSettings(); err != nil {
		t.Fatalf("valid DNS/prescreen config rejected: %v", err)
	}
	if cfg.SubscriptionRefresh.PreScreenEnabledFor(500) {
		t.Fatal("explicit prescreen_enabled=false should stay disabled for 500 nodes")
	}
	if cfg.SubscriptionRefresh.PreScreenConcurrencyOrDefault() != 512 || cfg.SubscriptionRefresh.PreScreenTimeoutOrDefault() != 3*time.Second {
		t.Fatalf("unexpected prescreen settings: %+v", cfg.SubscriptionRefresh)
	}

	auto := SubscriptionRefreshConfig{}
	if auto.PreScreenEnabledFor(49) || !auto.PreScreenEnabledFor(50) {
		t.Fatal("auto prescreen threshold should trigger at 50 nodes")
	}
	if got := (SubscriptionRefreshConfig{PreScreenConcurrency: 9999}).PreScreenConcurrencyOrDefault(); got != maxPreScreenConcurrency {
		t.Fatalf("expected concurrency clamped to %d, got %d", maxPreScreenConcurrency, got)
	}

	for _, mutate := range []func(*Config){
		func(c *Config) { c.DNS.Strategy = "bad_strategy" },
		func(c *Config) { c.SubscriptionRefresh.PreScreenConcurrency = 2048 },
		func(c *Config) { c.SubscriptionRefresh.PreScreenTimeout = -time.Second },
	} {
		invalid := &Config{Mode: "pool"}
		mutate(invalid)
		if invalid.ValidateManagementSettings() == nil {
			t.Fatal("invalid DNS/prescreen config was accepted")
		}
	}
}

func TestLoadContextRespectsCancellation(t *testing.T) {
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: pool\nsubscriptions:\n  - "+srv.URL+"/sub\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-started
		cancel()
	}()

	start := time.Now()
	_, err := LoadContext(ctx, cfgPath)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("LoadContext error = %v, want context.Canceled", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("LoadContext took too long to abort: %s", time.Since(start))
	}
}

func TestLoadResolvesRelativeGeoIPDatabasePath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	raw := `
mode: pool
geoip:
  enabled: false
  database_path: "./GeoLite2-Country.mmdb"
nodes:
  - name: "n"
    uri: "http://127.0.0.1:8080"
`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "GeoLite2-Country.mmdb")
	if cfg.GeoIP.DatabasePath != want {
		t.Fatalf("GeoIP.DatabasePath = %q, want %q", cfg.GeoIP.DatabasePath, want)
	}
}
