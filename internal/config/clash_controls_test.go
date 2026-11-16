package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestClashControlsKeepValidNodesAndRejectDamagedConnectionFields(t *testing.T) {
	content := "proxies:\n" +
		"- {name: good-before, type: trojan, server: before.example, port: 443, password: unchanged}\n" +
		"- {name: damaged-sni, type: trojan, server: bad.example, port: 443, password: secret, sni: \"bad\u009f.example\"}\n" +
		"- {name: \"clean\x00-name\", type: trojan, server: names.example, port: 443, password: unchanged}\n" +
		"- {name: damaged-password, type: trojan, server: bad.example, port: 443, password: \"pass\x1bword\"}\n" +
		"- {name: good-after, type: trojan, server: after.example, port: 443, password: unchanged}\n"
	var strict clashConfig
	if yaml.Unmarshal([]byte(content), &strict) == nil {
		t.Fatal("fixture must reproduce strict YAML failure")
	}
	nodes, err := ParseSubscriptionContent(content)
	if err != nil || len(nodes) != 3 {
		t.Fatalf("retained %d nodes: %v", len(nodes), err)
	}
	for i, name := range []string{"good-before", "clean-name", "good-after"} {
		if nodes[i].Name != name || !strings.Contains(nodes[i].URI, "trojan://unchanged@") {
			t.Fatalf("valid connection changed at index %d", i)
		}
	}
}

func TestClashControlsDoNotHideSyntaxErrorsOrDamageLegalUnicode(t *testing.T) {
	for _, content := range []string{
		"proxies:\n- {name: \"bad\x00name\", type: trojan, password: \"unterminated}\n",
		"proxies:\n- {name: invalid-utf8, password: \"\xff\"}\n",
	} {
		if _, err := ParseSubscriptionContent(content); err == nil {
			t.Fatal("unsafe document accepted")
		}
	}
	content := "proxies:\n- {name: \"Unicode\ue000\", type: trojan, server: fixture.example, port: 443, password: \"original\ue000\"}\n"
	nodes, err := ParseSubscriptionContent(content)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "Unicode\ue000" || !strings.Contains(nodes[0].URI, "original%EE%80%80") {
		t.Fatalf("legal Unicode changed: %v", err)
	}
}

func TestClashControlsRejectEscapedControlsAndAliasedDamage(t *testing.T) {
	content := "defaults: &bad {sni: \"bad\u0087.example\"}\nproxies:\n" +
		"- {name: alias, type: trojan, server: bad.example, port: 443, password: secret, extra: *bad}\n" +
		"- {name: escaped, type: trojan, server: bad.example, port: 443, password: \"bad\\x00password\"}\n" +
		"- {name: good, type: trojan, server: good.example, port: 443, password: unchanged}\n"
	nodes, err := ParseSubscriptionContent(content)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "good" {
		t.Fatalf("damaged alias/escaped data accepted: count=%d err=%v", len(nodes), err)
	}
}

func TestClashNameCleanupDoesNotRepairAliasedPasswords(t *testing.T) {
	content := "proxies:\n" +
		"- {name: &shared \"bad\x00name\", type: trojan, server: bad.example, port: 443, password: *shared}\n" +
		"- {name: good, type: trojan, server: good.example, port: 443, password: unchanged}\n"
	nodes, err := ParseSubscriptionContent(content)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "good" {
		t.Fatalf("name cleanup modified an aliased password: count=%d err=%v", len(nodes), err)
	}
}

func TestClashRecoveryMarkerDoesNotCollideWithEscapedUnicode(t *testing.T) {
	content := "proxies:\n- {name: good, type: trojan, server: good.example, port: 443, password: \"pass\\uE000\\U0000E001\"}\n- {name: bad, type: trojan, server: bad.example, port: 443, sni: \"bad\u009f.example\", password: secret}\n"
	nodes, err := ParseSubscriptionContent(content)
	if err != nil || len(nodes) != 1 || !strings.Contains(nodes[0].URI, "pass%EE%80%80%EE%80%81") {
		t.Fatalf("escaped credential collided with recovery marker: count=%d err=%v", len(nodes), err)
	}
}

func TestFiveSubscriptionsKeepValidEntriesWhenOneContainsControls(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/damaged" {
			_, _ = w.Write([]byte("proxies:\n- {name: good, type: trojan, server: good.example, port: 443, password: good}\n- {name: bad, type: trojan, server: bad.example, port: 443, password: bad, sni: \"bad\u009f.example\"}\n"))
			return
		}
		_, _ = w.Write([]byte("trojan://password@" + strings.TrimPrefix(r.URL.Path, "/") + ".example:443#valid"))
	}))
	defer server.Close()
	urls := []string{server.URL + "/one", server.URL + "/two", server.URL + "/damaged", server.URL + "/four", server.URL + "/five"}
	nodes, stats := FetchSubscriptionNodes(context.Background(), urls, SubscriptionFetchOptions{Timeout: time.Second, Concurrency: 3})
	if len(nodes) != 5 || stats.Failed != 0 || stats.Empty != 0 || stats.Successful != 5 {
		t.Fatalf("partial provider caused refresh failure: nodes=%d stats=%+v", len(nodes), stats)
	}
	for _, node := range nodes {
		if strings.Contains(node.URI, "bad.example") {
			t.Fatal("damaged connection retained")
		}
	}
}

func TestReportedClashControlsResponse(t *testing.T) {
	path := os.Getenv("EASYPROXIES_TEST_CLASH_FILE")
	if path == "" {
		t.Skip("optional live-response fixture")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	masked, marker, count, err := maskClashControls(string(body))
	if err != nil {
		t.Fatal(err)
	}
	var clash clashConfig
	if err := yaml.Unmarshal([]byte(masked), &clash); err != nil {
		t.Fatal(err)
	}
	damaged := 0
	for _, node := range clash.Proxies {
		cleanClashDisplayName(&node, marker)
		if damagedClashValue(&node, marker, make(map[*yaml.Node]bool)) {
			damaged++
		}
	}
	nodes, err := ParseSubscriptionContent(string(body))
	if err != nil || len(nodes) == 0 {
		t.Fatalf("live response: count=%d err=%v", len(nodes), err)
	}
	t.Logf("live response: controls=%d total=%d damaged=%d usable=%d", count, len(clash.Proxies), damaged, len(nodes))
}
