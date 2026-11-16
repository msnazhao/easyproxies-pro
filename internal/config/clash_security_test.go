package config

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"
)

func TestClashSecurityRejectsEncodedControlsAndCustomTags(t *testing.T) {
	for _, field := range []string{"sni: !!binary YmFkAC5leGFtcGxl", "username: !!binary c2VjcmV0AA==", "sni: !include /etc/passwd", "sni: \"bad\\n.example\"", "sni: \"bad\\t.example\""} {
		content := "proxies:\n- {name: unsafe, type: trojan, server: bad.example, port: 443, password: secret, " + field + "}\n- {name: good, type: trojan, server: good.example, port: 443, password: good}\n"
		nodes, err := ParseSubscriptionContent(content)
		if err != nil || len(nodes) != 1 || nodes[0].Name != "good" {
			t.Fatalf("unsafe field accepted: %s count=%d err=%v", strings.Split(field, ":")[0], len(nodes), err)
		}
	}
}

func TestClashSecurityRejectsOversizedAndTooDeepDocuments(t *testing.T) {
	tooLarge := "proxies: []\n#" + strings.Repeat("x", maxSubscriptionBodySize)
	for _, parse := range []func(string) ([]NodeConfig, error){ParseSubscriptionContent, parseClashYAML} {
		if _, err := parse(tooLarge); err == nil {
			t.Fatal("oversized document accepted")
		}
	}
	deep := "proxies:\n- {name: deep, type: trojan, server: bad.example, port: 443, password: secret, extra: " + strings.Repeat("[", 10001) + "0" + strings.Repeat("]", 10001) + "}\n"
	if nodes, err := parseClashYAML(deep); err == nil && len(nodes) > 0 {
		t.Fatal("excessively nested document accepted")
	}
}

func TestClashSecurityRejectsCyclesAndExpandedAliasBombs(t *testing.T) {
	var bomb strings.Builder
	bomb.WriteString("a0: &a0 [value, value, value, value, value, value, value, value, value, value]\n")
	for i := 1; i <= 8; i++ {
		fmt.Fprintf(&bomb, "a%d: &a%d [", i, i)
		for j := 0; j < 10; j++ {
			if j > 0 {
				bomb.WriteByte(',')
			}
			fmt.Fprintf(&bomb, "*a%d", i-1)
		}
		bomb.WriteString("]\n")
	}
	for _, prefix := range []string{"loop: &unsafe {self: *unsafe}\n", bomb.String() + "loop: &unsafe {value: *a8}\n"} {
		content := prefix + "proxies:\n- {name: unsafe, type: trojan, server: bad.example, port: 443, password: secret, extra: *unsafe}\n- {name: good, type: trojan, server: good.example, port: 443, password: good}\n"
		nodes, err := ParseSubscriptionContent(content)
		if err != nil || len(nodes) != 1 || nodes[0].Name != "good" {
			t.Fatalf("unsafe alias graph accepted: count=%d err=%v", len(nodes), err)
		}
	}
}

func TestClashSecurityDoesNotExposeRejectedValuesInLogsOrErrors(t *testing.T) {
	const secret = "DO_NOT_LOG_TEST_SECRET"
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	for _, content := range []string{
		"proxies:\n- {name: test, type: trojan, server: bad.example, port: '" + secret + "', password: secret}\n",
		"proxies:\n- {name: '" + secret + "', type: unsupported-secret-protocol}\n",
		"proxies: *" + secret + "\n",
	} {
		_, err := ParseSubscriptionContent(content)
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Fatal("rejected value leaked through parse error")
		}
	}
	if strings.Contains(logs.String(), secret) {
		t.Fatal("rejected value leaked through log output")
	}
}

func TestClashSecurityPreservesValidMergeAliases(t *testing.T) {
	content := "defaults: &base {type: trojan, server: good.example, port: 443, password: unchanged}\nproxies:\n- {<<: *base, name: merged}\n"
	nodes, err := ParseSubscriptionContent(content)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "merged" || !strings.Contains(nodes[0].URI, "trojan://unchanged@good.example:443") {
		t.Fatalf("valid merge alias broken: count=%d err=%v", len(nodes), err)
	}
}

func TestClashSecurityBoundsPerNodeWarningVolume(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	content := "proxies:\n" + strings.Repeat("- {name: bad, type: unsupported}\n", 128)
	_, _ = ParseSubscriptionContent(content)
	if strings.Count(logs.String(), "skip proxy #") != 10 || !strings.Contains(logs.String(), "skipped 128") {
		t.Fatal("per-node warning limit or aggregate count missing")
	}
}

func TestClashSecurityBoundsAliasBytesAndGeneratedOutput(t *testing.T) {
	large := strings.Repeat("x", 64<<10)
	content := "value: &large " + large + "\nproxies:\n- {name: too-large, type: trojan, server: bad.example, port: 443, password: secret, extra: [*large,*large,*large,*large,*large]}\n- {name: good, type: trojan, server: good.example, port: 443, password: good}\n"
	nodes, err := ParseSubscriptionContent(content)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "good" {
		t.Fatalf("large scalar alias expansion accepted: count=%d err=%v", len(nodes), err)
	}
	content = "password: &password " + large + "\nproxies:\n" + strings.Repeat("- {name: expanded, type: trojan, server: good.example, port: 443, password: *password}\n", 170)
	if nodes, err := ParseSubscriptionContent(content); err == nil || len(nodes) != 0 {
		t.Fatal("generated output amplification accepted")
	}
}

func FuzzClashSubscriptionRecovery(f *testing.F) {
	for _, seed := range []string{"proxies: []", "proxies:\n- {name: \"bad\x00name\", type: trojan, server: good.example, port: 443, password: secret}", "loop: &a {self: *a}\nproxies: [*a]", "proxies:\n- {name: test, sni: !!binary YmFkAA==}"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, content string) {
		if len(content) > 65536 {
			t.Skip()
		}
		nodes, err := parseClashYAML(content)
		if err != nil {
			return
		}
		for _, node := range nodes {
			if node.URI == "" {
				t.Fatal("empty URI accepted")
			}
		}
	})
}
