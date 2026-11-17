package builder

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func TestSubscriptionOutboundIncludesProtocolOptions(t *testing.T) {
	data, err := SubscriptionOutbound("node-1", "vless://d5bf4ef3-2df1-4f01-8d51-98411b39a882@example.com:443?security=tls&sni=example.com#US", false)
	if err != nil {
		t.Fatal(err)
	}
	var outbound map[string]any
	if err := json.Unmarshal(data, &outbound); err != nil {
		t.Fatal(err)
	}
	if outbound["type"] != "vless" || outbound["tag"] != "node-1" || outbound["server"] != "example.com" {
		t.Fatalf("incomplete outbound: %s", data)
	}
}

func TestSubscriptionOutboundReportedSSURI(t *testing.T) {
	uri := os.Getenv("EASYPROXIES_TEST_SS_URI")
	if uri == "" {
		uri = "ss://" + base64.RawStdEncoding.EncodeToString([]byte("aes-256-cfb:test-password")) + "@211.178.105.134:6123#%F0%9F%87%B0%F0%9F%87%B7KR_79"
	}
	for _, tag := range []string{"ISP|0|KR|211.178.105.134|Org|Original", "ISP|58|KR|211.178.105.134|Org|Original"} {
		data, err := SubscriptionOutbound(tag, uri, false)
		if err != nil {
			t.Fatalf("SS conversion failed: %v", err)
		}
		var outbound map[string]any
		if err := json.Unmarshal(data, &outbound); err != nil {
			t.Fatal(err)
		}
		if outbound["type"] != "shadowsocks" || outbound["method"] != "aes-256-cfb" || outbound["server"] != "211.178.105.134" || outbound["server_port"] != float64(6123) || outbound["tag"] != tag {
			t.Fatal("SS conversion changed connection settings")
		}
		t.Logf("conversion passed: method=%s server=%s port=%.0f tag=%s", outbound["method"], outbound["server"], outbound["server_port"], tag)
	}
}
