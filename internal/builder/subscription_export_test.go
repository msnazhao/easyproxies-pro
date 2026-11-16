package builder

import (
	"encoding/json"
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
