package ipmeta

import "testing"

func TestNetworkTypeNormalizesWhitespaceWithoutGuessingISP(t *testing.T) {
	for _, tc := range []struct{ usage, want string }{
		{" Fixed Line ISP \r\n", "isp"}, {" MOBILE ISP ", "mobile"},
		{"Commercial", "unknown"}, {"Organization", "unknown"}, {"Fixed Line ISP / Commercial", "unknown"},
		{"Data Center/Web Hosting/Transit", "hosting"},
	} {
		if got := (Abuse{Usage: tc.usage}).NetworkType(); got != tc.want {
			t.Errorf("%q: got %s want %s", tc.usage, got, tc.want)
		}
	}
}
