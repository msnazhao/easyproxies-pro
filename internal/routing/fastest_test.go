package routing

import "testing"

func TestParseFastestRoute(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want FastestRoute
	}{
		{"account._fast1_", FastestRoute{Enabled: true}},
		{"account._fast1_us_", FastestRoute{Enabled: true, Country: "US"}},
		{"account.with.dots._fast1_gb_", FastestRoute{Enabled: true, Country: "GB"}},
		{"account._fast1_tr_", FastestRoute{Enabled: true, Country: "TR"}},
		{"account.with.dots._fast1_isp_", FastestRoute{Enabled: true, ZeroAbuseISP: true}},
		{"account._fast1_usa_", FastestRoute{}},
		{"account.task1", FastestRoute{}},
	} {
		if got := ParseFastestRoute(tc.key); got != tc.want {
			t.Fatalf("%q: got %+v, want %+v", tc.key, got, tc.want)
		}
	}
}
