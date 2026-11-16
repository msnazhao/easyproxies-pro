package routing

import "testing"

func TestFastestCountry(t *testing.T) {
	for _, tc := range []struct {
		key, country string
		fastest      bool
	}{
		{"account._fast1_", "", true},
		{"account._fast1_us_", "US", true},
		{"account.with.dots._fast1_gb_", "GB", true},
		{"account._fast1_tr_", "TR", true},
		{"account._fast1_usa_", "", false},
		{"account.task1", "", false},
	} {
		country, fastest := FastestCountry(tc.key)
		if country != tc.country || fastest != tc.fastest {
			t.Fatalf("%q: %q %v", tc.key, country, fastest)
		}
	}
}
