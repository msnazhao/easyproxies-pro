package geoip

import (
	"strings"
	"testing"
)

func TestRegionForISOIncludesRequestedCountries(t *testing.T) {
	tests := []struct {
		iso  string
		want string
	}{
		{iso: "GB", want: RegionGB},
		{iso: "DE", want: RegionDE},
		{iso: "FR", want: RegionFR},
		{iso: "TR", want: RegionTR},
	}

	for _, test := range tests {
		t.Run(test.iso, func(t *testing.T) {
			if got := RegionForISO(test.iso); got != test.want {
				t.Fatalf("RegionForISO(%q) = %q, want %q", test.iso, got, test.want)
			}
			if got := RegionForISO(strings.ToLower(test.iso)); got != test.want {
				t.Fatalf("RegionForISO(lowercase %q) = %q, want %q", test.iso, got, test.want)
			}
			for _, region := range AllRegions() {
				if region == test.want {
					return
				}
			}
			t.Fatalf("region %q is missing from AllRegions", test.want)
		})
	}
}
