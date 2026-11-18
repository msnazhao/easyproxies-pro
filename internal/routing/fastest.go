package routing

import "strings"

// FastestRoute describes the selection requested by a reserved session suffix.
type FastestRoute struct {
	Enabled      bool
	Country      string
	ZeroAbuseISP bool
}

// ParseFastestRoute recognizes the reserved fastest-session suffixes.
func ParseFastestRoute(key string) FastestRoute {
	separator := strings.LastIndexByte(key, '.')
	if separator < 0 {
		return FastestRoute{}
	}
	id := key[separator+1:]
	switch id {
	case "_fast1_":
		return FastestRoute{Enabled: true}
	case "_fast1_isp_":
		return FastestRoute{Enabled: true, ZeroAbuseISP: true}
	}
	if len(id) == len("_fast1_us_") && strings.HasPrefix(id, "_fast1_") && strings.HasSuffix(id, "_") {
		code := id[7:9]
		if code[0] >= 'a' && code[0] <= 'z' && code[1] >= 'a' && code[1] <= 'z' {
			return FastestRoute{Enabled: true, Country: strings.ToUpper(code)}
		}
	}
	return FastestRoute{}
}
