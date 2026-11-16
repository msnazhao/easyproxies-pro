package routing

import "strings"

// FastestCountry recognizes the reserved session suffix and its exit country.
func FastestCountry(key string) (string, bool) {
	separator := strings.LastIndexByte(key, '.')
	if separator < 0 {
		return "", false
	}
	id := key[separator+1:]
	if id == "_fast1_" {
		return "", true
	}
	if len(id) == len("_fast1_us_") && strings.HasPrefix(id, "_fast1_") && strings.HasSuffix(id, "_") {
		code := id[7:9]
		if code[0] >= 'a' && code[0] <= 'z' && code[1] >= 'a' && code[1] <= 'z' {
			return strings.ToUpper(code), true
		}
	}
	return "", false
}
