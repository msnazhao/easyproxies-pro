package monitor

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
)

func namedURI(uri, name string) string {
	if name == "" {
		return uri
	}
	if strings.HasPrefix(uri, "vmess://") && !strings.Contains(uri, "@") {
		payload := strings.SplitN(strings.TrimPrefix(uri, "vmess://"), "#", 2)[0]
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			body, err := encoding.DecodeString(payload)
			if err != nil {
				continue
			}
			fields := map[string]any{}
			if json.Unmarshal(body, &fields) != nil {
				continue
			}
			fields["ps"] = name
			body, err = json.Marshal(fields)
			if err == nil {
				return "vmess://" + base64.StdEncoding.EncodeToString(body)
			}
		}
	}
	if strings.HasPrefix(uri, "ssr://") {
		payload := strings.TrimPrefix(uri, "ssr://")
		for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
			body, err := encoding.DecodeString(payload)
			if err != nil {
				continue
			}
			base, query, _ := strings.Cut(string(body), "/?")
			values, _ := url.ParseQuery(query)
			values.Set("remarks", base64.RawURLEncoding.EncodeToString([]byte(name)))
			return "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(base+"/?"+values.Encode()))
		}
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	parsed.Fragment = name
	parsed.RawFragment = ""
	return parsed.String()
}
