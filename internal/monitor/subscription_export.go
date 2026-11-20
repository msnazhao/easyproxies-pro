package monitor

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"easy_proxies/internal/routing"
)

// handleProxySubscription is public so subscription clients need no login.
func (s *Server) handleProxySubscription(w http.ResponseWriter, r *http.Request) {
	s.writeProxySubscription(w, r, false)
}

func (s *Server) handleExitProxySubscription(w http.ResponseWriter, r *http.Request) {
	s.writeProxySubscription(w, r, true)
}

func (s *Server) writeProxySubscription(w http.ResponseWriter, r *http.Request, byExitIP bool) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	var exitProxy url.URL
	if byExitIP {
		cfg, _ := s.proxyRoutingSnapshot()
		if enabled, _ := proxySessionAvailability(cfg); !enabled || cfg.Listener.Port == 0 {
			http.Error(w, "exit IP sessions unavailable", http.StatusServiceUnavailable)
			return
		}
		user, password, ok := r.BasicAuth()
		if _, authorized := routing.VerifyProxyCredentials(cfg.Listener.Username, cfg.Listener.Password, user, password, false); !ok || !authorized {
			w.Header().Set("WWW-Authenticate", `Basic realm="Proxy subscription"`)
			http.Error(w, "proxy listener credentials required", http.StatusUnauthorized)
			return
		}
		exitProxy = url.URL{
			Scheme: "socks5",
			Host:   net.JoinHostPort(proxyLinkHost(cfg.ExternalIP, r), strconv.Itoa(int(cfg.Listener.Port))),
			User:   url.UserPassword(cfg.Listener.Username, cfg.Listener.Password),
		}
	}
	s.cfgMu.RLock()
	converter := s.outboundConverter
	skipCert := s.cfg.SkipCertVerify
	s.cfgMu.RUnlock()
	countries := make(map[string]bool)
	for _, value := range r.URL.Query()["c"] {
		for _, code := range strings.Split(value, ",") {
			code = strings.ToUpper(strings.TrimSpace(code))
			if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
				http.Error(w, "c must contain comma-separated two-letter country codes", http.StatusBadRequest)
				return
			}
			countries[code] = true
		}
	}
	types := make(map[string]bool)
	for _, value := range r.URL.Query()["t"] {
		for _, protocol := range strings.Split(value, ",") {
			protocol = strings.ToLower(strings.TrimSpace(protocol))
			switch protocol {
			case "ss", "vless", "vmess", "trojan", "ssr", "hysteria2", "tuic":
				types[protocol] = true
			default:
				http.Error(w, "unsupported proxy type", http.StatusBadRequest)
				return
			}
		}
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("f")))
	network := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("n")))
	if network != "" && network != "isp" && network != "mobile" && network != "hosting" && network != "unknown" {
		http.Error(w, "n must be isp, mobile, hosting or unknown", http.StatusBadRequest)
		return
	}
	if byExitIP {
		if format != "" && format != "socks5" {
			http.Error(w, "f must be socks5", http.StatusBadRequest)
			return
		}
	} else {
		if format == "" {
			format = "v2ray"
		}
		if format != "v2ray" && format != "sing-box" {
			http.Error(w, "f must be v2ray or sing-box", http.StatusBadRequest)
			return
		}
	}
	// Never infer a country from the server's location: only measured exits
	// qualify for a country-specific subscription.
	var nodes []Snapshot
	for _, node := range s.mgr.SnapshotFiltered(true) {
		if node.LastProbeLatency <= 0 || (byExitIP && !node.exitRouteIP.IsValid()) {
			continue
		}
		if network != "" && node.NetworkType != network && !(network == "isp" && node.NetworkType == "mobile") && !(network == "unknown" && node.NetworkType == "") {
			continue
		}
		protocol, _, _ := strings.Cut(strings.ToLower(node.URI), "://")
		if protocol == "hy2" {
			protocol = "hysteria2"
		}
		if (len(countries) == 0 || node.ExitIP != "" && countries[node.CountryCode]) && (len(types) == 0 || types[protocol]) {
			nodes = append(nodes, node)
		}
	}
	if byExitIP {
		writeExitProxyLinks(w, exitProxy, nodes)
		return
	}
	if len(nodes) == 0 {
		http.Error(w, "no tested proxies available for this country", http.StatusServiceUnavailable)
		return
	}
	if format == "v2ray" {
		var links []string
		for _, node := range nodes {
			scheme, _, _ := strings.Cut(strings.ToLower(node.URI), "://")
			switch scheme {
			case "vmess", "vless", "trojan", "ss", "ssr", "hysteria2", "hy2", "tuic":
				links = append(links, namedURI(node.URI, node.Name))
			}
		}
		if len(links) == 0 {
			http.Error(w, "no supported v2ray proxies available", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprint(w, base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
		return
	}
	if converter == nil {
		http.Error(w, "sing-box exporter unavailable", http.StatusServiceUnavailable)
		return
	}
	type taggedOutbound struct {
		Type      string   `json:"type"`
		Tag       string   `json:"tag"`
		Outbounds []string `json:"outbounds"`
	}
	outbounds := make([]json.RawMessage, 0, len(nodes)+1)
	tags := make([]string, 0, len(nodes))
	for i, node := range nodes {
		tag := fmt.Sprintf("node-%d", i+1)
		if node.Name != "" {
			tag = fmt.Sprintf("%s [%d]", node.Name, i+1)
		}
		converted, err := converter(tag, node.URI, skipCert)
		if err != nil || !json.Valid(converted) {
			continue
		}
		outbounds = append(outbounds, converted)
		tags = append(tags, tag)
	}
	if len(tags) == 0 {
		http.Error(w, "no supported sing-box proxies available", http.StatusServiceUnavailable)
		return
	}
	result := map[string]any{"outbounds": outbounds}
	result["route"] = map[string]string{"final": "proxy-auto"}
	selector, _ := json.Marshal(taggedOutbound{Type: "urltest", Tag: "proxy-auto", Outbounds: tags})
	result["outbounds"] = append(outbounds, selector)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(result)
}

func writeExitProxyLinks(w http.ResponseWriter, proxy url.URL, nodes []Snapshot) {
	username := proxy.User.Username()
	password, _ := proxy.User.Password()
	if len(password) > 255 {
		http.Error(w, "proxy password exceeds the SOCKS5 limit", http.StatusServiceUnavailable)
		return
	}
	links := make([]string, 0, len(nodes))
	type selectedExit struct {
		linkIndex int
		latency   time.Duration
	}
	selected := make(map[string]selectedExit, len(nodes))
	for _, node := range nodes {
		session := routing.ExitSessionName(node.exitRouteIP)
		if session == "" {
			continue
		}
		user := username + "." + session
		if len(user) > 255 {
			continue
		}
		previous, exists := selected[session]
		latency := node.LastProbeLatency
		// Use the full probe resolution when selecting a display name.
		if exists && previous.latency <= latency {
			continue
		}
		proxy.User = url.UserPassword(user, password)
		proxy.Fragment = node.Name
		if exists {
			links[previous.linkIndex] = proxy.String()
		} else {
			previous.linkIndex = len(links)
			links = append(links, proxy.String())
		}
		previous.latency = latency
		selected[session] = previous
	}
	if len(links) == 0 {
		http.Error(w, "no matching verified exit IP proxies available", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(w, strings.Join(links, "\n"))
}
