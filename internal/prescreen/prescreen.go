package prescreen

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"easy_proxies/internal/builder"
	"easy_proxies/internal/config"
	"easy_proxies/internal/ssuri"
)

const (
	defaultConcurrency = 256
	maxConcurrency     = 1024
	defaultTimeout     = 2 * time.Second
)

// Options configures the 3-stage subscription node pre-screening pipeline.
type Options struct {
	Concurrency     int
	DNSTimeout      time.Duration
	TCPTimeout      time.Duration
	SkipCertVerify  bool
	AllowPrivateIPs bool
	ValidateURI     func(uri string) error
	ResolveHost     func(ctx context.Context, host string) ([]netip.Addr, error)
	DialTCP         func(ctx context.Context, addr string) error
	Loggerf         func(format string, args ...any)
}

// Stats captures node counts across the 3 pre-screening stages.
type Stats struct {
	Raw             int
	SyntaxOK        int
	DNSOK           int
	UniqueHosts     int
	TCPReachable    int
	UniqueEndpoints int
	UDPPassthrough  int
	Duration        time.Duration
}

// Result contains the surviving nodes in original order and pipeline statistics.
type Result struct {
	Nodes []config.NodeConfig
	Stats Stats
}

type parsedCandidate struct {
	node    config.NodeConfig
	host    string
	port    uint16
	isUDP   bool
	literal netip.Addr
}

type endpointKey struct {
	ip   string
	port uint16
}

// Filter runs a 3-stage pre-screen (syntax -> deduplicated DNS -> deduplicated TCP reachability)
// to quickly eliminate dead or invalid nodes before building a sing-box runtime.
func Filter(ctx context.Context, nodes []config.NodeConfig, opts Options) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	start := time.Now()
	res := Result{Stats: Stats{Raw: len(nodes)}}
	if len(nodes) == 0 {
		return res, nil
	}

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}
	if concurrency > maxConcurrency {
		concurrency = maxConcurrency
	}
	dnsTimeout := opts.DNSTimeout
	if dnsTimeout <= 0 {
		dnsTimeout = defaultTimeout
	}
	tcpTimeout := opts.TCPTimeout
	if tcpTimeout <= 0 {
		tcpTimeout = defaultTimeout
	}
	validateURI := opts.ValidateURI
	if validateURI == nil {
		validateURI = func(uri string) error {
			return builder.ValidateNodeURI(uri, opts.SkipCertVerify)
		}
	}
	resolveHost := opts.ResolveHost
	if resolveHost == nil {
		resolveHost = func(resolveCtx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(resolveCtx, "ip", host)
		}
	}
	dialTCP := opts.DialTCP
	if dialTCP == nil {
		dialTCP = func(dialCtx context.Context, addr string) error {
			conn, err := (&net.Dialer{Timeout: tcpTimeout}).DialContext(dialCtx, "tcp", addr)
			if err != nil {
				return err
			}
			_ = conn.Close()
			return nil
		}
	}

	// Stage 0: In-memory URI syntax, protocol and literal private-IP filtering.
	stage0 := make([]parsedCandidate, 0, len(nodes))
	uniqueHosts := make([]string, 0)
	hostSeen := make(map[string]struct{})
	for _, node := range nodes {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		uri := strings.TrimSpace(node.URI)
		if uri == "" {
			continue
		}
		if err := validateURI(uri); err != nil {
			continue
		}
		host, port, isUDP, ok := extractEndpoint(uri)
		if !ok || host == "" || port == 0 {
			continue
		}
		node.URI = uri
		cand := parsedCandidate{node: node, host: strings.ToLower(host), port: port, isUDP: isUDP}
		if addr, err := netip.ParseAddr(strings.Trim(cand.host, "[]")); err == nil {
			addr = addr.Unmap()
			if !opts.AllowPrivateIPs && !isPublicAddr(addr) {
				continue
			}
			cand.literal = addr
		} else if _, seen := hostSeen[cand.host]; !seen {
			hostSeen[cand.host] = struct{}{}
			uniqueHosts = append(uniqueHosts, cand.host)
		}
		stage0 = append(stage0, cand)
	}
	res.Stats.SyntaxOK = len(stage0)
	res.Stats.UniqueHosts = len(uniqueHosts)
	if len(stage0) == 0 {
		res.Stats.Duration = time.Since(start)
		logSummary(opts.Loggerf, res.Stats)
		return res, nil
	}

	// Stage 1: Deduplicated concurrent DNS resolution for domain hosts.
	resolvedHosts := make(map[string]netip.Addr, len(uniqueHosts))
	if len(uniqueHosts) > 0 {
		var mu sync.Mutex
		if err := runBounded(ctx, uniqueHosts, min(concurrency, len(uniqueHosts)), func(workerCtx context.Context, host string) {
			reqCtx, cancel := context.WithTimeout(workerCtx, dnsTimeout)
			addrs, err := resolveHost(reqCtx, host)
			cancel()
			if err != nil || len(addrs) == 0 {
				return
			}
			chosen, ok := pickResolvedAddr(addrs, opts.AllowPrivateIPs)
			if !ok {
				return
			}
			mu.Lock()
			resolvedHosts[host] = chosen
			mu.Unlock()
		}); err != nil {
			return Result{}, err
		}
	}

	stage1 := make([]parsedCandidate, 0, len(stage0))
	uniqueEndpoints := make([]endpointKey, 0)
	endpointSeen := make(map[endpointKey]struct{})
	for _, cand := range stage0 {
		if cand.literal.IsValid() {
			stage1 = append(stage1, cand)
			if !cand.isUDP {
				key := endpointKey{ip: cand.literal.String(), port: cand.port}
				if _, ok := endpointSeen[key]; !ok {
					endpointSeen[key] = struct{}{}
					uniqueEndpoints = append(uniqueEndpoints, key)
				}
			}
			continue
		}
		ip, ok := resolvedHosts[cand.host]
		if !ok {
			continue
		}
		cand.literal = ip
		stage1 = append(stage1, cand)
		if !cand.isUDP {
			key := endpointKey{ip: ip.String(), port: cand.port}
			if _, exists := endpointSeen[key]; !exists {
				endpointSeen[key] = struct{}{}
				uniqueEndpoints = append(uniqueEndpoints, key)
			}
		}
	}
	res.Stats.DNSOK = len(stage1)
	res.Stats.UniqueEndpoints = len(uniqueEndpoints)
	if len(stage1) == 0 {
		res.Stats.Duration = time.Since(start)
		logSummary(opts.Loggerf, res.Stats)
		return res, nil
	}

	// Stage 2: Deduplicated concurrent TCP reachability dial per unique ip:port.
	reachable := make(map[endpointKey]bool, len(uniqueEndpoints))
	if len(uniqueEndpoints) > 0 {
		var mu sync.Mutex
		if err := runBounded(ctx, uniqueEndpoints, min(concurrency, len(uniqueEndpoints)), func(workerCtx context.Context, ep endpointKey) {
			reqCtx, cancel := context.WithTimeout(workerCtx, tcpTimeout)
			err := dialTCP(reqCtx, net.JoinHostPort(ep.ip, strconv.Itoa(int(ep.port))))
			cancel()
			if err == nil {
				mu.Lock()
				reachable[ep] = true
				mu.Unlock()
			}
		}); err != nil {
			return Result{}, err
		}
	}

	surviving := make([]config.NodeConfig, 0, len(stage1))
	for _, cand := range stage1 {
		if cand.isUDP {
			res.Stats.UDPPassthrough++
			surviving = append(surviving, cand.node)
			continue
		}
		key := endpointKey{ip: cand.literal.String(), port: cand.port}
		if reachable[key] {
			res.Stats.TCPReachable++
			surviving = append(surviving, cand.node)
		}
	}
	res.Nodes = surviving
	res.Stats.Duration = time.Since(start)
	logSummary(opts.Loggerf, res.Stats)
	return res, nil
}

func runBounded[T any](ctx context.Context, items []T, workers int, fn func(context.Context, T)) error {
	if workers <= 0 {
		workers = 1
	}
	jobs := make(chan T)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for item := range jobs {
				if ctx.Err() != nil {
					return
				}
				fn(ctx, item)
			}
		}()
	}
	for _, item := range items {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return ctx.Err()
		case jobs <- item:
		}
	}
	close(jobs)
	wg.Wait()
	return ctx.Err()
}

func logSummary(loggerf func(string, ...any), s Stats) {
	if loggerf == nil {
		return
	}
	loggerf("prescreen: raw=%d -> syntax=%d -> dns=%d (hosts=%d) -> tcp=%d (endpoints=%d) + udp=%d => kept=%d in %s",
		s.Raw, s.SyntaxOK, s.DNSOK, s.UniqueHosts, s.TCPReachable, s.UniqueEndpoints, s.UDPPassthrough, s.TCPReachable+s.UDPPassthrough, s.Duration.Round(time.Millisecond))
}

func pickResolvedAddr(addrs []netip.Addr, allowPrivate bool) (netip.Addr, bool) {
	var fallback netip.Addr
	for _, raw := range addrs {
		addr := raw.Unmap()
		if !allowPrivate && !isPublicAddr(addr) {
			continue
		}
		if addr.Is4() {
			return addr, true
		}
		if !fallback.IsValid() {
			fallback = addr
		}
	}
	return fallback, fallback.IsValid()
}

func isPublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return false
	}
	return addr.IsGlobalUnicast()
}

func extractEndpoint(rawURI string) (host string, port uint16, isUDP bool, ok bool) {
	lower := strings.ToLower(rawURI)
	switch {
	case strings.HasPrefix(lower, "ss://"), strings.HasPrefix(lower, "shadowsocks://"):
		parsed, err := ssuri.Parse(rawURI)
		if err != nil || parsed.Server == "" || parsed.Port < 1 || parsed.Port > 65535 {
			return "", 0, false, false
		}
		return parsed.Server, uint16(parsed.Port), false, true

	case strings.HasPrefix(lower, "ssr://"), strings.HasPrefix(lower, "shadowsocksr://"):
		host, port, err := extractSSREndpoint(rawURI)
		return host, port, false, err == nil

	case strings.HasPrefix(lower, "vmess://"):
		host, port, err := extractVMessEndpoint(rawURI)
		return host, port, false, err == nil
	}

	schemeEnd := strings.Index(lower, "://")
	if schemeEnd <= 0 {
		return "", 0, false, false
	}
	scheme := lower[:schemeEnd]
	defaultPort := uint16(443)
	switch scheme {
	case "hysteria2", "hy2", "hysteria", "tuic", "wireguard":
		isUDP = true
	case "socks5", "socks5h", "socks":
		defaultPort = 1080
	case "http":
		defaultPort = 8080
	case "https", "vless", "trojan", "anytls":
	default:
		return "", 0, false, false
	}

	u, err := url.Parse(rawURI)
	if err != nil && (scheme == "hysteria2" || scheme == "hy2") {
		if normalized, changed := normalizeHy2PortHopping(rawURI); changed {
			u, err = url.Parse(normalized)
		}
	}
	if err != nil || u == nil {
		return "", 0, false, false
	}
	host = u.Hostname()
	if host == "" {
		return "", 0, false, false
	}
	if p := u.Port(); p != "" {
		parsedPort, convErr := strconv.Atoi(p)
		if convErr != nil {
			if isUDP && (scheme == "hysteria2" || scheme == "hy2") {
				return host, defaultPort, true, true
			}
			return "", 0, false, false
		}
		if parsedPort < 1 || parsedPort > 65535 {
			return "", 0, false, false
		}
		port = uint16(parsedPort)
	} else {
		port = defaultPort
	}
	return host, port, isUDP, true
}

func extractVMessEndpoint(rawURI string) (string, uint16, error) {
	encoded := rawURI[len("vmess://"):]
	if strings.Contains(encoded, "@") {
		u, err := url.Parse(rawURI)
		if err != nil || u.Hostname() == "" {
			return "", 0, errors.New("invalid vmess url")
		}
		port := 443
		if p := u.Port(); p != "" {
			v, err := strconv.Atoi(p)
			if err != nil || v < 1 || v > 65535 {
				return "", 0, errors.New("invalid vmess port")
			}
			port = v
		}
		return u.Hostname(), uint16(port), nil
	}
	if idx := strings.Index(encoded, "#"); idx != -1 {
		encoded = encoded[:idx]
	}
	encoded = strings.TrimSpace(encoded)
	var decoded []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err = enc.DecodeString(encoded)
		if err == nil {
			break
		}
	}
	if err != nil {
		return "", 0, err
	}
	var payload struct {
		Add  string `json:"add"`
		Port any    `json:"port"`
	}
	if err := json.Unmarshal(decoded, &payload); err != nil || payload.Add == "" {
		return "", 0, errors.New("invalid vmess json")
	}
	port := 443
	switch v := payload.Port.(type) {
	case float64:
		port = int(v)
	case string:
		if p, convErr := strconv.Atoi(v); convErr == nil {
			port = p
		}
	}
	if port == 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid vmess port %d", port)
	}
	return payload.Add, uint16(port), nil
}

func extractSSREndpoint(rawURI string) (string, uint16, error) {
	sep := strings.Index(rawURI, "://")
	if sep < 0 {
		return "", 0, errors.New("missing scheme")
	}
	payload := rawURI[sep+3:]
	if idx := strings.Index(payload, "#"); idx != -1 {
		payload = payload[:idx]
	}
	payload = strings.TrimRight(strings.TrimSpace(payload), "=")
	padded := payload
	if m := len(padded) % 4; m != 0 {
		padded += strings.Repeat("=", 4-m)
	}
	var decoded string
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		input := padded
		if enc == base64.RawStdEncoding || enc == base64.RawURLEncoding {
			input = payload
		}
		if b, err := enc.DecodeString(input); err == nil {
			decoded = string(b)
			break
		}
	}
	if decoded == "" {
		return "", 0, errors.New("invalid ssr base64")
	}
	mainPart := decoded
	if idx := strings.Index(decoded, "/?"); idx != -1 {
		mainPart = decoded[:idx]
	} else if strings.HasSuffix(decoded, "/") {
		mainPart = decoded[:len(decoded)-1]
	}
	parts := strings.Split(mainPart, ":")
	if len(parts) < 6 {
		return "", 0, errors.New("invalid ssr fields")
	}
	n := len(parts)
	host := strings.Join(parts[:n-5], ":")
	port, err := strconv.Atoi(parts[n-5])
	if err != nil || host == "" || port < 1 || port > 65535 {
		return "", 0, errors.New("invalid ssr host or port")
	}
	return host, uint16(port), nil
}

func normalizeHy2PortHopping(rawURI string) (string, bool) {
	sep := strings.Index(rawURI, "://")
	if sep < 0 {
		return "", false
	}
	scheme := rawURI[:sep]
	rest := rawURI[sep+3:]
	fragment := ""
	if idx := strings.Index(rest, "#"); idx != -1 {
		fragment = rest[idx:]
		rest = rest[:idx]
	}
	rawQuery := ""
	if idx := strings.Index(rest, "?"); idx != -1 {
		rawQuery = rest[idx+1:]
		rest = rest[:idx]
	}
	atIdx := strings.LastIndex(rest, "@")
	if atIdx == -1 {
		return "", false
	}
	userInfo := rest[:atIdx]
	authority := rest[atIdx+1:]
	portSep := strings.LastIndex(authority, ":")
	if portSep == -1 {
		return "", false
	}
	host := authority[:portSep]
	rawPort := strings.TrimSpace(authority[portSep+1:])
	if host == "" || rawPort == "" {
		return "", false
	}
	for _, r := range rawPort {
		if !((r >= '0' && r <= '9') || r == '-' || r == ',') {
			return "", false
		}
	}
	normalized := fmt.Sprintf("%s://%s@%s:443", scheme, userInfo, host)
	if rawQuery != "" {
		normalized += "?" + rawQuery
	}
	return normalized + fragment, true
}
