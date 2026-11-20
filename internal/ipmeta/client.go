package ipmeta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	IPinfoKeys []string `yaml:"ipinfo_keys,omitempty" json:"ipinfo_keys"`
	AbuseKeys  []string `yaml:"abuseipdb_keys,omitempty" json:"abuseipdb_keys"`
}

type Location struct {
	IP      string `json:"ip"`
	ASN     string `json:"asn"`
	Org     string `json:"as_name"`
	Domain  string `json:"as_domain"`
	ISO     string `json:"country_code"`
	Country string `json:"country"`
}

type Abuse struct {
	IP         string `json:"ipAddress"`
	Score      *int   `json:"abuseConfidenceScore,omitempty"`
	Usage      string `json:"usageType"`
	ISP        string `json:"isp"`
	Domain     string `json:"domain"`
	Tor        *bool  `json:"isTor,omitempty"`
	Reports    int    `json:"totalReports"`
	Users      int    `json:"numDistinctUsers"`
	LastReport string `json:"lastReportedAt"`
}

func (a Abuse) NetworkType() string {
	switch strings.ToLower(strings.TrimSpace(a.Usage)) {
	case "fixed line isp":
		return "isp"
	case "mobile isp":
		return "mobile"
	case "data center/web hosting/transit", "content delivery network":
		return "hosting"
	}
	return "unknown"
}

// Service survives runtime reloads. Each provider has one serialized request
// lane and its own keep-alive transport, cache and key cooldowns.
type Service struct {
	mu                sync.RWMutex
	cfg               Config
	version           uint64
	info, abuse       *provider
	locations         map[string]Location
	checks            map[string]abuseCheck
	lastAbusePrune    time.Time
	InfoURL, AbuseURL string
}

type abuseCheck struct {
	result     Abuse
	retryAfter time.Time
}
type provider struct {
	gate    chan struct{}
	client  *http.Client
	blocked map[string]time.Time
	next    int
}

func newProvider() *provider {
	return &provider{gate: make(chan struct{}, 1), blocked: make(map[string]time.Time), client: &http.Client{
		Timeout:       8 * time.Second,
		Transport:     &http.Transport{Proxy: http.ProxyFromEnvironment, MaxConnsPerHost: 1, MaxIdleConns: 2, MaxIdleConnsPerHost: 1, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 5 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}
func New() *Service {
	return &Service{info: newProvider(), abuse: newProvider(), locations: map[string]Location{}, checks: map[string]abuseCheck{}, InfoURL: "https://api.ipinfo.io/lite/", AbuseURL: "https://api.abuseipdb.com/api/v2/check"}
}
func (s *Service) Close() {
	s.info.client.CloseIdleConnections()
	s.abuse.client.CloseIdleConnections()
}
func CleanKeys(keys []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key != "" && !seen[key] {
			out = append(out, key)
			seen[key] = true
		}
	}
	return out
}
func (s *Service) Configure(c Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.IPinfoKeys = CleanKeys(c.IPinfoKeys)
	c.AbuseKeys = CleanKeys(c.AbuseKeys)
	if !slices.Equal(s.cfg.IPinfoKeys, c.IPinfoKeys) || !slices.Equal(s.cfg.AbuseKeys, c.AbuseKeys) {
		s.version++
	}
	s.cfg = c
}
func (s *Service) Version() uint64 { s.mu.RLock(); defer s.mu.RUnlock(); return s.version + 1 }
func (s *Service) HasInfo() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cfg.IPinfoKeys) > 0
}
func (s *Service) HasAbuse() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.cfg.AbuseKeys) > 0
}
func acquire(ctx context.Context, p *provider) error {
	select {
	case p.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *provider) request(ctx context.Context, keys []string, endpoint string, abuse bool, dst any, client *http.Client) error {

	if client == nil {
		client = p.client
	}
	for i := 0; i < len(keys); i++ {
		index := (p.next + i) % len(keys)
		key := keys[index]
		if time.Now().Before(p.blocked[key]) {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return fmt.Errorf("invalid metadata endpoint")
		}
		req.Header.Set("Accept", "application/json")
		if abuse {
			req.Header.Set("Key", key)
		} else {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && readErr == nil && json.Unmarshal(body, dst) == nil {
			p.next = index
			return nil
		}
		delay := time.Minute
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			delay = 24 * time.Hour
		}
		if resp.StatusCode == 429 {
			delay = 24 * time.Hour
			if seconds, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && seconds > 0 {
				delay = time.Duration(seconds) * time.Second
			} else if until, err := http.ParseTime(resp.Header.Get("Retry-After")); err == nil {
				delay = time.Until(until)
			}
		}
		p.blocked[key] = time.Now().Add(delay)
	}
	return fmt.Errorf("metadata provider unavailable or keys exhausted")
}

func (s *Service) Lookup(ctx context.Context, ip string) (Location, error) {
	if _, err := netip.ParseAddr(ip); err != nil {
		return Location{}, fmt.Errorf("invalid exit IP")
	}
	if err := acquire(ctx, s.info); err != nil {
		return Location{}, err
	}
	defer func() { <-s.info.gate }()
	s.mu.RLock()
	cached, ok := s.locations[ip]
	keys := append([]string(nil), s.cfg.IPinfoKeys...)
	s.mu.RUnlock()
	if ok {
		return cached, nil
	}
	var result Location
	if err := s.info.request(ctx, keys, s.InfoURL+url.PathEscape(ip), false, &result, nil); err != nil {
		return result, err
	}
	if result.IP != ip || len(result.ISO) != 2 || result.Org == "" {
		return Location{}, fmt.Errorf("invalid IPinfo response")
	}
	result.ISO = strings.ToUpper(result.ISO)
	s.mu.Lock()
	s.locations[ip] = result
	s.mu.Unlock()
	return result, nil
}

// Check shares a result and its retry interval across nodes with the same exit IP.
func (s *Service) Check(ctx context.Context, ip string) (Abuse, error) {
	if cached, ok := s.cachedAbuseCheck(ip); ok {
		return cached.resultOrError()
	}
	if err := acquire(ctx, s.abuse); err != nil {
		return Abuse{}, err
	}
	defer func() { <-s.abuse.gate }()
	if cached, ok := s.cachedAbuseCheck(ip); ok {
		return cached.resultOrError()
	}
	s.mu.RLock()
	keys := append([]string(nil), s.cfg.AbuseKeys...)
	s.mu.RUnlock()
	if len(keys) == 0 {
		return Abuse{}, fmt.Errorf("abuse lookup skipped")
	}
	var result struct {
		Data Abuse `json:"data"`
	}
	err := s.abuse.request(ctx, keys, s.AbuseURL+"?ipAddress="+url.QueryEscape(ip)+"&maxAgeInDays=90", true, &result, nil)
	if ctx.Err() != nil {
		return Abuse{}, ctx.Err()
	}
	if err == nil && (result.Data.IP != ip || result.Data.Score != nil && (*result.Data.Score < 0 || *result.Data.Score > 100)) {
		err = fmt.Errorf("invalid AbuseIPDB response")
	}
	now := time.Now()
	check := abuseCheck{result: result.Data, retryAfter: now.Add(24 * time.Hour)}
	if err != nil {
		check = abuseCheck{retryAfter: now.Add(time.Hour)}
	}
	s.mu.Lock()
	if now.Sub(s.lastAbusePrune) >= time.Hour {
		for address, cached := range s.checks {
			if !now.Before(cached.retryAfter) {
				delete(s.checks, address)
			}
		}
		s.lastAbusePrune = now
	}
	s.checks[ip] = check
	s.mu.Unlock()
	if err != nil {
		return Abuse{}, err
	}
	return result.Data, nil
}

func (s *Service) cachedAbuseCheck(ip string) (abuseCheck, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	check := s.checks[ip]
	return check, time.Now().Before(check.retryAfter)
}

func (c abuseCheck) resultOrError() (Abuse, error) {
	if c.result.IP == "" {
		return Abuse{}, fmt.Errorf("abuse lookup on cooldown")
	}
	return c.result, nil
}

func Hosting(org string) bool {
	value := strings.ToLower(org)
	for _, name := range []string{"amazon", "microsoft", "oracle", "google", "ovh", "gthost", "melbikomas", "alibaba", "tencent", "greenhost", "digitalocean", "m247", "host", "cloud", "datacamp", "contabo", "bytevirt", "vmiss"} {
		if strings.Contains(value, name) {
			return true
		}
	}
	return false
}

func ShortOrg(org, domain string) string {
	aliases := [][2]string{{"amazon", "AWS"}, {"microsoft", "MSFT"}, {"oracle", "Oracle"}, {"google", "Google"}, {"digitalocean", "DO"}, {"alibaba", "Alibaba"}, {"tencent", "Tencent"}, {"ovh", "OVH"}, {"china mobile", "CMCC"}, {"china telecom", "CT"}, {"china unicom", "CU"}}
	for _, alias := range aliases {
		if strings.Contains(strings.ToLower(org), alias[0]) {
			return alias[1]
		}
	}
	name := org
	for _, suffix := range []string{" Co., Ltd.", ", Inc.", " Inc.", " LLC", " Limited", " Ltd.", " Ltd", " b.v.", " B.V.", " Communications", " Corporation"} {
		name = strings.TrimSuffix(name, suffix)
	}
	if name == "" {
		name = domain
	}
	if len([]rune(name)) > 24 && domain != "" {
		name = strings.Split(domain, ".")[0]
	}
	return name
}

func DisplayName(original, iso, ip, org, domain, network string, score *int) string {
	parts := []string{}
	if network == "isp" || network == "mobile" {
		parts = append(parts, "ISP")
	}
	if score != nil {
		parts = append(parts, strconv.Itoa(*score))
	}
	for _, part := range []string{iso, ip, ShortOrg(org, domain), original} {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, "|")
}
