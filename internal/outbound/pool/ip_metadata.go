package pool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"easy_proxies/internal/geoip"
	"easy_proxies/internal/ipmeta"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var errExitProbeMismatch = errors.New("exit probes disagree")
var errExitProbeRateLimited = errors.New("exit probe rate limited")

type exitLookupTask struct {
	member *memberState
	used   bool
}

const exitLookupWorkerCount = 16

func (p *poolOutbound) startExitLookupWorkers() {
	p.exitLookupOnce.Do(func() {
		bufSize := max(64, min(16384, len(p.options.Members)))
		p.exitLookupCh = make(chan exitLookupTask, bufSize)
		workers := min(exitLookupWorkerCount, max(1, len(p.options.Members)))
		for range workers {
			go p.exitLookupWorker()
		}
	})
}

func (p *poolOutbound) exitLookupWorker() {
	for {
		select {
		case <-p.ctx.Done():
			for {
				select {
				case task := <-p.exitLookupCh:
					if task.member != nil && task.member.entry != nil {
						task.member.entry.EndExitLookup("canceled")
					}
				default:
					return
				}
			}
		case task := <-p.exitLookupCh:
			if p.ctx.Err() != nil {
				if task.member != nil && task.member.entry != nil {
					task.member.entry.EndExitLookup("canceled")
				}
				continue
			}
			p.runExitLookup(task.member, task.used)
		}
	}
}

func (p *poolOutbound) scheduleExitLookup(member *memberState, used bool) <-chan struct{} {
	entry := member.entry
	if entry == nil || p.ctx.Err() != nil {
		return nil
	}
	done, start := entry.QueueExitLookup(used)
	if start {
		p.startExitLookupWorkers()
		select {
		case p.exitLookupCh <- exitLookupTask{member: member, used: used}:
		default:
			entry.EndExitLookup("canceled")
		}
	}
	return done
}

func (p *poolOutbound) enrichExit(member *memberState, used bool) {
	if p.monitor != nil && member.entry != nil {
		p.monitor.EnrichExit(p.ctx, member.entry, used)
	}
}

func (p *poolOutbound) runExitLookup(member *memberState, used bool) {
	entry := member.entry
	failure := "canceled"
	defer func() { entry.EndExitLookup(failure) }()
	select {
	case exitLookupGate <- struct{}{}:
		defer func() { <-exitLookupGate }()
	case <-p.ctx.Done():
		return
	}
	if p.ctx.Err() != nil || !entry.ExitLookupHealthy() {
		return
	}
	location, err := p.lookupExit(member)
	if p.ctx.Err() != nil {
		return
	}
	if err == nil {
		failure = ""
		entry.SetExit(location)
		if p.monitor != nil {
			if used {
				p.monitor.RefreshExitMetadata(p.ctx, entry)
			} else {
				p.monitor.EnrichExit(p.ctx, entry, false)
			}
		}
		return
	}
	failure = "failed"
	if errors.Is(err, errExitProbeMismatch) {
		entry.InvalidateExit()
		failure = "mismatch"
	} else if errors.Is(err, errExitProbeRateLimited) {
		failure = "rate_limited"
	}
	if count := exitLookupErrors.Add(1); count <= 5 {
		log.Printf("[pool] exit lookup failed for %s: %v", member.tag, err)
	} else if count == 6 {
		log.Printf("[pool] exit lookup errors exceeded 5, suppressing further per-node warnings until next reload")
	}
}

type exitProbeConfig struct {
	CFTraceV4URL        string
	CFTraceV6URL        string
	CFTraceDualURL      string
	VerifyV4URLs        []string
	VerifyV6URLs        []string
	FallbackEchoURL     string
	FallbackLocationURL string
}

func defaultExitProbeConfig() exitProbeConfig {
	return exitProbeConfig{
		CFTraceV4URL:        "https://1.1.1.1/cdn-cgi/trace",
		CFTraceV6URL:        "https://[2606:4700:4700::1111]/cdn-cgi/trace",
		CFTraceDualURL:      "https://www.cloudflare.com/cdn-cgi/trace",
		VerifyV4URLs:        []string{"https://checkip.amazonaws.com/", "https://api.ipify.org/?format=json", "https://ipapi.co/json/"},
		VerifyV6URLs:        []string{"https://api6.ipify.org/?format=json", "https://api64.ipify.org/?format=json", "https://ipapi.co/json/"},
		FallbackEchoURL:     "https://api64.ipify.org/?format=json",
		FallbackLocationURL: "https://ipapi.co/json/",
	}
}

func (p *poolOutbound) lookupExit(member *memberState) (ipmeta.Location, error) {
	ctx, cancel := context.WithTimeout(p.ctx, 15*time.Second)
	defer cancel()
	transport := &http.Transport{DialContext: func(dialCtx context.Context, _, address string) (net.Conn, error) {
		return member.outbound.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr(address))
	}, DisableKeepAlives: true, TLSHandshakeTimeout: 4 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var metadata *ipmeta.Service
	if p.monitor != nil {
		metadata = p.monitor.Metadata
	}
	return lookupExitWithConfig(ctx, client, defaultExitProbeConfig(), metadata)
}

func lookupExitWithConfig(ctx context.Context, client *http.Client, cfg exitProbeConfig, metadata *ipmeta.Service) (ipmeta.Location, error) {
	var (
		cfLoc ipmeta.Location
		cfIP  netip.Addr
		hasCF bool
	)
	for _, endpoint := range []string{cfg.CFTraceV4URL, cfg.CFTraceV6URL, cfg.CFTraceDualURL} {
		if strings.TrimSpace(endpoint) == "" {
			continue
		}
		if ctx.Err() != nil {
			return ipmeta.Location{}, ctx.Err()
		}
		loc, ip, err := lookupCloudflareTrace(ctx, client, endpoint)
		if err == nil {
			cfLoc, cfIP, hasCF = loc, ip, true
			break
		}
	}

	if !hasCF {
		if ctx.Err() != nil {
			return ipmeta.Location{}, ctx.Err()
		}
		if cfg.FallbackEchoURL != "" && cfg.FallbackLocationURL != "" {
			return lookupExitFrom(ctx, client, cfg.FallbackEchoURL, cfg.FallbackLocationURL, metadata)
		}
		return ipmeta.Location{}, errors.New("cloudflare exit probe unavailable")
	}

	var (
		lastErr      error
		sawRateLimit bool
		verified     bool
	)

	if metadata != nil && metadata.HasInfo() {
		if preferred, err := metadata.Self(ctx, client); err == nil {
			if obs, parseErr := netip.ParseAddr(preferred.IP); parseErr == nil {
				obs = obs.Unmap()
				// On dual-stack proxies, IPinfo may use the opposite IP family; only compare same-family pairs.
				if obs.Is4() == cfIP.Is4() {
					if obs != cfIP {
						return ipmeta.Location{}, fmt.Errorf("%w: cloudflare saw %s, ipinfo saw %s", errExitProbeMismatch, cfIP, obs)
					}
					iso := geoip.NormalizeCountryCode(preferred.ISO)
					if iso == geoip.UnknownCountryCode {
						iso = cfLoc.ISO
					}
					cfLoc = preferred
					cfLoc.IP = cfIP.String()
					cfLoc.ISO = iso
					verified = true
				}
			}
		}
	}

	if !verified {
		verifiers := cfg.VerifyV4URLs
		if !cfIP.Is4() {
			verifiers = cfg.VerifyV6URLs
		}
		for _, endpoint := range verifiers {
			if strings.TrimSpace(endpoint) == "" {
				continue
			}
			if ctx.Err() != nil {
				return ipmeta.Location{}, ctx.Err()
			}
			obsLoc, obsIP, err := readObservedExit(ctx, client, endpoint)
			if err != nil {
				lastErr = err
				if errors.Is(err, errExitProbeRateLimited) {
					sawRateLimit = true
				}
				continue
			}
			if obsIP.Is4() != cfIP.Is4() {
				continue
			}
			if obsIP != cfIP {
				return ipmeta.Location{}, fmt.Errorf("%w: cloudflare saw %s, verifier saw %s", errExitProbeMismatch, cfIP, obsIP)
			}
			if cfLoc.Country == "" && obsLoc.Country != "" {
				cfLoc.Country = obsLoc.Country
			}
			if cfLoc.Org == "" && obsLoc.Org != "" {
				cfLoc.Org = obsLoc.Org
			}
			if cfLoc.ISO == "" || cfLoc.ISO == geoip.UnknownCountryCode {
				if iso := geoip.NormalizeCountryCode(obsLoc.ISO); iso != geoip.UnknownCountryCode {
					cfLoc.ISO = iso
				}
			}
			verified = true
			break
		}
	}

	if !verified {
		if ctx.Err() != nil {
			return ipmeta.Location{}, ctx.Err()
		}
		if sawRateLimit {
			return ipmeta.Location{}, fmt.Errorf("exit verification failed: %w", errExitProbeRateLimited)
		}
		if lastErr != nil {
			return ipmeta.Location{}, fmt.Errorf("exit verification failed: %w", lastErr)
		}
		return ipmeta.Location{}, errors.New("exit verification failed: no same-family confirmation")
	}

	cfLoc.IP = cfIP.String()
	cfLoc.ISO = geoip.NormalizeCountryCode(cfLoc.ISO)
	return cfLoc, nil
}

func lookupCloudflareTrace(ctx context.Context, client *http.Client, endpoint string) (ipmeta.Location, netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ipmeta.Location{}, netip.Addr{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return ipmeta.Location{}, netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return ipmeta.Location{}, netip.Addr{}, fmt.Errorf("%w: HTTP 429", errExitProbeRateLimited)
	}
	if resp.StatusCode != http.StatusOK {
		return ipmeta.Location{}, netip.Addr{}, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ipmeta.Location{}, netip.Addr{}, err
	}
	var rawIP, rawLoc string
	for _, line := range strings.Split(string(body), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			rawIP = strings.TrimSpace(v)
		case "loc":
			rawLoc = strings.TrimSpace(v)
		}
	}
	ip, err := netip.ParseAddr(rawIP)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return ipmeta.Location{}, netip.Addr{}, fmt.Errorf("invalid cloudflare trace IP")
	}
	ip = ip.Unmap()
	return ipmeta.Location{
		IP:  ip.String(),
		ISO: geoip.NormalizeCountryCode(rawLoc),
	}, ip, nil
}

func readObservedExit(ctx context.Context, client *http.Client, endpoint string) (ipmeta.Location, netip.Addr, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ipmeta.Location{}, netip.Addr{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return ipmeta.Location{}, netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return ipmeta.Location{}, netip.Addr{}, fmt.Errorf("%w: HTTP 429", errExitProbeRateLimited)
	}
	if resp.StatusCode != http.StatusOK {
		return ipmeta.Location{}, netip.Addr{}, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ipmeta.Location{}, netip.Addr{}, err
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return ipmeta.Location{}, netip.Addr{}, errors.New("empty exit probe response")
	}
	if strings.HasPrefix(trimmed, "{") {
		var result struct {
			IP      string `json:"ip"`
			ISO     string `json:"country_code"`
			Country string `json:"country_name"`
			Org     string `json:"org"`
			Error   any    `json:"error"`
			Reason  string `json:"reason"`
		}
		if err := json.Unmarshal([]byte(trimmed), &result); err != nil {
			return ipmeta.Location{}, netip.Addr{}, err
		}
		if result.Error != nil && result.Error != false || result.IP == "" {
			errMsg := strings.ToLower(fmt.Sprint(result.Error) + " " + result.Reason)
			if strings.Contains(errMsg, "ratelimit") || strings.Contains(errMsg, "too many requests") {
				return ipmeta.Location{}, netip.Addr{}, fmt.Errorf("%w: %s", errExitProbeRateLimited, strings.TrimSpace(errMsg))
			}
			return ipmeta.Location{}, netip.Addr{}, errors.New("invalid JSON exit response")
		}
		ip, err := netip.ParseAddr(result.IP)
		if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return ipmeta.Location{}, netip.Addr{}, errors.New("invalid JSON exit address")
		}
		ip = ip.Unmap()
		return ipmeta.Location{
			IP:      ip.String(),
			ISO:     geoip.NormalizeCountryCode(result.ISO),
			Country: strings.TrimSpace(result.Country),
			Org:     strings.TrimSpace(result.Org),
		}, ip, nil
	}
	ip, err := netip.ParseAddr(trimmed)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return ipmeta.Location{}, netip.Addr{}, errors.New("invalid plain-text exit address")
	}
	ip = ip.Unmap()
	return ipmeta.Location{IP: ip.String()}, ip, nil
}

// Require independent agreement before classifying a node: a proxy can use
// different egress addresses for different destinations.
func lookupExitFrom(ctx context.Context, client *http.Client, echoURL, locationURL string, metadata *ipmeta.Service) (ipmeta.Location, error) {
	var location ipmeta.Location
	if metadata != nil && metadata.HasInfo() {
		if preferred, err := metadata.Self(ctx, client); err == nil {
			location = preferred
		}
	}
	var echo struct {
		IP string `json:"ip"`
	}
	if err := readExitProbe(ctx, client, echoURL, &echo); err != nil {
		return ipmeta.Location{}, fmt.Errorf("IPify exit probe: %w", err)
	}
	ip, err := netip.ParseAddr(echo.IP)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return ipmeta.Location{}, fmt.Errorf("invalid IPify exit address")
	}
	ip = ip.Unmap()
	if location.IP == "" {
		// IPify supplies the address; the keyless lookup supplies its location
		// and confirms that the same node presents that address to both sites.
		location, err = lookupExitLocation(ctx, client, locationURL)
		if err != nil {
			return ipmeta.Location{}, err
		}
	}
	observed, err := netip.ParseAddr(location.IP)
	if err != nil || observed.Unmap() != ip {
		return ipmeta.Location{}, fmt.Errorf("%w: IPify saw %s, location probe saw %q", errExitProbeMismatch, ip, location.IP)
	}
	location.IP = ip.String()
	location.ISO = geoip.NormalizeCountryCode(location.ISO)
	return location, nil
}

func lookupExitLocation(ctx context.Context, client *http.Client, endpoint string) (ipmeta.Location, error) {
	var result struct {
		IP      string `json:"ip"`
		ISO     string `json:"country_code"`
		Country string `json:"country_name"`
		Org     string `json:"org"`
		Error   bool   `json:"error"`
		Reason  string `json:"reason"`
	}
	if err := readExitProbe(ctx, client, endpoint, &result); err != nil {
		return ipmeta.Location{}, fmt.Errorf("ipapi.co exit probe: %w", err)
	}
	if result.Error || result.IP == "" {
		if result.Error && strings.EqualFold(result.Reason, "RateLimited") {
			return ipmeta.Location{}, fmt.Errorf("ipapi.co: %w", errExitProbeRateLimited)
		}
		return ipmeta.Location{}, fmt.Errorf("invalid ipapi.co location response")
	}
	return ipmeta.Location{IP: result.IP, ISO: result.ISO, Country: result.Country, Org: result.Org}, nil
}

func readExitProbe(ctx context.Context, client *http.Client, endpoint string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("%w: HTTP 429", errExitProbeRateLimited)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(dst)
}
