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

func (p *poolOutbound) scheduleExitLookup(member *memberState, used bool) {
	entry := member.entry
	if entry == nil || p.ctx.Err() != nil {
		return
	}
	if !entry.BeginExitLookup(used) {
		return
	}
	go p.runExitLookup(member, used)
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
		log.Printf("[pool] further exit lookup errors suppressed")
	}
}

func (p *poolOutbound) lookupExit(member *memberState) (ipmeta.Location, error) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		return member.outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(address))
	}, DisableKeepAlives: true, TLSHandshakeTimeout: 5 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var metadata *ipmeta.Service
	if p.monitor != nil {
		metadata = p.monitor.Metadata
	}
	return lookupExitFrom(p.ctx, client, "https://api64.ipify.org/?format=json", "https://ipapi.co/json/", metadata)
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
