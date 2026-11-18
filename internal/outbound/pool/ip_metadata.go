package pool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"easy_proxies/internal/ipmeta"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (p *poolOutbound) enrichExit(member *memberState, used bool) {
	if p.monitor != nil && member.entry != nil {
		p.monitor.EnrichExit(p.ctx, member.entry, used)
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
		return ipmeta.Location{}, fmt.Errorf("exit probes disagree: IPify saw %s, location probe saw %q", ip, location.IP)
	}
	location.IP = ip.String()
	location.ISO = strings.ToUpper(location.ISO)
	return location, nil
}

func lookupExitLocation(ctx context.Context, client *http.Client, endpoint string) (ipmeta.Location, error) {
	var result struct {
		IP      string `json:"ip"`
		ISO     string `json:"country_code"`
		Country string `json:"country_name"`
		Org     string `json:"org"`
		Error   bool   `json:"error"`
	}
	if err := readExitProbe(ctx, client, endpoint, &result); err != nil {
		return ipmeta.Location{}, fmt.Errorf("ipapi.co exit probe: %w", err)
	}
	if result.Error || len(result.ISO) != 2 {
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
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(dst)
}
