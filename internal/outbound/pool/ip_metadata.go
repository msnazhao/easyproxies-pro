package pool

import (
	"context"
	"net"
	"net/http"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (p *poolOutbound) enrichExit(member *memberState, used bool) {
	if p.monitor != nil && member.entry != nil {
		p.monitor.EnrichExit(p.ctx, member.entry, used)
	}
}

func (p *poolOutbound) lookupExit(member *memberState) (ip, iso, country, provider string, err error) {
	if p.monitor != nil && p.monitor.Metadata != nil && p.monitor.Metadata.HasInfo() {
		transport := &http.Transport{DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return member.outbound.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(address))
		}, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		if location, lookupErr := p.monitor.Metadata.Self(p.ctx, client); lookupErr == nil {
			return location.IP, location.ISO, location.Country, location.Org, nil
		}
	}
	return lookupExit(p.ctx, member.outbound)
}
