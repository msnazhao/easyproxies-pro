package pool

import (
	"errors"
	"io"
	"net/netip"
	"time"

	"github.com/sagernet/sing/common"
)

const exitSessionDialTimeout = 10 * time.Second

var (
	errExitSessionDisabled = errors.New("exit IP session routing is disabled")
	errNoExitCandidate     = errors.New("no verified healthy proxy available for the requested exit IP")
	errExitChanged         = errors.New("exit verification changed or expired during dial")
)

func (p *poolOutbound) pickExitIP(network string, tried map[string]bool, ip netip.Addr) (*memberState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.members) == 0 {
		if err := p.initializeMembersLocked(); err != nil {
			return nil, err
		}
	}
	now := time.Now()
	var best *memberState
	var bestLatency time.Duration
	for _, member := range p.members {
		if tried[member.tag] {
			continue
		}
		latency := member.entry.ExitRouteLatency(ip, now)
		if latency <= 0 || (best != nil && latency >= bestLatency) {
			continue
		}
		if network != "" && !common.Contains(member.outbound.Network(), network) {
			continue
		}
		if member.shared != nil && member.shared.isBlacklisted(now) {
			continue
		}
		best, bestLatency = member, latency
	}
	if best == nil {
		return nil, errNoExitCandidate
	}
	return best, nil
}

func checkDialedExit(conn io.Closer, err error, member *memberState, ip netip.Addr) error {
	if err != nil || !ip.IsValid() || member.entry.ExitRouteLatency(ip, time.Now()) > 0 {
		return err
	}
	_ = conn.Close()
	return errExitChanged
}
