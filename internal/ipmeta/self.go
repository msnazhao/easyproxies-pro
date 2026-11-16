package ipmeta

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
)

// Self must use a client that dials through the exact proxy being inspected.
func (s *Service) Self(ctx context.Context, client *http.Client) (Location, error) {
	if err := acquire(ctx, s.info); err != nil {
		return Location{}, err
	}
	defer func() { <-s.info.gate }()
	s.mu.RLock()
	keys := append([]string(nil), s.cfg.IPinfoKeys...)
	s.mu.RUnlock()
	var result Location
	if err := s.info.request(ctx, keys, s.InfoURL+"me", false, &result, client); err != nil {
		return result, err
	}
	ip, err := netip.ParseAddr(result.IP)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || len(result.ISO) != 2 || result.Org == "" {
		return Location{}, fmt.Errorf("invalid IPinfo exit response")
	}
	s.mu.Lock()
	s.locations[result.IP] = result
	s.mu.Unlock()
	return result, nil
}
