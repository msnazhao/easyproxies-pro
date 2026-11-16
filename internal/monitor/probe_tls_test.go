package monitor

import (
	"testing"

	"easy_proxies/internal/config"
)

func TestHTTPSProbeCertificatePolicy(t *testing.T) {
	for _, skip := range []bool{false, true} {
		mgr, err := NewManager(Config{ProbeTarget: "https://www.gstatic.com/generate_204", SkipCertVerify: skip})
		if err != nil {
			t.Fatal(err)
		}
		dst, host, tls, skipVerify, ready := mgr.DestinationForProbe()
		if !ready || !tls || skipVerify != skip || host != "www.gstatic.com" || dst.Port != 443 {
			t.Fatalf("skip=%v: destination=%v host=%q TLS=%v skipVerify=%v ready=%v", skip, dst, host, tls, skipVerify, ready)
		}
		mgr.SetProbeTarget("https://www.gstatic.com/generate_204", !skip)
		_, _, tls, skipVerify, ready = mgr.DestinationForProbe()
		if !ready || !tls || skipVerify == skip {
			t.Fatalf("live settings: TLS=%v skipVerify=%v ready=%v", tls, skipVerify, ready)
		}
		mgr.Stop()
	}
}

func TestDefaultProbeIsStrictHTTPS(t *testing.T) {
	cfg := &config.Config{Nodes: []config.NodeConfig{{Name: "fixture", URI: "http://127.0.0.1:1"}}}
	if err := cfg.NormalizeWithPortMap(nil); err != nil {
		t.Fatal(err)
	}
	if cfg.SkipCertVerify || cfg.Management.ProbeTarget != "https://www.gstatic.com/generate_204" {
		t.Fatalf("default probe=%q skip cert=%v", cfg.Management.ProbeTarget, cfg.SkipCertVerify)
	}
}
