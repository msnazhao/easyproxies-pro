package app

import (
	"context"
	"net"
	"testing"
	"time"

	"easy_proxies/internal/config"
)

func TestRunWithoutConfigReturnsError(t *testing.T) {
	if err := Run(context.Background(), nil); err == nil {
		t.Fatal("nil config started application")
	}
}

func TestRunWiresSkipCertVerifyAndStopsPromptlyOnContextCancel(t *testing.T) {
	disabled := false
	mc := buildMonitorConfig(&config.Config{
		Mode:           "pool",
		SkipCertVerify: true,
		Management: config.ManagementConfig{
			Enabled:          &disabled,
			ProbeTarget:      "https://example.invalid/generate_204",
			ProbeConcurrency: 64,
		},
	})
	if !mc.SkipCertVerify || mc.Enabled || mc.ProbeConcurrency != 64 {
		t.Fatalf("unexpected monitor config: %+v", mc)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	cfg := &config.Config{
		Mode:       "pool",
		LogLevel:   "error",
		Listener:   config.ListenerConfig{Address: "127.0.0.1", Port: uint16(port)},
		Management: config.ManagementConfig{Enabled: &disabled},
		Pool:       config.PoolConfig{Mode: "sequential"},
		Nodes:      []config.NodeConfig{{Name: "n", URI: "http://127.0.0.1:1"}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()
	time.Sleep(50 * time.Millisecond)

	stopStart := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error on graceful shutdown: %v", err)
		}
		if elapsed := time.Since(stopStart); elapsed > time.Second {
			t.Fatalf("graceful shutdown took too long: %s", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit promptly after context cancellation")
	}
}
