package monitor

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestClassifyProbeError_PerProbeDeadlineIsNodeFault is the regression test for
// the classification-precision fix: a per-probe context deadline (the periodic
// health check wraps each probe in a ~10s timeout) must be reported as a real
// node fault — dial_timeout when it surfaces at the dial stage, read_timeout at
// the read stage — and NOT mislabeled as "cancelled (non-fault)". Otherwise a
// genuinely unreachable or too-slow node reads as "not a node problem" in logs.
func TestClassifyProbeError_PerProbeDeadlineIsNodeFault(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		wantCat string
	}{
		{
			// Go's dialer surfaces a context timeout during connect like this.
			name:    "dial-stage deadline -> dial_timeout",
			err:     fmt.Errorf("dial tcp 1.2.3.4:443: i/o timeout"),
			wantCat: "dial_timeout",
		},
		{
			// Bare context deadline at the read stage (no dial prefix).
			name:    "read-stage deadline -> read_timeout",
			err:     fmt.Errorf("Get \"https://probe\": context deadline exceeded"),
			wantCat: "read_timeout",
		},
		{
			// The raw sentinel must not be excused as a cancellation.
			name:    "bare deadline exceeded -> read_timeout",
			err:     context.DeadlineExceeded,
			wantCat: "read_timeout",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cat, _ := classifyProbeError(c.err)
			if cat != c.wantCat {
				t.Errorf("classifyProbeError(%q) category = %q, want %q", c.err, cat, c.wantCat)
			}
			if cat == "cancelled" {
				t.Errorf("a per-probe deadline must not be classified as 'cancelled' (non-fault)")
			}
		})
	}
}

// TestClassifyProbeError_BareCancellationIsNonFault verifies the narrowed
// cancellation case still fires for true cancellation (client disconnect / batch
// deadline cascade) that carries no transport-stage signal.
func TestClassifyProbeError_BareCancellationIsNonFault(t *testing.T) {
	cat, _ := classifyProbeError(context.Canceled)
	if cat != "cancelled" {
		t.Errorf("context.Canceled category = %q, want cancelled", cat)
	}
}

// TestClassifyProbeError_DialSignalWinsOverCancellation ensures a concrete dial
// failure that also mentions cancellation is still classified by the dial stage,
// not excused as a cancellation.
func TestClassifyProbeError_DialSignalWinsOverCancellation(t *testing.T) {
	err := errors.New("dial tcp 1.2.3.4:443: operation was canceled")
	if cat, _ := classifyProbeError(err); cat == "cancelled" {
		t.Errorf("dial-stage failure must not be classified as cancelled, got cancelled")
	}
}

func TestNodeBriefRedactsVMessBase64AndExtractsHostPort(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"secret-node","add":"203.0.113.10","port":"8443","id":"11111111-2222-3333-4444-555555555555"}`
	vmessURI := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON))
	if got := nodeBrief(vmessURI); got != "vmess@203.0.113.10:8443" {
		t.Fatalf("vmess nodeBrief = %q, want vmess@203.0.113.10:8443", got)
	}
	if strings.Contains(nodeBrief(vmessURI), "11111111") {
		t.Fatal("vmess nodeBrief leaked UUID")
	}
	for _, secretURI := range []string{
		"ssr://" + base64.RawURLEncoding.EncodeToString([]byte("1.2.3.4:443:origin:aes-256-cfb:plain:cGFzcw")),
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret@1.2.3.4:8388")),
	} {
		if got := nodeBrief(secretURI); got != "" {
			t.Fatalf("legacy base64 URI %q should return empty brief, got %q", secretURI, got)
		}
	}
	if got := nodeBrief("vless://secret-uuid@example.com:443?type=ws#name"); got != "vless@example.com:443" {
		t.Fatalf("vless nodeBrief = %q", got)
	}
}
