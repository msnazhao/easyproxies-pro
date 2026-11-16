package pool

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLookupExitUsesNodeDialAndRejectsInvalidResponse(t *testing.T) {
	body := `{"ip":"8.8.8.8","country_code":"US","country_name":"United States","org":"Example ISP"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	called := false
	dial := func(ctx context.Context, address string) (net.Conn, error) {
		called = true
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	ip, code, country, provider, err := lookupExitFrom(context.Background(), dial, server.URL)
	if err != nil || !called || ip != "8.8.8.8" || code != "US" || country != "United States" || provider != "Example ISP" {
		t.Fatalf("lookup: ip=%s code=%s country=%s provider=%s dialed=%t err=%v", ip, code, country, provider, called, err)
	}
	body = `{"ip":"127.0.0.1","country_code":"US"}`
	if _, _, _, _, err := lookupExitFrom(context.Background(), dial, server.URL); err == nil {
		t.Fatal("accepted loopback address as a public exit")
	}
	body = `{"ip":"1.1.1.1","success":true,"country_code":"AU","country":"Australia","connection":{"isp":"Cloud Provider"}}`
	ip, code, country, provider, err = lookupExitFrom(context.Background(), dial, server.URL)
	if err != nil || ip != "1.1.1.1" || code != "AU" || country != "Australia" || provider != "Cloud Provider" {
		t.Fatalf("fallback response: %s %s %s %s %v", ip, code, country, provider, err)
	}
}
