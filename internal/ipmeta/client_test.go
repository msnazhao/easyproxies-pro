package ipmeta

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestInfoFailoverSerialAndCache(t *testing.T) {
	var bad, good, active atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if active.Add(1) != 1 {
			t.Error("concurrent provider requests")
		}
		defer active.Add(-1)
		if r.Header.Get("Authorization") == "Bearer bad" {
			bad.Add(1)
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(429)
			return
		}
		if r.Header.Get("Authorization") != "Bearer good" {
			t.Error("missing authentication")
		}
		good.Add(1)
		fmt.Fprint(w, `{"ip":"23.230.52.119","country_code":"NL","country":"The Netherlands","as_name":"ColoCenter b.v.","asn":"AS58291","as_domain":"colocenter.nl"}`)
	}))
	defer server.Close()
	service := New()
	service.InfoURL = server.URL + "/"
	service.Configure(Config{IPinfoKeys: []string{"bad", "good"}})
	var workers sync.WaitGroup
	for i := 0; i < 12; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			loc, err := service.Lookup(context.Background(), "23.230.52.119")
			if err != nil || loc.Org != "ColoCenter b.v." {
				t.Errorf("lookup: %+v %v", loc, err)
			}
		}()
	}
	workers.Wait()
	if bad.Load() != 1 || good.Load() != 1 {
		t.Fatalf("calls bad=%d good=%d", bad.Load(), good.Load())
	}
}

func TestAbuseCacheByExitAndFailureRotation(t *testing.T) {
	var bad, good atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("maxAgeInDays") != "90" {
			t.Error("wrong report period")
		}
		if r.Header.Get("Key") == "bad" {
			bad.Add(1)
			w.WriteHeader(401)
			return
		}
		good.Add(1)
		fmt.Fprintf(w, `{"data":{"ipAddress":%q,"abuseConfidenceScore":0,"usageType":"Mobile ISP","isTor":false}}`, r.URL.Query().Get("ipAddress"))
	}))
	defer server.Close()
	service := New()
	service.AbuseURL = server.URL
	_, _ = service.Check(context.Background(), "1.1.1.1")
	if good.Load() != 0 {
		t.Fatal("no-key lookup made a request")
	}
	service.Configure(Config{AbuseKeys: []string{"bad", "good"}})
	result, err := service.Check(context.Background(), "1.1.1.1")
	if err != nil || result.Score == nil || *result.Score != 0 || result.NetworkType() != "mobile" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	_, _ = service.Check(context.Background(), "1.1.1.1")
	_, err = service.Check(context.Background(), "8.8.8.8")
	if err != nil || bad.Load() != 1 || good.Load() != 2 {
		t.Fatalf("cache/failover: bad=%d good=%d err=%v", bad.Load(), good.Load(), err)
	}
	expires := service.checks["1.1.1.1"]
	expires.retryAfter = time.Now().Add(-time.Second)
	service.checks["1.1.1.1"] = expires
	if _, err := service.Check(context.Background(), "1.1.1.1"); err != nil || good.Load() != 3 {
		t.Fatalf("expired score was not refreshed: calls=%d err=%v", good.Load(), err)
	}
}

func TestNamesAndHostingExclusions(t *testing.T) {
	for _, org := range []string{"Amazon.com, Inc.", "Microsoft", "ORACLE", "Google", "OVH", "GTHost", "Melbikomas", "Alibaba", "Tencent", "Greenhost", "DigitalOcean", "M247", "Datacamp", "Contabo", "ByteVirt", "VMISS", "Example cloud", "Example hosting"} {
		if !Hosting(org) {
			t.Errorf("not excluded: %s", org)
		}
	}
	zero := 0
	if got := DisplayName("Original", "NL", "23.230.52.119", "ColoCenter b.v.", "colocenter.nl", "isp", &zero); got != "ISP|0|NL|23.230.52.119|ColoCenter|Original" {
		t.Fatal(got)
	}
	if got := DisplayName("Original", "US", "8.8.8.8", "Google LLC", "google.com", "unknown", nil); got != "US|8.8.8.8|Google|Original" {
		t.Fatal(got)
	}
}

func TestSelfUsesProvidedNodeTransport(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/me" {
			t.Error(r.URL.Path)
		}
		fmt.Fprint(w, `{"ip":"1.1.1.1","country_code":"AU","as_name":"Example ISP"}`)
	}))
	defer server.Close()
	service := New()
	defer service.Close()
	service.InfoURL = server.URL + "/"
	service.Configure(Config{IPinfoKeys: []string{"key"}})
	used := false
	client := server.Client()
	base := client.Transport
	client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { used = true; return base.RoundTrip(r) })
	loc, err := service.Self(context.Background(), client)
	if err != nil || !used || calls != 1 || loc.IP != "1.1.1.1" {
		t.Fatalf("self: %+v %v used=%v", loc, err, used)
	}
	_, err = service.Lookup(context.Background(), "1.1.1.1")
	if err != nil || calls != 1 {
		t.Fatal("self response not reused")
	}
}

func TestSelfAccessBlockDoesNotDisableKeyForOtherNodes(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `{"ip":"8.8.8.8"}`)
	}))
	defer server.Close()
	service := New()
	defer service.Close()
	service.InfoURL = server.URL + "/"
	service.Configure(Config{IPinfoKeys: []string{"key"}})
	if _, err := service.Self(context.Background(), server.Client()); err == nil {
		t.Fatal("blocked IPinfo response was accepted")
	}
	result, err := service.Self(context.Background(), server.Client())
	if err != nil || result.IP != "8.8.8.8" || calls.Load() != 2 {
		t.Fatalf("another node could not use the same key: output=%+v err=%v calls=%d", result, err, calls.Load())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
