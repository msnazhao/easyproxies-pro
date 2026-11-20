package monitor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"easy_proxies/internal/ipmeta"
)

func TestRegistrationPreservesMeasuredISPForSameIdentity(t *testing.T) {
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	meta := NodeInfo{Tag: "kr", Name: "Original", URI: "ss://aes-256-cfb:fixture@211.178.105.134:6123#Original", Port: 24000}
	h := registerHealthySubscriptionNode(s.mgr, meta)
	score := 58
	h.ref.mu.Lock()
	h.ref.info.ExitIP = "211.178.105.1"
	h.ref.info.CountryCode = "KR"
	h.ref.info.Country = "South Korea"
	h.ref.info.Region = "kr"
	h.ref.info.Provider = "SK Broadband Co"
	h.ref.info.ASN = "AS9318"
	h.ref.info.OrgDomain = "skbroadband.com"
	h.ref.info.OrgShort = "SK Broadband Co"
	h.ref.info.NetworkType = "isp"
	h.ref.info.Abuse = &ipmeta.Abuse{Score: &score, Usage: "Fixed Line ISP"}
	h.ref.info.OriginalName = "Original"
	h.ref.info.Name = ipmeta.DisplayName("Original", "KR", "211.178.105.1", "SK Broadband Co", "skbroadband.com", "isp", &score)
	h.ref.metadataVersion = s.mgr.Metadata.Version()
	h.ref.metadataUsageDone = true
	h.ref.mu.Unlock()
	meta.Name = "Renamed"
	meta.URI = "ss://aes-256-cfb:fixture@211.178.105.134:6123#Renamed"
	meta.Port = 24001
	again := s.mgr.Register(meta)
	snap := s.mgr.Snapshot()[0]
	if again.ref != h.ref || snap.NetworkType != "isp" || snap.ExitIP != "211.178.105.1" || snap.Abuse == nil || snap.ASN != "AS9318" || snap.Port != 24001 || snap.OriginalName != "Renamed" || !strings.HasSuffix(snap.Name, "|Renamed") {
		t.Fatalf("registration lost metadata or static update: %+v", snap)
	}
	for _, path := range []string{"/sub/proxies?t=ss", "/sub/proxies?n=isp&t=ss"} {
		r := proxyAPIRequest(t, s, http.MethodGet, path, "")
		if r.Code != 200 {
			t.Fatalf("%s: %d %s", path, r.Code, r.Body)
		}
	}
}

func TestRegistrationReusedTagDoesNotInheritMetadata(t *testing.T) {
	m, _ := NewManager(Config{})
	defer m.Stop()
	h := m.Register(NodeInfo{Tag: "shared", Name: "first", URI: "trojan://old@old.example:443", ExitIP: "1.1.1.1", NetworkType: "isp"})
	h.MarkInitialCheckDone(true)
	replacement := m.Register(NodeInfo{Tag: "shared", Name: "second", URI: "trojan://new@new.example:443"})
	// Simulate an old request completing after registration of a different node.
	h.SetExit("8.8.8.8", "US", "United States", "us", "Old ISP")
	snap := m.Snapshot()[0]
	if replacement.ref == h.ref || snap.Name != "second" || snap.ExitIP != "" || snap.NetworkType != "" || snap.InitialCheckDone {
		t.Fatalf("reused tag leaked old node state: %+v", snap)
	}
}

func TestMetadataCompletionKeepsConcurrentStaticChanges(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		fmt.Fprint(w, `{"data":{"ipAddress":"1.1.1.1","usageType":"Fixed Line ISP","abuseConfidenceScore":58}}`)
	}))
	defer api.Close()
	m, _ := NewManager(Config{})
	defer m.Stop()
	m.Metadata.AbuseURL = api.URL
	m.Metadata.Configure(ipmeta.Config{AbuseKeys: []string{"fixture"}})
	meta := NodeInfo{Tag: "a", Name: "Before", URI: "trojan://fixture@host.example:443#Before", ExitIP: "1.1.1.1", CountryCode: "KR", Provider: "Example ISP", Port: 24000}
	h := m.Register(meta)
	m.EnrichExit(context.Background(), h, false)
	<-started
	meta.Name = "After"
	meta.URI = "trojan://fixture@host.example:443#After"
	meta.Port = 24001
	m.Register(meta)
	once.Do(func() { close(release) })
	waitMetadata(t, h)
	snap := m.Snapshot()[0]
	if snap.Port != 24001 || snap.URI != meta.URI || snap.OriginalName != "After" || !strings.HasSuffix(snap.Name, "|After") || snap.NetworkType != "isp" {
		t.Fatalf("async completion overwrote registration: %+v", snap)
	}
}

func TestISPNameCannotBypassNetworkFilter(t *testing.T) {
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	registerHealthySubscriptionNode(s.mgr, NodeInfo{Tag: "fake", Name: "ISP|0|KR|fake", URI: "trojan://fixture@host.example:443", NetworkType: "hosting", ExitIP: "1.1.1.1", CountryCode: "KR"})
	if r := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies?n=isp", ""); r.Code != 503 {
		t.Fatal("untrusted display name bypassed type filter")
	}
}

func TestMetadataForPreviousExitCannotOverwriteNewExit(t *testing.T) {
	oldStarted, releaseOld := make(chan struct{}), make(chan struct{})
	var release sync.Once
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ipAddress")
		score := 7
		if ip == "1.1.1.1" {
			close(oldStarted)
			<-releaseOld
			score = 58
		}
		fmt.Fprintf(w, `{"data":{"ipAddress":%q,"usageType":"Fixed Line ISP","abuseConfidenceScore":%d}}`, ip, score)
	}))
	defer api.Close()
	defer release.Do(func() { close(releaseOld) })
	m, _ := NewManager(Config{})
	defer m.Stop()
	m.Metadata.AbuseURL = api.URL
	m.Metadata.Configure(ipmeta.Config{AbuseKeys: []string{"fixture"}})
	h := m.Register(NodeInfo{Tag: "a", Name: "Original"})
	h.SetExit("1.1.1.1", "AU", "", "", "")
	m.EnrichExit(context.Background(), h, false)
	select {
	case <-oldStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("old lookup did not start")
	}
	h.SetExit("8.8.8.8", "US", "", "", "")
	m.EnrichExit(context.Background(), h, false)
	release.Do(func() { close(releaseOld) })

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := m.Snapshot()[0]
		if snapshot.ExitIP != "8.8.8.8" || snapshot.CountryCode != "US" {
			t.Fatalf("late lookup overwrote new exit: %+v", snapshot.NodeInfo)
		}
		if snapshot.Abuse != nil {
			if snapshot.Abuse.IP != snapshot.ExitIP || *snapshot.Abuse.Score != 7 {
				t.Fatalf("wrong exit score: %+v", snapshot.Abuse)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("new exit was not enriched")
}

func TestISPClassificationPendingThenNonzeroScoreExports(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var calls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		close(started)
		<-release
		fmt.Fprint(w, `{"data":{"ipAddress":"1.1.1.1","usageType":"Fixed Line ISP","abuseConfidenceScore":58}}`)
	}))
	defer api.Close()
	s, _ := newProxySessionTestServer(t, proxySessionTestConfig())
	s.mgr.Metadata.AbuseURL = api.URL
	s.mgr.Metadata.Configure(ipmeta.Config{AbuseKeys: []string{"fixture"}})
	h := registerHealthySubscriptionNode(s.mgr, NodeInfo{Tag: "a", Name: "Original", URI: "trojan://fixture@host.example:443", ExitIP: "1.1.1.1", CountryCode: "KR", Provider: "Example ISP"})
	s.mgr.EnrichExit(context.Background(), h, false)
	<-started
	if r := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies", ""); r.Code != 200 {
		t.Fatal("healthy pending node missing from unfiltered export")
	}
	if r := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies?n=isp", ""); r.Code != 503 {
		t.Fatal("pending classification treated as ISP")
	}
	once.Do(func() { close(release) })
	waitMetadata(t, h)
	if r := proxyAPIRequest(t, s, http.MethodGet, "/sub/proxies?n=isp", ""); r.Code != 200 || calls.Load() != 1 {
		t.Fatal("confirmed nonzero-score ISP was omitted")
	}
}

func TestActualUsageDuringPendingLookupIsNotLost(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var calls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		close(started)
		<-release
		fmt.Fprint(w, `{"data":{"ipAddress":"1.1.1.1","usageType":"Fixed Line ISP","abuseConfidenceScore":58}}`)
	}))
	defer api.Close()
	defer once.Do(func() { close(release) })
	m, _ := NewManager(Config{})
	defer m.Stop()
	m.Metadata.AbuseURL = api.URL
	m.Metadata.Configure(ipmeta.Config{AbuseKeys: []string{"fixture"}})
	h := m.Register(NodeInfo{Tag: "a", Name: "Original", URI: "trojan://fixture@host.example:443", ExitIP: "1.1.1.1", Provider: "Example ISP"})
	m.EnrichExit(context.Background(), h, false)
	<-started
	m.EnrichExit(context.Background(), h, true)
	once.Do(func() { close(release) })
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		h.ref.mu.RLock()
		done := !h.ref.metadataPending && h.ref.metadataUsageDone
		h.ref.mu.RUnlock()
		if done {
			if calls.Load() != 1 {
				t.Fatal("follow-up spent quota again")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("actual-use event lost during pending lookup")
}
