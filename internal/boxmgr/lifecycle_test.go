package boxmgr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"easy_proxies/internal/config"
	"easy_proxies/internal/monitor"
	"easy_proxies/internal/outbound/pool"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

type lifecycleTestBox struct {
	start  func() error
	close  func() error
	starts atomic.Int32
	closes atomic.Int32
}

func (b *lifecycleTestBox) Start() error {
	b.starts.Add(1)
	if b.start != nil {
		return b.start()
	}
	return nil
}
func (b *lifecycleTestBox) Close() error {
	b.closes.Add(1)
	if b.close != nil {
		return b.close()
	}
	return nil
}
func lifecycleTestManager() *Manager {
	return New(&config.Config{Mode: "multi-port", MultiPort: config.MultiPortConfig{Address: "127.0.0.1"}, Nodes: []config.NodeConfig{{Name: "fixture", URI: "http://127.0.0.1:1", Port: 30000}}}, monitor.Config{ProbeTarget: ""})
}
func TestStartRejectsCancelledContextWithoutAllocatingComponents(t *testing.T) {
	m := lifecycleTestManager()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	if m.currentBox != nil || m.monitorMgr != nil || m.baseCtx != nil {
		t.Fatal("cancelled startup allocated runtime components")
	}
}
func TestStartExhaustedPortRetriesReturnsErrorAndCleansUp(t *testing.T) {
	m := lifecycleTestManager()
	var instances []*lifecycleTestBox
	m.boxFactory = func(_ context.Context, cfg *config.Config) (managedBox, error) {
		port := cfg.Nodes[0].Port
		instance := &lifecycleTestBox{start: func() error { return fmt.Errorf("listen tcp4 127.0.0.1:%d: bind: address already in use", port) }}
		instances = append(instances, instance)
		return instance, nil
	}
	err := m.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exhausted 10 attempts") {
		t.Fatalf("Start = %v, expected exhausted retry error", err)
	}
	if len(instances) != 10 {
		t.Fatalf("attempts = %d, want 10", len(instances))
	}
	for _, instance := range instances {
		if instance.closes.Load() != 1 {
			t.Fatalf("failed instance closes = %d", instance.closes.Load())
		}
	}
	if m.currentBox != nil || m.monitorMgr != nil || m.monitorServer != nil || m.baseCtx != nil {
		t.Fatal("failed startup retained runtime components")
	}
}
func TestCloseCancelsInFlightReloadAndNeverRestartsBox(t *testing.T) {
	m := lifecycleTestManager()
	old := &lifecycleTestBox{}
	calls := atomic.Int32{}
	m.boxFactory = func(context.Context, *config.Config) (managedBox, error) { calls.Add(1); return old, nil }
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	old.close = func() error { once.Do(func() { close(entered) }); <-release; return nil }
	reloaded := make(chan error, 1)
	go func() { reloaded <- m.Reload(m.CurrentConfig()) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("reload did not begin closing old box")
	}
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()
	// Close cancels the runtime before it waits for the lifecycle lock.
	m.mu.RLock()
	runtimeCtx := m.baseCtx
	m.mu.RUnlock()
	select {
	case <-runtimeCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel an in-flight reload")
	}
	close(release)
	select {
	case err := <-reloaded:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Reload = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reload cancellation blocked")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked after cancelled reload")
	}
	if calls.Load() != 1 || m.currentBox != nil || m.monitorMgr != nil {
		t.Fatal("shutdown revived a box or retained monitoring")
	}
	if err := m.Start(context.Background()); err == nil {
		t.Fatal("closed manager restarted")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestCloseCancelsInFlightStartup(t *testing.T) {
	m := lifecycleTestManager()
	entered, release := make(chan struct{}), make(chan struct{})
	instance := &lifecycleTestBox{}
	m.boxFactory = func(context.Context, *config.Config) (managedBox, error) {
		close(entered)
		<-release
		return instance, nil
	}
	started := make(chan error, 1)
	go func() { started <- m.Start(context.Background()) }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()
	m.mu.RLock()
	runtimeCtx := m.baseCtx
	m.mu.RUnlock()
	select {
	case <-runtimeCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("startup was not cancelled")
	}
	close(release)
	if err := <-started; !errors.Is(err, context.Canceled) {
		t.Fatalf("Start = %v", err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if instance.closes.Load() != 1 || m.currentBox != nil {
		t.Fatal("cancelled startup retained a box")
	}
}
func TestTriggerReloadWithoutConfigReturnsError(t *testing.T) {
	m := New(nil, monitor.Config{})
	if err := m.TriggerReload(context.Background()); !errors.Is(err, errConfigUnavailable) {
		t.Fatalf("TriggerReload = %v", err)
	}
}
func TestReassignConflictingPortDoesNotOverflow(t *testing.T) {
	for _, port := range []uint16{65535, 65534} {
		cfg := &config.Config{Mode: "multi-port", MultiPort: config.MultiPortConfig{Address: "127.0.0.1"}, Nodes: []config.NodeConfig{{Name: "fixture", Port: port}, {Name: "reserved", Port: 65535}}}
		if reassignConflictingPort(cfg, port) {
			t.Fatalf("port %d unexpectedly reassigned", port)
		}
		if cfg.Nodes[0].Port != port {
			t.Fatalf("port %d changed to %d", port, cfg.Nodes[0].Port)
		}
	}
}
func TestCurrentConfigIsIndependentSnapshot(t *testing.T) {
	enabled := true
	m := lifecycleTestManager()
	m.cfg.Subscriptions = []string{"fixture"}
	m.cfg.Management.Enabled = &enabled
	m.cfg.Pool.RetryEnabled = &enabled
	m.cfg.Sticky.SessionEnabled = &enabled
	snapshot := m.CurrentConfig()
	snapshot.Nodes[0].Name = "changed"
	snapshot.Subscriptions[0] = "changed"
	*snapshot.Management.Enabled = false
	*snapshot.Pool.RetryEnabled = false
	*snapshot.Sticky.SessionEnabled = false
	if m.cfg.Nodes[0].Name == "changed" || m.cfg.Subscriptions[0] == "changed" || !*m.cfg.Management.Enabled || !*m.cfg.Pool.RetryEnabled || !*m.cfg.Sticky.SessionEnabled {
		t.Fatal("snapshot modified live configuration")
	}
}
func TestReloadFailureRestoresGeoIPRouterAndMonitorNodes(t *testing.T) {
	a, b := newSessionLocalUpstream(t, "node-a"), newSessionLocalUpstream(t, "node-b")
	m, cfg := startSessionLocalManager(t, a, b, nil)
	cfg.GeoIP = config.GeoIPConfig{Enabled: true, Listen: "127.0.0.1", Port: sessionLocalPort(t)}
	m.startGeoIPRouter(m.baseCtx, cfg)
	invalid := m.CurrentConfig()
	invalid.Nodes = []config.NodeConfig{{Name: "invalid", URI: "unsupported://fixture"}}
	if err := m.Reload(invalid); err == nil {
		t.Fatal("invalid reload succeeded")
	}
	if m.geoRouter == nil {
		t.Fatal("rollback lost GeoIP router")
	}
	if got := sessionLocalHTTPNode(t, cfg, "wang.rollback"); got != "node-a" {
		t.Fatalf("rollback did not restore pool: %q", got)
	}
	if snapshots := m.monitorMgr.Snapshot(); len(snapshots) != 2 {
		t.Fatalf("rollback left stale monitor nodes: %d", len(snapshots))
	}
}

func TestExtractPortFromIPv6BindError(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "[::1]", "[::]"} {
		if got := extractPortFromBindError(fmt.Errorf("listen tcp6 %s:2323: bind: address already in use", address)); got != 2323 {
			t.Fatalf("address %s: got port %d", address, got)
		}
	}
}

func TestCurrentConfigReloadTransactionSerializesSettingsAndUsesLatestSnapshot(t *testing.T) {
	m := lifecycleTestManager()
	m.boxFactory = func(context.Context, *config.Config) (managedBox, error) { return &lifecycleTestBox{}, nil }
	defer m.Close()
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	unlock := m.LockSettings()
	m.cfg.ExternalIP = "latest-before-refresh"
	unlock()
	entered, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- m.ReloadWithCurrentConfig(func(candidate *config.Config) error {
			if candidate.ExternalIP != "latest-before-refresh" {
				return errors.New("refresh used stale config")
			}
			candidate.LogLevel = "debug"
			close(entered)
			<-release
			return nil
		}, func(candidate *config.Config) error {
			if candidate.ExternalIP != "latest-before-refresh" {
				return errors.New("persist saw stale config")
			}
			return nil
		})
	}()
	<-entered
	settingsEntered := make(chan struct{})
	settingsDone := make(chan struct{})
	go func() {
		unlock := m.LockSettings()
		close(settingsEntered)
		m.cfg.ExternalIP = "settings-after-refresh"
		unlock()
		close(settingsDone)
	}()
	select {
	case <-settingsEntered:
		t.Fatal("settings interleaved with a runtime config transaction")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	<-settingsDone
	cfg := m.CurrentConfig()
	if cfg.LogLevel != "debug" || cfg.ExternalIP != "settings-after-refresh" {
		t.Fatalf("transaction lost a configuration update: %+v", cfg)
	}
}
func TestCurrentConfigReloadTransactionRollsBackRuntimeOnPersistFailure(t *testing.T) {
	m := lifecycleTestManager()
	m.boxFactory = func(context.Context, *config.Config) (managedBox, error) { return &lifecycleTestBox{}, nil }
	defer m.Close()
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := m.CurrentConfig()
	sentinel := errors.New("fixture disk failure")
	err := m.ReloadWithCurrentConfig(func(candidate *config.Config) error { candidate.LogLevel = "debug"; return nil }, func(*config.Config) error { return sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("transaction error = %v", err)
	}
	if cfg := m.CurrentConfig(); cfg.LogLevel != before.LogLevel || m.currentBox == nil {
		t.Fatal("failed persistence retained updated runtime config")
	}
}

func TestCloseCancelsInitialHealthWait(t *testing.T) {
	m := lifecycleTestManager()
	m.cfg.SubscriptionRefresh.MinAvailableNodes = 1
	m.cfg.SubscriptionRefresh.HealthCheckTimeout = time.Minute
	m.boxFactory = func(context.Context, *config.Config) (managedBox, error) { return &lifecycleTestBox{}, nil }
	started := make(chan error, 1)
	go func() { started <- m.Start(context.Background()) }()
	deadline := time.After(time.Second)
	for {
		m.mu.RLock()
		waiting := m.currentBox != nil
		m.mu.RUnlock()
		if waiting {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Start did not reach initial health wait")
		case <-time.After(time.Millisecond):
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- m.Close() }()
	select {
	case err := <-started:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Start = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("health wait ignored shutdown cancellation")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close waited for health-check timeout")
	}
}

func TestReassignConflictingPortSkipsStoppedAuxiliaryListeners(t *testing.T) {
	base := sessionLocalPort(t)
	if base >= 65533 {
		t.Skip("ephemeral port is too close to maximum for this fixture")
	}
	cfg := &config.Config{Mode: "hybrid", Listener: config.ListenerConfig{Port: base + 3}, MultiPort: config.MultiPortConfig{Address: "127.0.0.1"}, Sticky: config.StickyConfig{Enabled: true, Port: base + 1}, GeoIP: config.GeoIPConfig{Enabled: true, Port: base + 2}, Nodes: []config.NodeConfig{{Name: "fixture", Port: base}}}
	if !reassignConflictingPort(cfg, base) {
		t.Fatal("available replacement port was not found")
	}
	if cfg.Nodes[0].Port <= base+3 {
		t.Fatalf("replacement stole an auxiliary/main listener port: %d", cfg.Nodes[0].Port)
	}
}

func TestCurrentSubscriptionConfigIsNarrowIndependentSnapshot(t *testing.T) {
	m := lifecycleTestManager()
	m.cfg.Nodes = make([]config.NodeConfig, 8192)
	m.cfg.NodesFile = "fixture-nodes.txt"
	m.cfg.SetFilePath("fixture-config.yaml")
	m.cfg.Subscriptions = []string{"http://fixture.invalid/sub"}
	m.cfg.SubscriptionRefresh.Interval = time.Hour
	m.cfg.Listener.Password = "not-worker-owned"
	snapshot := m.CurrentSubscriptionConfig()
	if snapshot.Nodes != nil || snapshot.Listener.Password != "" {
		t.Fatal("worker snapshot included node or credential fields")
	}
	if snapshot.NodesFile != m.cfg.NodesFile || snapshot.FilePath() != m.cfg.FilePath() || snapshot.SubscriptionRefresh != m.cfg.SubscriptionRefresh || len(snapshot.Subscriptions) != 1 {
		t.Fatalf("worker snapshot missed required fields: %+v", snapshot)
	}
	snapshot.Subscriptions[0] = "changed"
	snapshot.NodesFile = "changed"
	snapshot.SubscriptionRefresh.Interval = time.Minute
	if m.cfg.Subscriptions[0] == "changed" || m.cfg.NodesFile == "changed" || m.cfg.SubscriptionRefresh.Interval != time.Hour {
		t.Fatal("worker snapshot modified active configuration")
	}
	if New(nil, monitor.Config{}).CurrentSubscriptionConfig() != nil {
		t.Fatal("nil config returned a worker snapshot")
	}
}
func TestCurrentSubscriptionConfigCanBeReadDuringLifecycleTransaction(t *testing.T) {
	m := lifecycleTestManager()
	m.cfg.Subscriptions = []string{"http://fixture.invalid/sub"}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	done := make(chan *config.Config, 1)
	go func() { done <- m.CurrentSubscriptionConfig() }()
	select {
	case snapshot := <-done:
		if snapshot == nil || len(snapshot.Subscriptions) != 1 {
			t.Fatal("worker snapshot was empty")
		}
	case <-time.After(time.Second):
		t.Fatal("worker snapshot waited on lifecycle lock")
	}
}

func BenchmarkCurrentSubscriptionConfig(b *testing.B) {
	for _, count := range []int{32, 8192} {
		b.Run(fmt.Sprintf("nodes=%d", count), func(b *testing.B) {
			m := lifecycleTestManager()
			m.cfg.Nodes = make([]config.NodeConfig, count)
			m.cfg.Subscriptions = []string{"http://fixture.invalid/sub"}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				snapshot := m.CurrentSubscriptionConfig()
				if snapshot.Nodes != nil {
					b.Fatal("narrow snapshot copied nodes")
				}
			}
		})
	}
}

func TestPrevalidateOptionsStripsMultipleInvalidOutbounds(t *testing.T) {
	opts := option.Options{
		Outbounds: []option.Outbound{
			{
				Type: C.TypeHTTP,
				Tag:  "valid-1",
				Options: &option.HTTPOutboundOptions{
					ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 8080},
				},
			},
			{
				Type: C.TypeShadowsocks,
				Tag:  "invalid-1",
				Options: &option.ShadowsocksOutboundOptions{
					ServerOptions: option.ServerOptions{Server: "1.2.3.4", ServerPort: 443},
					Method:        "not-a-valid-ss-method",
				},
			},
			{
				Type: C.TypeShadowsocks,
				Tag:  "invalid-2",
				Options: &option.ShadowsocksOutboundOptions{
					ServerOptions: option.ServerOptions{Server: "1.2.3.5", ServerPort: 443},
					Method:        "another-bad-method",
				},
			},
			{
				Type: C.TypeHTTP,
				Tag:  "valid-2",
				Options: &option.HTTPOutboundOptions{
					ServerOptions: option.ServerOptions{Server: "127.0.0.2", ServerPort: 8081},
				},
			},
			{
				Type: pool.Type,
				Tag:  pool.Tag,
				Options: &pool.Options{
					Members: []string{"valid-1", "invalid-1", "invalid-2", "valid-2"},
					Metadata: map[string]pool.MemberMeta{
						"valid-1":   {Name: "valid-1"},
						"invalid-1": {Name: "invalid-1"},
						"invalid-2": {Name: "invalid-2"},
						"valid-2":   {Name: "valid-2"},
					},
				},
			},
			{
				Type: pool.Type,
				Tag:  "empty-pool",
				Options: &pool.Options{
					Members:  []string{"invalid-1"},
					Metadata: map[string]pool.MemberMeta{"invalid-1": {Name: "invalid-1"}},
				},
			},
		},
		Route: &option.RouteOptions{
			Final: pool.Tag,
			Rules: []option.Rule{
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{Inbound: badoption.Listable[string]{"empty-in"}},
						RuleAction: option.RuleAction{
							Action:       C.RuleActionTypeRoute,
							RouteOptions: option.RouteActionOptions{Outbound: "empty-pool"},
						},
					},
				},
				{
					Type: C.RuleTypeDefault,
					DefaultOptions: option.DefaultRule{
						RawDefaultRule: option.RawDefaultRule{Inbound: badoption.Listable[string]{"keep-in"}},
						RuleAction: option.RuleAction{
							Action:       C.RuleActionTypeRoute,
							RouteOptions: option.RouteActionOptions{Outbound: pool.Tag},
						},
					},
				},
			},
		},
	}

	cleaned, err := prevalidateOptions(context.Background(), opts)
	if err != nil {
		t.Fatalf("prevalidateOptions failed: %v", err)
	}
	if len(cleaned.Outbounds) != 3 {
		t.Fatalf("expected 2 valid outbounds + 1 pool, got %d", len(cleaned.Outbounds))
	}
	poolOpts := cleaned.Outbounds[2].Options.(*pool.Options)
	if len(poolOpts.Members) != 2 || poolOpts.Members[0] != "valid-1" || poolOpts.Members[1] != "valid-2" {
		t.Fatalf("unexpected pool members after prune: %+v", poolOpts.Members)
	}
	if _, ok := poolOpts.Metadata["invalid-1"]; ok {
		t.Fatal("stale metadata remained for removed outbound")
	}
	if len(cleaned.Route.Rules) != 1 || cleaned.Route.Rules[0].DefaultOptions.RuleAction.RouteOptions.Outbound != pool.Tag {
		t.Fatalf("dangling route rule not pruned: %+v", cleaned.Route.Rules)
	}
}

func TestReloadInvalidConfigLeavesRunningBoxUntouched(t *testing.T) {
	a, b := newSessionLocalUpstream(t, "node-a"), newSessionLocalUpstream(t, "node-b")
	m, cfg := startSessionLocalManager(t, a, b, nil)

	m.mu.RLock()
	prevBox := m.currentBox
	m.mu.RUnlock()

	invalid := m.CurrentConfig()
	invalid.Nodes = []config.NodeConfig{{Name: "invalid", URI: "unsupported://fixture"}}
	if err := m.Reload(invalid); err == nil {
		t.Fatal("expected invalid reload to fail")
	}

	m.mu.RLock()
	curBox := m.currentBox
	m.mu.RUnlock()
	if curBox != prevBox {
		t.Fatal("failed reload stopped/replaced running box instead of preserving zero downtime")
	}
	if got := sessionLocalHTTPNode(t, cfg, "wang.zero-downtime"); got != "node-a" {
		t.Fatalf("expected existing running box to keep serving, got %q", got)
	}
}

func TestReloadUpdatesMonitorProbeTargetAndRestoresOnRollback(t *testing.T) {
	m := lifecycleTestManager()
	defer m.Close()

	var failNext atomic.Bool
	m.boxFactory = func(_ context.Context, cfg *config.Config) (managedBox, error) {
		if failNext.Load() && cfg.Management.ProbeConcurrency == 128 {
			return &lifecycleTestBox{start: func() error { return errors.New("boom") }}, nil
		}
		return &lifecycleTestBox{}, nil
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	next := m.CurrentConfig()
	next.Management.ProbeTarget = "https://example.org/probe"
	next.Management.ProbeConcurrency = 64
	if err := m.Reload(next); err != nil {
		t.Fatalf("first reload failed: %v", err)
	}
	dst, _, _, _, ok := m.monitorMgr.DestinationForProbe()
	if !ok || dst.String() != "example.org:443" || m.monitorMgr.ProbeConcurrency() != 64 {
		t.Fatalf("reload did not update monitor probe target/concurrency: ok=%v dst=%s conc=%d", ok, dst.String(), m.monitorMgr.ProbeConcurrency())
	}

	failNext.Store(true)
	failing := m.CurrentConfig()
	failing.Management.ProbeTarget = "http://other.invalid:8080/health"
	failing.Management.ProbeConcurrency = 128
	if err := m.Reload(failing); err == nil {
		t.Fatal("expected second reload to fail and roll back")
	}
	dst, _, _, _, ok = m.monitorMgr.DestinationForProbe()
	if !ok || dst.String() != "example.org:443" || m.monitorMgr.ProbeConcurrency() != 64 {
		t.Fatalf("rollback did not restore probe settings: ok=%v dst=%s conc=%d", ok, dst.String(), m.monitorMgr.ProbeConcurrency())
	}
}

func TestStartPersistsReassignedPortToSidecar(t *testing.T) {
	busyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busyLn.Close()
	busyPort := uint16(busyLn.Addr().(*net.TCPAddr).Port)
	if busyPort >= 65535 {
		t.Skip("ephemeral port too high")
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := &config.Config{
		Mode:      "multi-port",
		MultiPort: config.MultiPortConfig{Address: "127.0.0.1", BasePort: busyPort},
		Nodes:     []config.NodeConfig{{Name: "fixture", URI: "http://127.0.0.1:1", Port: busyPort}},
	}
	cfg.SetFilePath(cfgPath)

	m := New(cfg, monitor.Config{Enabled: false, ProbeTarget: ""})
	defer m.Close()
	m.boxFactory = func(_ context.Context, c *config.Config) (managedBox, error) {
		p := c.Nodes[0].Port
		return &lifecycleTestBox{
			start: func() error {
				ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
				if err != nil {
					return fmt.Errorf("listen tcp4 127.0.0.1:%d: bind: address already in use", p)
				}
				_ = ln.Close()
				return nil
			},
		}, nil
	}

	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if cfg.Nodes[0].Port == busyPort {
		t.Fatalf("expected port %d to be reassigned", busyPort)
	}
	data, err := os.ReadFile(filepath.Join(dir, "node_ports.json"))
	if err != nil {
		t.Fatalf("expected node_ports.json sidecar: %v", err)
	}
	if !strings.Contains(string(data), fmt.Sprintf(": %d", cfg.Nodes[0].Port)) {
		t.Fatalf("node_ports.json did not persist reassigned port %d: %s", cfg.Nodes[0].Port, string(data))
	}
}
