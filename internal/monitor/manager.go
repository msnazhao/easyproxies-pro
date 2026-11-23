package monitor

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"easy_proxies/internal/geoip"
	"easy_proxies/internal/ipmeta"

	M "github.com/sagernet/sing/common/metadata"
)

// Config mirrors user settings needed by the monitoring server.
type Config struct {
	Enabled          bool
	Listen           string
	ProbeTarget      string
	Password         string
	ProxyUsername    string // 代理池的用户名（用于导出）
	ProxyPassword    string // 代理池的密码（用于导出）
	ExternalIP       string // 外部 IP 地址，用于导出时替换 0.0.0.0
	SkipCertVerify   bool   // 全局跳过 SSL 证书验证
	ProbeConcurrency int    // 并发探测线程数（批量探测与周期健康检查共用）
}

// NodeInfo is static metadata about a proxy entry.
type NodeInfo struct {
	OriginalName  string        `json:"original_name,omitempty"`
	ASN           string        `json:"asn,omitempty"`
	OrgDomain     string        `json:"org_domain,omitempty"`
	OrgShort      string        `json:"org_short,omitempty"`
	NetworkType   string        `json:"network_type,omitempty"`
	Abuse         *ipmeta.Abuse `json:"abuse,omitempty"`
	Tag           string        `json:"tag"`
	Name          string        `json:"name"`
	URI           string        `json:"uri"`
	Mode          string        `json:"mode"`
	ListenAddress string        `json:"listen_address,omitempty"`
	Port          uint16        `json:"port,omitempty"`
	Region        string        `json:"region,omitempty"`  // Region code derived from the measured exit IP.
	Country       string        `json:"country,omitempty"` // Full country name from GeoIP
	EntryCountry  string        `json:"entry_country,omitempty"`
	EntryISO      string        `json:"entry_iso,omitempty"`
	ExitIP        string        `json:"exit_ip,omitempty"`
	Provider      string        `json:"provider,omitempty"`
	CountryCode   string        `json:"country_code,omitempty"`
}

// TimelineEvent represents a single usage event for debug tracking.
type TimelineEvent struct {
	Time      time.Time `json:"time"`
	Success   bool      `json:"success"`
	LatencyMs int64     `json:"latency_ms"`
	Error     string    `json:"error,omitempty"`
}

const maxTimelineSize = 20

// Snapshot is a runtime view of a proxy node.
type Snapshot struct {
	NodeInfo
	FailureCount      int             `json:"failure_count"`
	SuccessCount      int64           `json:"success_count"`
	Blacklisted       bool            `json:"blacklisted"`
	BlacklistedUntil  time.Time       `json:"blacklisted_until"`
	ActiveConnections int32           `json:"active_connections"`
	LastError         string          `json:"last_error,omitempty"`
	LastFailure       time.Time       `json:"last_failure,omitempty"`
	LastSuccess       time.Time       `json:"last_success,omitempty"`
	LastProbeLatency  time.Duration   `json:"last_probe_latency,omitempty"`
	ExitVerifiedAt    time.Time       `json:"exit_verified_at,omitzero"`
	ExitProbeStatus   string          `json:"exit_probe_status,omitempty"`
	LastLatencyMs     int64           `json:"last_latency_ms"`
	Available         bool            `json:"available"`
	InitialCheckDone  bool            `json:"initial_check_done"`
	Timeline          []TimelineEvent `json:"timeline,omitempty"`
	exitRouteIP       netip.Addr
}

type probeFunc func(ctx context.Context) (time.Duration, error)
type releaseFunc func()

type periodicProbeKey struct{}

// PeriodicProbeSince returns the activity cutoff for a periodic probe.
// Startup and manual probes have no activity cutoff.
func PeriodicProbeSince(ctx context.Context) time.Time {
	since, _ := ctx.Value(periodicProbeKey{}).(time.Time)
	return since
}

// probeRun coalesces callers for one node. A protocol dial that ignores context
// can retain at most one callback goroutine per entry, not one per HTTP request.
type probeRun struct {
	done       chan struct{}
	latency    time.Duration
	err        error
	generation uint64
}

type EntryHandle struct {
	ref *entry
}

type entry struct {
	metadataPending    bool
	metadataUsed       bool
	metadataVersion    uint64
	metadataUsageDone  bool
	nextAbuseCheck     time.Time
	info               NodeInfo
	failure            int
	success            int64
	timeline           []TimelineEvent
	blacklist          bool
	until              time.Time
	lastError          string
	lastFail           time.Time
	lastOK             time.Time
	lastProbe          time.Duration
	lastProbeAt        time.Time
	active             atomic.Int32
	lastUsedAt         atomic.Int64
	probe              probeFunc
	afterProbeSuccess  func(context.Context)
	probeRun           *probeRun
	probeGeneration    uint64
	exitPending        chan struct{}
	exitProbeFailure   string
	exitIP             netip.Addr
	exitVerifiedAt     time.Time
	exitAttemptedAt    time.Time
	exitGeneration     uint64
	release            releaseFunc
	blacklistFn        func(time.Duration)
	initialCheckDone   bool
	available          bool
	needsRecoveryProbe bool
	availableFast      atomic.Bool
	blacklistUntilNano atomic.Int64
	mu                 sync.RWMutex
}

type enrichTask struct {
	ctx         context.Context
	handle      *EntryHandle
	info        NodeInfo
	generation  uint64
	needsEnrich bool
	hasAbuse    bool
	version     uint64
}

// Manager aggregates all node states for the UI/API.
type Manager struct {
	Metadata         *ipmeta.Service
	cfg              Config
	probeDst         M.Socksaddr
	probeHost        string // probe target hostname (TLS SNI when probeTLS is true)
	probeTLS         bool   // HTTPS health check, regardless of certificate policy
	probeSkipVerify  bool   // explicitly configured certificate-verification override
	probeReady       bool
	probeConcurrency int
	mu               sync.RWMutex
	nodes            map[string]*entry
	reloadMeasures   map[string]nodeMeasurements
	ctx              context.Context
	cancel           context.CancelFunc
	logger           Logger
	enrichCh         chan enrichTask
	enrichOnce       sync.Once

	// Sweep progress for the WebUI. probeSweepActive is 1 while probeAllNodes
	// runs; the counters let the dashboard show a live "初始化探测中 3200/8363".
	probeSweepActive atomic.Int32
	probeSweepTotal  atomic.Int32
	probeSweepDone   atomic.Int32
	probeSweepOK     atomic.Int32
	probeSweepFail   atomic.Int32

	// probeGate serializes health-check sweeps. probeAllNodes is triggered from
	// several places concurrently (boot, the 5-minute ticker, and post-reload
	// ProbeAllNow); without this gate two sweeps overlap, corrupt the shared
	// progress counters, and — because each one clears probeSweepActive on
	// return — leave the flag flapping so the dashboard progress bar reappears
	// forever. The gate enforces single-flight and coalesces any trigger that
	// arrives mid-sweep into exactly one follow-up pass (so a reload's newly
	// registered nodes still get probed).
	probeGate      sync.Mutex
	sweepRunning   bool
	sweepCancel    context.CancelFunc
	rerunRequested bool
	rerunSince     time.Time
	rerunUnchecked bool
}

// ProbeSweepProgress reports the current health-check sweep progress. active is
// true only while a sweep is running.
func (m *Manager) ProbeSweepProgress() (active bool, done, total, ok, failed int) {
	return m.probeSweepActive.Load() == 1,
		int(m.probeSweepDone.Load()),
		int(m.probeSweepTotal.Load()),
		int(m.probeSweepOK.Load()),
		int(m.probeSweepFail.Load())
}

// Logger interface for logging
type Logger interface {
	Info(args ...any)
	Warn(args ...any)
}

// clampProbeConcurrency is the single source of truth for the periodic probe
// worker count: 0/unset → 32 default, then bounded to [8, 1024]. The high
// ceiling lets large inventories (thousands of nodes) finish the initial sweep
// in minutes instead of ~an hour; fd use is ~2× the worker count, well within a
// raised nofile limit. Used by every write path (NewManager, SetProbeConcurrency)
// so batch and periodic probes can never disagree on the ceiling.
func clampProbeConcurrency(n int) int {
	if n <= 0 {
		n = 32
	}
	if n < 8 {
		n = 8
	}
	if n > 1024 {
		n = 1024
	}
	return n
}

// resolveProbeTarget derives the probe destination and TLS SNI host. HTTPS
// always uses TLS even if certificate verification is explicitly disabled.
func resolveProbeTarget(probeTarget string) (dst M.Socksaddr, host string, useTLS, ready bool) {
	if probeTarget == "" {
		return M.Socksaddr{}, "", false, false
	}
	target := probeTarget
	isHTTPS := strings.HasPrefix(target, "https://")
	// Strip URL scheme if present (e.g., "https://www.google.com:443" -> "www.google.com:443")
	if strings.HasPrefix(target, "https://") {
		target = strings.TrimPrefix(target, "https://")
	} else if strings.HasPrefix(target, "http://") {
		target = strings.TrimPrefix(target, "http://")
	}
	// Remove trailing path if present
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}
	h, port, err := net.SplitHostPort(target)
	if err != nil {
		// If no port specified, use default based on original scheme
		h = target
		if isHTTPS {
			port = "443"
		} else {
			port = "80"
		}
	}
	return M.ParseSocksaddrHostPort(h, parsePort(port)), h, isHTTPS, true
}

// NewManager constructs a manager and pre-validates the probe target.
func NewManager(cfg Config) (*Manager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		Metadata:         ipmeta.New(),
		cfg:              cfg,
		nodes:            make(map[string]*entry),
		ctx:              ctx,
		cancel:           cancel,
		probeConcurrency: clampProbeConcurrency(cfg.ProbeConcurrency),
	}
	m.probeDst, m.probeHost, m.probeTLS, m.probeReady = resolveProbeTarget(cfg.ProbeTarget)
	m.probeSkipVerify = cfg.SkipCertVerify
	return m, nil
}

// SetLogger sets the logger for the manager.
func (m *Manager) SetLogger(logger Logger) {
	m.mu.Lock()
	m.logger = logger
	m.mu.Unlock()
}

// SetProbeConcurrency updates the worker limit used by periodic health checks.
// Called when the live config changes so WebUI edits apply after a reload.
func (m *Manager) SetProbeConcurrency(n int) {
	n = clampProbeConcurrency(n)
	m.mu.Lock()
	m.probeConcurrency = n
	m.mu.Unlock()
}

// ProbeConcurrency returns the current periodic-probe worker limit (clamped).
func (m *Manager) ProbeConcurrency() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.probeConcurrency
}

// SetProbeTarget re-derives the probe destination and strict-TLS decision from
// the live config so WebUI changes to probe_target / skip_cert_verify take
// effect after a reload without a full process restart. The monitor Manager is
// a long-lived singleton, so without this the startup-time target/TLS mode
// would persist until the process restarts.
func (m *Manager) SetProbeTarget(probeTarget string, skipCertVerify bool) {
	dst, host, useTLS, ready := resolveProbeTarget(probeTarget)
	m.mu.Lock()
	m.probeDst, m.probeHost, m.probeTLS, m.probeReady = dst, host, useTLS, ready
	m.probeSkipVerify = skipCertVerify
	m.mu.Unlock()
}

// StartPeriodicHealthCheck discovers nodes at startup and checks recently used nodes.
// interval: how often to check (e.g., 30 * time.Second)
// timeout: timeout for each probe (e.g., 10 * time.Second)
func (m *Manager) StartPeriodicHealthCheck(interval, timeout time.Duration) {
	m.mu.RLock()
	probeReady, logger := m.probeReady, m.logger
	m.mu.RUnlock()
	if !probeReady {
		// No probe target configured: nodes cannot be verified. Run probeAllNodes
		// once so it marks every node initialCheckDone+available via its nil-probe
		// branch — otherwise nodes stay initialCheckDone=false forever and both the
		// export and the "healthy online" count read zero. Do not start the ticker.
		if logger != nil {
			logger.Warn("probe target not configured, marking all nodes available without verification")
		}
		m.probeAllNodes(timeout)
		return
	}

	go func() {
		// 启动后立即进行一次检查
		m.probeAllNodes(timeout)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
				m.probeNodes(timeout, time.Now().Add(-interval), false)
			}
		}
	}()

	if logger != nil {
		logger.Info("periodic health check started, interval: ", interval)
	}
}

// ProbeAllNow triggers a one-time health check on all nodes (e.g. after reload).
func (m *Manager) ProbeAllNow(timeout time.Duration) {
	m.probeAllNodes(timeout)
}

// ProbeUncheckedNow triggers a health check only for nodes without an initial result.
func (m *Manager) ProbeUncheckedNow(timeout time.Duration) {
	m.probeNodes(timeout, time.Time{}, true)
}

// CancelActiveSweep cancels any in-flight health-check sweep and clears queued reruns.
func (m *Manager) CancelActiveSweep() {
	m.probeGate.Lock()
	cancel := m.sweepCancel
	m.rerunRequested = false
	m.rerunSince = time.Time{}
	m.rerunUnchecked = false
	m.probeGate.Unlock()
	if cancel != nil {
		cancel()
	}
}

// probeAllNodes runs a health-check sweep, but only one at a time. If a sweep is
// already in flight, the request is coalesced: exactly one additional sweep runs
// after the current one finishes, so triggers that arrive mid-sweep (e.g. a
// reload registering new nodes) are honored without stacking up overlapping
// sweeps that would corrupt the shared progress counters and wedge the WebUI
// progress bar "active" flag on.
func (m *Manager) probeAllNodes(timeout time.Duration) {
	m.probeNodes(timeout, time.Time{}, false)
}

func (m *Manager) probeNodes(timeout time.Duration, since time.Time, onlyUnchecked bool) {
	if m.ctx.Err() != nil {
		return
	}
	m.probeGate.Lock()
	if m.sweepRunning {
		// A sweep is running: request one follow-up pass and return. The running
		// sweep will pick this up when it drains the gate.
		if !m.rerunRequested {
			m.rerunSince = since
			m.rerunUnchecked = onlyUnchecked
		} else {
			if since.Before(m.rerunSince) {
				m.rerunSince = since
			}
			if !onlyUnchecked {
				m.rerunUnchecked = false
			}
		}
		m.rerunRequested = true
		m.probeGate.Unlock()
		return
	}
	m.sweepRunning = true
	m.probeGate.Unlock()

	for {
		sweepCtx, sweepCancel := context.WithCancel(m.ctx)
		m.probeGate.Lock()
		m.sweepCancel = sweepCancel
		m.probeGate.Unlock()

		m.runProbeSweep(sweepCtx, timeout, since, onlyUnchecked)
		sweepCancel()

		m.probeGate.Lock()
		m.sweepCancel = nil
		if m.rerunRequested && m.ctx.Err() == nil {
			since = m.rerunSince
			onlyUnchecked = m.rerunUnchecked
			m.rerunRequested = false
			m.rerunUnchecked = false
			m.probeGate.Unlock()
			continue // A trigger arrived mid-sweep; run exactly one more pass.
		}
		m.rerunRequested = false
		m.rerunSince = time.Time{}
		m.rerunUnchecked = false
		m.sweepRunning = false
		m.probeGate.Unlock()
		return
	}
}

// runProbeSweep checks the selected nodes concurrently. probeNodes guarantees
// single-flight execution, so the
// shared probeSweep* progress counters are never written by two sweeps at once.
func (m *Manager) runProbeSweep(sweepCtx context.Context, timeout time.Duration, since time.Time, onlyUnchecked bool) {
	if sweepCtx.Err() != nil {
		return
	}
	now := time.Now()
	m.mu.RLock()
	logger := m.logger
	entries := make([]*entry, 0, len(m.nodes))
	for _, e := range m.nodes {
		e.mu.RLock()
		checked := e.initialCheckDone
		used := since.IsZero() || e.usedSince(since)
		needsRecovery := e.needsRecoveryLocked(now)
		e.mu.RUnlock()
		if onlyUnchecked {
			if checked {
				continue
			}
		} else if !used && !needsRecovery {
			continue
		}
		entries = append(entries, e)
	}
	m.mu.RUnlock()

	if len(entries) == 0 {
		return
	}

	if logger != nil {
		logger.Info("starting health check for ", len(entries), " nodes")
	}

	// Publish sweep progress for the WebUI. Reset counters, mark active, and
	// clear the active flag when the sweep returns.
	m.probeSweepTotal.Store(int32(len(entries)))
	m.probeSweepDone.Store(0)
	m.probeSweepOK.Store(0)
	m.probeSweepFail.Store(0)
	m.probeSweepActive.Store(1)
	defer m.probeSweepActive.Store(0)

	m.mu.RLock()
	workerLimit := m.probeConcurrency
	m.mu.RUnlock()
	if workerLimit < 8 {
		workerLimit = 8
	}
	sem := make(chan struct{}, workerLimit)
	var wg sync.WaitGroup
	var availableCount atomic.Int32
	var failedCount atomic.Int32

	for _, e := range entries {
		e.mu.RLock()
		probeFn := e.probe
		tag := e.info.Tag
		e.mu.RUnlock()

		if probeFn == nil {
			// No probe function (probe target not configured): the node cannot be
			// verified, so optimistically mark it checked+available — matching the
			// old per-pool startup probe's "no target → mark available" behavior.
			// Skipping it instead would leave initialCheckDone=false forever and
			// exclude it from export and the healthy-online count.
			e.mu.Lock()
			e.initialCheckDone = true
			e.available = true
			e.syncFastStateLocked()
			e.mu.Unlock()
			availableCount.Add(1)
			m.probeSweepOK.Add(1)
			m.probeSweepDone.Add(1)
			continue
		}

		select {
		case sem <- struct{}{}:
		case <-sweepCtx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func(entry *entry, tag string) {
			defer wg.Done()
			defer func() { <-sem }()
			if !since.IsZero() && !entry.usedSince(since) && !entry.needsRecovery(time.Now()) {
				m.probeSweepDone.Add(1)
				return
			}

			ctx, cancel := context.WithTimeout(sweepCtx, timeout)
			defer cancel()
			if !since.IsZero() {
				ctx = context.WithValue(ctx, periodicProbeKey{}, since)
			}

			latency, err, authoritative, generation := entry.waitProbe(ctx)
			// Shutdown/client cancellation says nothing about a node's health.
			if !authoritative || errors.Is(err, context.Canceled) {
				m.probeSweepDone.Add(1)
				return
			}

			if !entry.applyProbeResult(ctx, generation, latency, err) {
				m.probeSweepDone.Add(1)
				return
			}
			if err != nil {
				failedCount.Add(1)
				m.probeSweepFail.Add(1)
			} else {
				availableCount.Add(1)
				m.probeSweepOK.Add(1)
			}
			m.probeSweepDone.Add(1)

			if err != nil && logger != nil {
				entry.mu.RLock()
				uri := entry.info.URI
				entry.mu.RUnlock()
				logger.Warn("probe failed: ", FormatProbeFailure(tag, uri, err))
			}
		}(e, tag)
	}
	wg.Wait()

	if logger != nil {
		logger.Info("health check completed: ", availableCount.Load(), " available, ", failedCount.Load(), " failed")
	}
}

// Stop stops the periodic health check.
func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	if m.Metadata != nil {
		m.Metadata.Close()
	}
}

func parsePort(value string) uint16 {
	p, err := strconv.Atoi(value)
	if err != nil || p <= 0 || p > 65535 {
		return 80
	}
	return uint16(p)
}

// Register ensures a node is tracked and returns its entry.
func (m *Manager) Register(info NodeInfo) *EntryHandle {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.nodes[info.Tag]
	if ok {
		e.mu.RLock()
		same := sameNodeIdentity(e.info, info)
		e.mu.RUnlock()
		// Old callbacks keep their old entry; never let them enrich a new
		// connection merely because its display tag was reused.
		if !same {
			ok = false
		}
	}
	if !ok {
		e = &entry{
			info:     info,
			timeline: make([]TimelineEvent, 0, maxTimelineSize),
		}
		if len(m.reloadMeasures) != 0 && info.URI != "" {
			if measurements, ok := m.reloadMeasures[nodeIdentity(info)]; ok {
				measurements.restore(e)
			}
		}
		m.nodes[info.Tag] = e
	} else {
		e.mu.Lock()
		if e.info.ExitIP != "" {
			if info.OriginalName == "" {
				info.OriginalName = info.Name
				if info.Name == e.info.Name && e.info.OriginalName != "" {
					info.OriginalName = e.info.OriginalName
				}
			}
			copyExitMetadata(&info, e.info)
			formatNodeName(&info)
		}
		e.info = info
		e.mu.Unlock()
	}
	return &EntryHandle{ref: e}
}

// BeginNodeReload passes exit attempts and measured availability to matching nodes
// in the replacement runtime. New entries keep old callbacks isolated.
func (m *Manager) BeginNodeReload() func() {
	m.CancelActiveSweep()
	m.mu.Lock()
	now := time.Now()
	m.reloadMeasures = make(map[string]nodeMeasurements)
	for _, e := range m.nodes {
		e.mu.RLock()
		blacklisted := e.blacklist && (e.until.IsZero() || now.Before(e.until))
		healthy := e.initialCheckDone && e.available && !blacklisted
		if e.info.URI != "" && (healthy || blacklisted || !e.exitAttemptedAt.IsZero() || !e.exitVerifiedAt.IsZero()) {
			key := nodeIdentity(e.info)
			measurements := nodeMeasurements{exitAttemptedAt: e.exitAttemptedAt, exitProbeFailure: e.exitProbeFailure}
			if e.exitVerifiedAt.After(measurements.exitAttemptedAt) {
				measurements.exitAttemptedAt = e.exitVerifiedAt
			}
			if e.exitIP.IsValid() {
				measurements.info, measurements.exitIP, measurements.exitVerifiedAt = e.info, e.exitIP, e.exitVerifiedAt
			}
			if healthy {
				measurements.healthy = true
				measurements.lastProbe = e.lastProbe
				measurements.lastProbeAt = e.lastProbeAt
				measurements.lastOK = e.lastOK
				if measurements.lastOK.IsZero() {
					measurements.lastOK = now
				}
			} else if blacklisted {
				measurements.blacklisted = true
				measurements.wasAvailable = e.available
				measurements.blacklistedUntil = e.until
				measurements.lastError = e.lastError
			}
			if prev, exists := m.reloadMeasures[key]; !exists || measurements.healthy && !prev.healthy {
				m.reloadMeasures[key] = measurements
			}
		}
		e.mu.RUnlock()
	}
	m.nodes = make(map[string]*entry)
	m.mu.Unlock()
	return func() {
		m.mu.Lock()
		m.reloadMeasures = nil
		m.mu.Unlock()
	}
}

// ClearNodes removes all registered nodes. Call before re-registering
// during a config reload so stale entries don't persist in the dashboard.
func (m *Manager) ClearNodes() {
	m.CancelActiveSweep()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nodes = make(map[string]*entry)
}

// DestinationForProbe exposes the configured destination for health checks.
// host is the probe target's hostname (used as TLS SNI); useTLS and
// skipCertVerify independently control the HTTPS handshake and certificate policy.
func (m *Manager) DestinationForProbe() (dest M.Socksaddr, host string, useTLS, skipCertVerify, ok bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.probeReady {
		return M.Socksaddr{}, "", false, false, false
	}
	return m.probeDst, m.probeHost, m.probeTLS, m.probeSkipVerify, true
}

// Snapshot returns a sorted copy of current node states.
// If onlyAvailable is true, only returns nodes that passed initial health check.
func (m *Manager) Snapshot() []Snapshot {
	return m.SnapshotFiltered(false)
}

// SnapshotFiltered returns a sorted copy of current node states.
// If onlyAvailable is true, only returns nodes that have completed their initial
// health check and are currently available. This ensures the export function and
// the "healthy online" count in the WebUI use the same strict criterion: a node
// must be verified available, not merely "not yet proven unavailable".
func (m *Manager) SnapshotFiltered(onlyAvailable bool) []Snapshot {
	m.mu.RLock()
	list := make([]*entry, 0, len(m.nodes))
	for _, e := range m.nodes {
		list = append(list, e)
	}
	m.mu.RUnlock()
	snapshots := make([]Snapshot, 0, len(list))
	for _, e := range list {
		snap := e.snapshot()
		// When onlyAvailable is true, apply the same strict filter as the
		// "healthy online" statistic: InitialCheckDone && Available. This
		// excludes unchecked nodes (which the old logic optimistically included)
		// so export count matches the WebUI display.
		if onlyAvailable && (!snap.InitialCheckDone || !snap.Available || snap.Blacklisted) {
			continue
		}
		snapshots = append(snapshots, snap)
	}
	// 按延迟排序（延迟小的在前面，未测试的排在最后）
	sort.Slice(snapshots, func(i, j int) bool {
		latencyI := snapshots[i].LastLatencyMs
		latencyJ := snapshots[j].LastLatencyMs
		// -1 表示未测试，排在最后
		if latencyI < 0 && latencyJ < 0 {
			if snapshots[i].Name == snapshots[j].Name {
				return snapshots[i].Tag < snapshots[j].Tag
			}
			return snapshots[i].Name < snapshots[j].Name // 都未测试时按名称排序
		}
		if latencyI < 0 {
			return false // i 未测试，排在后面
		}
		if latencyJ < 0 {
			return true // j 未测试，i 排在前面
		}
		if latencyI == latencyJ {
			if snapshots[i].Name == snapshots[j].Name {
				return snapshots[i].Tag < snapshots[j].Tag
			}
			return snapshots[i].Name < snapshots[j].Name // 延迟相同时按名称排序
		}
		return latencyI < latencyJ
	})
	return snapshots
}

// Probe triggers a manual health check.
// It updates the full availability state (available / initialCheckDone / lastOK /
// lastError) so that manual and batch probes are reflected in the dashboard and
// SnapshotFiltered results immediately, matching the behaviour of the periodic
// probeAllNodes loop.
func (m *Manager) Probe(ctx context.Context, tag string) (time.Duration, error) {
	e, err := m.entry(tag)
	if err != nil {
		return 0, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Every manual caller is bounded, even when used outside the HTTP API.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	probeCtx, probeCancel := context.WithCancel(ctx)
	stop := context.AfterFunc(m.ctx, probeCancel)
	defer stop()
	defer probeCancel()
	latency, err, authoritative, generation := e.waitProbe(probeCtx)
	if !authoritative || errors.Is(err, context.Canceled) || errors.Is(err, errProbeUnavailable) {
		return 0, err
	}

	e.applyProbeResult(probeCtx, generation, latency, err)

	if err != nil {
		return 0, err
	}
	return latency, nil
}

// A completed run can have several waiting callers. A late caller from a
// previous run must not overwrite the health result of a newer run.
func (e *entry) applyProbeResult(ctx context.Context, generation uint64, latency time.Duration, err error) bool {
	e.mu.Lock()
	if generation != e.probeGeneration {
		e.mu.Unlock()
		return false
	}
	e.initialCheckDone = true
	e.needsRecoveryProbe = false
	if err != nil {
		e.lastError = err.Error()
		e.lastFail = time.Now()
		e.available = false
	} else {
		e.lastOK = time.Now()
		e.lastError = ""
		e.lastProbe = latency
		e.lastProbeAt = e.lastOK
		e.available = true
	}
	e.syncFastStateLocked()
	afterSuccess := e.afterProbeSuccess
	e.mu.Unlock()
	if err == nil && afterSuccess != nil {
		afterSuccess(ctx)
	}
	return true
}

var errProbeUnavailable = errors.New("probe not available for this node")

func (e *entry) waitProbe(ctx context.Context) (time.Duration, error, bool, uint64) {
	if err := ctx.Err(); err != nil {
		return 0, err, false, 0
	}
	e.mu.Lock()
	if e.probe == nil {
		e.mu.Unlock()
		return 0, errProbeUnavailable, false, 0
	}
	run := e.probeRun
	started := run == nil
	if run == nil {
		e.probeGeneration++
		run = &probeRun{done: make(chan struct{}), generation: e.probeGeneration}
		e.probeRun = run
		probe := e.probe
		go func() {
			run.latency, run.err = probe(ctx)
			e.mu.Lock()
			if e.probeRun == run {
				e.probeRun = nil
			}
			close(run.done)
			e.mu.Unlock()
		}()
	}
	e.mu.Unlock()
	select {
	case <-ctx.Done():
		return 0, ctx.Err(), started, run.generation
	case <-run.done:
		if err := ctx.Err(); err != nil {
			return 0, err, started, run.generation
		}
		return run.latency, run.err, true, run.generation
	}
}

// Release clears blacklist state for the given node.
func (m *Manager) Release(tag string) error {
	e, err := m.entry(tag)
	if err != nil {
		return err
	}
	e.mu.RLock()
	release := e.release
	e.mu.RUnlock()
	if release == nil {
		return errors.New("release not available for this node")
	}
	release()
	return nil
}

// ManualBlacklist manually blacklists a node for the given duration.
func (m *Manager) ManualBlacklist(tag string, duration time.Duration) error {
	e, err := m.entry(tag)
	if err != nil {
		return err
	}
	e.mu.RLock()
	fn := e.blacklistFn
	e.mu.RUnlock()

	if fn != nil {
		// Blacklist in pool shared state (affects routing)
		fn(duration)
	}
	// Also mark in monitor state (affects UI display)
	e.blacklistUntil(time.Now().Add(duration))
	return nil
}

func (m *Manager) entry(tag string) (*entry, error) {
	m.mu.RLock()
	e, ok := m.nodes[tag]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("node %s not found", tag)
	}
	return e, nil
}

func (e *entry) snapshot() Snapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now()
	var exitRouteIP netip.Addr
	if e.exitRouteReadyLocked(now) {
		exitRouteIP = e.exitIP
	}
	exitProbeStatus := e.exitProbeFailure
	if e.exitPending != nil {
		exitProbeStatus = "pending"
	}
	latencyMs := int64(-1)
	if e.lastProbe > 0 {
		latencyMs = e.lastProbe.Milliseconds()
		if latencyMs == 0 {
			latencyMs = 1
		}
	}

	var timelineCopy []TimelineEvent
	if len(e.timeline) > 0 {
		timelineCopy = make([]TimelineEvent, len(e.timeline))
		copy(timelineCopy, e.timeline)
	}

	return Snapshot{
		NodeInfo:          e.info,
		FailureCount:      e.failure,
		SuccessCount:      e.success,
		Blacklisted:       e.blacklist && (e.until.IsZero() || now.Before(e.until)),
		BlacklistedUntil:  e.until,
		ActiveConnections: e.active.Load(),
		LastError:         e.lastError,
		LastFailure:       e.lastFail,
		LastSuccess:       e.lastOK,
		LastProbeLatency:  e.lastProbe,
		ExitVerifiedAt:    e.exitVerifiedAt,
		ExitProbeStatus:   exitProbeStatus,
		LastLatencyMs:     latencyMs,
		Available:         e.available,
		InitialCheckDone:  e.initialCheckDone,
		Timeline:          timelineCopy,
		exitRouteIP:       exitRouteIP,
	}
}

func (e *entry) recordFailure(err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	errStr := err.Error()
	e.failure++
	e.lastError = errStr
	e.lastFail = time.Now()
	e.appendTimelineLocked(false, 0, errStr)
}

func (e *entry) recordSuccess() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.success++
	e.lastOK = time.Now()
	e.lastError = ""
	e.appendTimelineLocked(true, 0, "")
}

func (e *entry) recordSuccessWithLatency(latency time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.success++
	e.lastOK = time.Now()
	e.lastError = ""
	e.lastProbe = latency
	e.lastProbeAt = e.lastOK
	latencyMs := latency.Milliseconds()
	if latencyMs == 0 && latency > 0 {
		latencyMs = 1
	}
	e.appendTimelineLocked(true, latencyMs, "")
}

func (e *entry) appendTimelineLocked(success bool, latencyMs int64, errStr string) {
	evt := TimelineEvent{
		Time:      time.Now(),
		Success:   success,
		LatencyMs: latencyMs,
		Error:     errStr,
	}
	if len(e.timeline) >= maxTimelineSize {
		copy(e.timeline, e.timeline[1:])
		e.timeline[len(e.timeline)-1] = evt
	} else {
		e.timeline = append(e.timeline, evt)
	}
}

func (e *entry) syncFastStateLocked() {
	e.availableFast.Store(e.initialCheckDone && e.available)
	if !e.blacklist {
		e.blacklistUntilNano.Store(0)
		return
	}
	if e.until.IsZero() {
		e.blacklistUntilNano.Store(math.MaxInt64)
		return
	}
	e.blacklistUntilNano.Store(e.until.UnixNano())
}

func (e *entry) blacklistUntil(until time.Time) {
	e.mu.Lock()
	e.blacklist = true
	e.until = until
	e.syncFastStateLocked()
	e.mu.Unlock()
}

func (e *entry) clearBlacklist() {
	e.mu.Lock()
	e.blacklist = false
	e.until = time.Time{}
	if e.initialCheckDone && !e.available {
		e.needsRecoveryProbe = true
	}
	e.syncFastStateLocked()
	e.mu.Unlock()
}

func (e *entry) needsRecovery(now time.Time) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.needsRecoveryLocked(now)
}

func (e *entry) needsRecoveryLocked(now time.Time) bool {
	if !e.initialCheckDone || e.available {
		return false
	}
	// Still actively blacklisted or cooling down — leave parked until expiry.
	if e.blacklist && (e.until.IsZero() || now.Before(e.until)) {
		return false
	}
	return e.needsRecoveryProbe || e.blacklist
}

func (e *entry) incActive() {
	e.lastUsedAt.Store(time.Now().UnixNano())
	e.active.Add(1)
}

func (e *entry) decActive() {
	e.lastUsedAt.Store(time.Now().UnixNano())
	e.active.Add(-1)
}

func (e *entry) setRelease(fn releaseFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.release = fn
}

// RecordFailure updates failure counters.
func (h *EntryHandle) RecordFailure(err error) {
	if h == nil || h.ref == nil {
		return
	}
	h.ref.recordFailure(err)
}

// RecordSuccess updates the last success timestamp.
func (h *EntryHandle) RecordSuccess() {
	if h == nil || h.ref == nil {
		return
	}
	h.ref.recordSuccess()
}

// RecordSuccessWithLatency updates the last success timestamp and latency.
func (h *EntryHandle) RecordSuccessWithLatency(latency time.Duration) {
	if h == nil || h.ref == nil {
		return
	}
	h.ref.recordSuccessWithLatency(latency)
}

// Blacklist marks the node unavailable until the given deadline.
func (h *EntryHandle) Blacklist(until time.Time) {
	if h == nil || h.ref == nil {
		return
	}
	h.ref.blacklistUntil(until)
}

// ClearBlacklist removes the blacklist flag.
func (h *EntryHandle) ClearBlacklist() {
	if h == nil || h.ref == nil {
		return
	}
	h.ref.clearBlacklist()
}

// IncActive increments the active connection counter.
func (h *EntryHandle) IncActive() {
	if h == nil || h.ref == nil {
		return
	}
	h.ref.incActive()
}

// DecActive decrements the active connection counter.
func (h *EntryHandle) DecActive() {
	if h == nil || h.ref == nil {
		return
	}
	h.ref.decActive()
}

// SetProbe assigns a probe function.
func (h *EntryHandle) SetProbe(fn func(ctx context.Context) (time.Duration, error)) {
	h.SetProbeWithSuccess(fn, nil)
}

// SetProbeWithSuccess runs afterSuccess when the manager records a healthy result.
func (h *EntryHandle) SetProbeWithSuccess(fn func(context.Context) (time.Duration, error), afterSuccess func(context.Context)) {
	if h == nil || h.ref == nil {
		return
	}
	h.ref.mu.Lock()
	h.ref.probe = fn
	h.ref.afterProbeSuccess = afterSuccess
	h.ref.mu.Unlock()
}

// SetRelease assigns a release function.
func (h *EntryHandle) SetRelease(fn func()) {
	if h == nil || h.ref == nil {
		return
	}
	h.ref.setRelease(fn)
}

// SetBlacklistFn assigns a manual blacklist function.
func (h *EntryHandle) SetBlacklistFn(fn func(time.Duration)) {
	if h == nil || h.ref == nil {
		return
	}
	h.ref.mu.Lock()
	h.ref.blacklistFn = fn
	h.ref.mu.Unlock()
}

// MarkInitialCheckDone marks the initial health check as completed.
func (h *EntryHandle) MarkInitialCheckDone(available bool) {
	if h == nil || h.ref == nil {
		return
	}
	h.ref.mu.Lock()
	h.ref.initialCheckDone = true
	h.ref.available = available
	h.ref.syncFastStateLocked()
	h.ref.mu.Unlock()
}

// MarkAvailable updates the availability status.
func (h *EntryHandle) MarkAvailable(available bool) {
	if h == nil || h.ref == nil {
		return
	}
	h.ref.mu.Lock()
	h.ref.available = available
	if available {
		h.ref.needsRecoveryProbe = false
	}
	h.ref.syncFastStateLocked()
	h.ref.mu.Unlock()
}

// LastLatency returns the last measured probe latency.
// Returns 0 if no measurement is available yet.
func (h *EntryHandle) LastLatency() time.Duration {
	if h == nil || h.ref == nil {
		return 0
	}
	h.ref.mu.RLock()
	defer h.ref.mu.RUnlock()
	if !h.ref.available {
		return 0
	}
	return h.ref.lastProbe
}

const (
	exitRefreshInterval = 15 * time.Minute
	exitRoutingTTL      = 30 * time.Minute
)

// SetExit publishes a verified address and discards metadata belonging to the old address.
func (h *EntryHandle) SetExit(location ipmeta.Location) {
	if h == nil || h.ref == nil {
		return
	}
	address, err := netip.ParseAddr(location.IP)
	if err != nil {
		return
	}
	address = address.Unmap()
	h.ref.mu.Lock()
	defer h.ref.mu.Unlock()
	h.ref.exitVerifiedAt = time.Now()
	if h.ref.exitIP != address {
		h.ref.clearExitMetadata()
	}
	h.ref.exitIP = address
	h.ref.info.ExitIP = address.String()
	h.ref.info.mergeExitLocation(location)
	formatNodeName(&h.ref.info)
}

// InvalidateExit withdraws a conflicting exit observation from strict routing.
func (h *EntryHandle) InvalidateExit() {
	h.ref.mu.Lock()
	defer h.ref.mu.Unlock()
	h.ref.clearExitMetadata()
	h.ref.exitIP = netip.Addr{}
	h.ref.exitVerifiedAt = time.Time{}
	formatNodeName(&h.ref.info)
}

func (e *entry) clearExitMetadata() {
	copyExitMetadata(&e.info, NodeInfo{})
	e.exitGeneration++
	e.metadataVersion = 0
	e.metadataUsageDone = false
	e.nextAbuseCheck = time.Time{}
}

// BeginExitLookup allows initial discovery after a successful health check.
// Subsequent attempts also require recent traffic and respect the cooldown.
func (h *EntryHandle) BeginExitLookup(used bool) bool {
	_, start := h.QueueExitLookup(used)
	return start
}

// QueueExitLookup shares a pending exit check between callers for the same node.
func (h *EntryHandle) QueueExitLookup(used bool) (<-chan struct{}, bool) {
	if h == nil || h.ref == nil {
		return nil, false
	}
	h.ref.mu.Lock()
	defer h.ref.mu.Unlock()
	now := time.Now()
	e := h.ref
	if e.exitPending != nil {
		return e.exitPending, false
	}
	if !e.hasSuccessfulHealthCheckLocked() || now.Sub(e.exitVerifiedAt) < exitRefreshInterval ||
		now.Sub(e.exitAttemptedAt) < exitRefreshInterval {
		return nil, false
	}
	if !used && (!e.exitAttemptedAt.IsZero() || !e.exitVerifiedAt.IsZero()) {
		return nil, false
	}
	e.exitPending = make(chan struct{})
	return e.exitPending, true
}

// ExitLookupHealthy rechecks the health status when a queued lookup can run.
func (h *EntryHandle) ExitLookupHealthy() bool {
	h.ref.mu.RLock()
	defer h.ref.mu.RUnlock()
	return h.ref.hasSuccessfulHealthCheckLocked()
}

func (e *entry) hasSuccessfulHealthCheckLocked() bool {
	return e.initialCheckDone && e.available && e.lastProbe > 0
}

// ExitRouteLatency returns the latency of a healthy exit with fresh IP verification.
func (h *EntryHandle) ExitRouteLatency(ip netip.Addr, now time.Time) time.Duration {
	return h.exitRouteLatency(ip, now, true)
}

// ExitCandidateLatency includes idle exits that can be rechecked on demand.
func (h *EntryHandle) ExitCandidateLatency(ip netip.Addr, now time.Time) time.Duration {
	return h.exitRouteLatency(ip, now, false)
}

func (h *EntryHandle) exitRouteLatency(ip netip.Addr, now time.Time, fresh bool) time.Duration {
	if h == nil || h.ref == nil {
		return 0
	}
	e := h.ref
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.exitIP != ip || !e.exitRouteReadyLocked(now) || fresh && now.Sub(e.exitVerifiedAt) >= exitRoutingTTL {
		return 0
	}
	return e.lastProbe
}

func (e *entry) exitRouteReadyLocked(now time.Time) bool {
	return e.exitIP.IsValid() && e.hasSuccessfulHealthCheckLocked() &&
		!(e.blacklist && (e.until.IsZero() || now.Before(e.until)))
}

func (e *entry) usedSince(since time.Time) bool {
	return e.active.Load() > 0 || (!since.IsZero() && e.lastUsedAt.Load() >= since.UnixNano())
}

func (h *EntryHandle) UsedSince(since time.Time) bool {
	return h != nil && h.ref != nil && h.ref.usedSince(since)
}

func (h *EntryHandle) EndExitLookup(failure string) {
	if h == nil || h.ref == nil {
		return
	}
	h.ref.mu.Lock()
	if failure != "canceled" {
		h.ref.exitAttemptedAt = time.Now()
		h.ref.exitProbeFailure = failure
	}
	if h.ref.exitPending != nil {
		close(h.ref.exitPending)
		h.ref.exitPending = nil
	}
	h.ref.mu.Unlock()
}

func (h *EntryHandle) ExitKnown() bool {
	if h == nil || h.ref == nil {
		return false
	}
	h.ref.mu.RLock()
	defer h.ref.mu.RUnlock()
	return h.ref.info.ExitIP != ""
}

func (h *EntryHandle) ExitCountryCode() string {
	if h == nil || h.ref == nil {
		return ""
	}
	h.ref.mu.RLock()
	defer h.ref.mu.RUnlock()
	return h.ref.info.CountryCode
}

// ISPAbuseScore returns the AbuseIPDB score of a measured fixed-line or mobile ISP exit.
func (h *EntryHandle) ISPAbuseScore() (int, bool) {
	if h == nil || h.ref == nil {
		return 0, false
	}
	h.ref.mu.RLock()
	defer h.ref.mu.RUnlock()
	info := &h.ref.info
	if info.ExitIP == "" || (info.NetworkType != "isp" && info.NetworkType != "mobile") ||
		info.Abuse == nil || info.Abuse.Score == nil {
		return 0, false
	}
	return *info.Abuse.Score, true
}

func (h *EntryHandle) ExitIP() string {
	if h == nil || h.ref == nil {
		return ""
	}
	h.ref.mu.RLock()
	defer h.ref.mu.RUnlock()
	return h.ref.info.ExitIP
}

func (h *EntryHandle) ExitRegion() string {
	if h == nil || h.ref == nil {
		return ""
	}
	h.ref.mu.RLock()
	defer h.ref.mu.RUnlock()
	if h.ref.info.ExitIP == "" || h.ref.info.CountryCode == "" || h.ref.info.CountryCode == geoip.UnknownCountryCode {
		return ""
	}
	return h.ref.info.Region
}

func (h *EntryHandle) Available() bool {
	if h == nil || h.ref == nil {
		return false
	}
	h.ref.mu.RLock()
	defer h.ref.mu.RUnlock()
	return h.ref.initialCheckDone && h.ref.available && !(h.ref.blacklist && (h.ref.until.IsZero() || time.Now().Before(h.ref.until)))
}

// AvailableFast checks node availability without taking entry.mu.
func (h *EntryHandle) AvailableFast(nowUnixNano int64) bool {
	if h == nil || h.ref == nil || !h.ref.availableFast.Load() {
		return false
	}
	until := h.ref.blacklistUntilNano.Load()
	if until == 0 {
		return true
	}
	return until != math.MaxInt64 && nowUnixNano >= until
}
