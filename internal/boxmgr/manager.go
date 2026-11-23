package boxmgr

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"easy_proxies/internal/builder"
	"easy_proxies/internal/config"
	"easy_proxies/internal/geoip"
	"easy_proxies/internal/inbound/session"
	"easy_proxies/internal/monitor"
	"easy_proxies/internal/outbound/pool"
	"easy_proxies/internal/prescreen"
	"easy_proxies/internal/routing"

	"github.com/sagernet/sing-box"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// Ensure Manager implements monitor.NodeManager.
var _ monitor.NodeManager = (*Manager)(nil)

const (
	defaultDrainTimeout       = 10 * time.Second
	defaultHealthCheckTimeout = 30 * time.Second
	healthCheckPollInterval   = 500 * time.Millisecond
	periodicHealthInterval    = 5 * time.Minute
	// periodicHealthTimeout bounds each individual probe. Unreachable nodes wait
	// out this full deadline, so at scale (thousands of nodes) it dominates the
	// total sweep time; 5s covers a healthy node's dial+TLS+HTTP while letting
	// dead nodes be abandoned sooner.
	periodicHealthTimeout = 5 * time.Second
)

// Logger defines logging interface for the manager.
type Logger interface {
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

// Option configures the Manager.
type Option func(*Manager)

// WithLogger sets a custom logger.
func WithLogger(l Logger) Option {
	return func(m *Manager) { m.logger = l }
}

// managedBox isolates lifecycle coordination from the concrete sing-box core.
// The private factory is injectable by local regression tests.
type managedBox interface {
	Start() error
	Close() error
}

// Manager owns the lifecycle of the active sing-box instance.
type Manager struct {
	// Lifecycle operations never hold mu while waiting on network shutdown.
	lifecycleMu sync.Mutex
	mu          sync.RWMutex

	currentBox    managedBox
	boxFactory    func(context.Context, *config.Config) (managedBox, error)
	monitorMgr    *monitor.Manager
	monitorServer *monitor.Server
	geoRouter     *geoip.Router
	cfg           *config.Config
	monitorCfg    monitor.Config
	// The store belongs to the manager, not an individual box, so subscription
	// refreshes and core reloads do not discard authenticated session bindings.
	routingStore *routing.Store

	drainTimeout      time.Duration
	minAvailableNodes int
	logger            Logger

	baseCtx            context.Context
	baseCancel         context.CancelFunc
	closed             bool
	healthCheckStarted bool
}

// New creates a BoxManager with the given config.
func New(cfg *config.Config, monitorCfg monitor.Config, opts ...Option) *Manager {
	m := &Manager{
		cfg:          cfg,
		monitorCfg:   monitorCfg,
		routingStore: routing.NewStore(config.DefaultMaxSessions, config.DefaultSessionTTL),
	}
	m.applyConfigSettings(cfg)
	for _, opt := range opts {
		opt(m)
	}
	if m.logger == nil {
		m.logger = defaultLogger{}
	}
	if m.drainTimeout <= 0 {
		m.drainTimeout = defaultDrainTimeout
	}
	return m
}

// Start creates and starts the initial sing-box instance.
func (m *Manager) Start(ctx context.Context) (err error) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("box manager closed")
	}
	if m.cfg == nil {
		m.mu.Unlock()
		return errors.New("box manager requires config")
	}
	if m.currentBox != nil {
		m.mu.Unlock()
		return errors.New("sing-box already running")
	}
	m.applyConfigSettings(m.cfg)
	ctx, m.baseCancel = context.WithCancel(ctx)
	m.baseCtx = ctx
	cfg := m.cfg
	m.mu.Unlock()
	// A failed startup may already own a management listener and health-check
	// worker. Release them as well as the partially initialized box.
	defer func() {
		if err != nil {
			m.closeComponents()
		}
	}()
	if err = m.ensureMonitor(ctx); err != nil {
		return err
	}

	if cfg.SubscriptionRefresh.PreScreenEnabledFor(len(cfg.Nodes)) {
		inlineOrRetained := make([]config.NodeConfig, 0, len(cfg.Nodes))
		subOrFile := make([]config.NodeConfig, 0, len(cfg.Nodes))
		for _, node := range cfg.Nodes {
			if node.Source == config.NodeSourceInline || node.Source == config.NodeSourceRetained {
				inlineOrRetained = append(inlineOrRetained, node)
			} else {
				subOrFile = append(subOrFile, node)
			}
		}
		if len(subOrFile) > 0 && cfg.SubscriptionRefresh.PreScreenEnabledFor(len(subOrFile)) {
			res, psErr := prescreen.Filter(ctx, subOrFile, prescreen.Options{
				Concurrency:    cfg.SubscriptionRefresh.PreScreenConcurrencyOrDefault(),
				DNSTimeout:     cfg.SubscriptionRefresh.PreScreenTimeoutOrDefault(),
				TCPTimeout:     cfg.SubscriptionRefresh.PreScreenTimeoutOrDefault(),
				SkipCertVerify: cfg.SkipCertVerify,
				Loggerf:        m.logger.Infof,
			})
			if psErr != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				m.logger.Warnf("startup pre-screen failed, keeping all %d nodes: %v", len(cfg.Nodes), psErr)
			} else if len(res.Nodes) > 0 {
				filtered := make([]config.NodeConfig, 0, len(inlineOrRetained)+len(res.Nodes))
				filtered = append(filtered, inlineOrRetained...)
				filtered = append(filtered, res.Nodes...)
				m.mu.Lock()
				cfg.Nodes = filtered
				m.mu.Unlock()
				if len(inlineOrRetained) > 0 {
					m.logger.Infof("startup pre-screen active nodes: %d (%d filtered + %d inline/retained)", len(filtered), len(res.Nodes), len(inlineOrRetained))
				}
				// Sync filtered subscription nodes to disk so restart/mod-check baselines
				// match memory; never overwrite manual nodes_file when subscriptions are empty.
				filteredSubNodes := make([]config.NodeConfig, 0, len(res.Nodes))
				for _, node := range res.Nodes {
					if node.Source == config.NodeSourceSubscription {
						filteredSubNodes = append(filteredSubNodes, node)
					}
				}
				if len(filteredSubNodes) > 0 && len(cfg.Subscriptions) > 0 && cfg.NodesFile != "" {
					if saveErr := config.WriteNodesToFile(cfg.NodesFile, filteredSubNodes); saveErr != nil {
						m.logger.Warnf("failed to sync pre-screened nodes to %s: %v", cfg.NodesFile, saveErr)
					}
				}
				if (cfg.Mode == "multi-port" || cfg.Mode == "hybrid") && cfg.FilePath() != "" {
					if portErr := cfg.SaveNodePortMap(); portErr != nil {
						m.logger.Warnf("failed to persist pruned node ports: %v", portErr)
					}
				}
			} else {
				m.logger.Warnf("startup pre-screen kept 0/%d nodes; falling back to original nodes", len(subOrFile))
			}
		}
	}

	var instance managedBox
	var lastStartErr error
	started := false
	portReassigned := false
	const maxRetries = 10
	for retry := 0; retry < maxRetries; retry++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		instance, err = m.createInstance(ctx, cfg)
		if err != nil {
			return err
		}
		if err = instance.Start(); err != nil {
			_ = instance.Close()
			lastStartErr = err
			if conflictPort := extractPortFromBindError(err); conflictPort > 0 {
				m.logger.Warnf("port %d is in use, reassigning and retrying...", conflictPort)
				m.mu.Lock()
				reassigned := reassignConflictingPort(cfg, conflictPort)
				m.mu.Unlock()
				if reassigned {
					portReassigned = true
					pool.ResetSharedStateStore()
					m.monitorMgr.ClearNodes()
					continue
				}
			}
			return fmt.Errorf("start sing-box: %w", err)
		}
		started = true
		break
	}
	if !started {
		return fmt.Errorf("start sing-box: exhausted %d attempts: %w", maxRetries, lastStartErr)
	}
	if err = ctx.Err(); err != nil {
		_ = instance.Close()
		return err
	}
	if portReassigned && (cfg.Mode == "multi-port" || cfg.Mode == "hybrid") && cfg.FilePath() != "" {
		if portErr := cfg.SaveNodePortMap(); portErr != nil {
			m.logger.Warnf("failed to persist reassigned node ports: %v", portErr)
		}
	}
	m.mu.Lock()
	m.currentBox = instance
	manager := m.monitorMgr
	startHealthCheck := manager != nil && !m.healthCheckStarted
	if startHealthCheck {
		m.healthCheckStarted = true
	}
	m.mu.Unlock()
	if startHealthCheck {
		manager.StartPeriodicHealthCheck(periodicHealthInterval, periodicHealthTimeout)
	}
	m.logger.Infof("sing-box instance started with %d nodes", len(cfg.Nodes))
	if cfg.GeoIP.Enabled {
		m.startGeoIPRouter(ctx, cfg)
	}
	if cfg.SubscriptionRefresh.MinAvailableNodes > 0 {
		timeout := cfg.SubscriptionRefresh.HealthCheckTimeout
		if timeout <= 0 {
			timeout = defaultHealthCheckTimeout
		}
		if healthErr := m.waitForHealthCheck(ctx, timeout); healthErr != nil {
			if err = ctx.Err(); err != nil {
				return err
			}
			m.logger.Warnf("initial health check warning: %v", healthErr)
		}
	}
	return ctx.Err()
}

// Reload gracefully switches to a new configuration.
// For multi-port mode, we must stop the old instance first to release ports.
func (m *Manager) Reload(newCfg *config.Config) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	return m.reloadLocked(newCfg)
}

// reloadLocked requires lifecycleMu and never holds mu during network I/O.
func (m *Manager) reloadLocked(newCfg *config.Config) error {
	if newCfg == nil {
		return errors.New("new config is nil")
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("box manager closed")
	}
	if m.currentBox == nil {
		m.mu.Unlock()
		return errors.New("manager not started")
	}
	ctx := m.baseCtx
	if ctx != nil && ctx.Err() != nil {
		m.mu.Unlock()
		return ctx.Err()
	}
	oldBox := m.currentBox
	oldCfg := m.cfg
	useFactory := m.boxFactory != nil
	m.mu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}

	m.logger.Infof("reloading with %d nodes", len(newCfg.Nodes))

	oldProbeTarget := oldCfg.Management.ProbeTarget
	oldSkipCert := oldCfg.SkipCertVerify
	oldConcurrency := oldCfg.ProbeConcurrencyOrDefault()
	sameProbeSettings := oldProbeTarget == newCfg.Management.ProbeTarget && oldSkipCert == newCfg.SkipCertVerify

	restoreProbeSettings := func() {
		if m.monitorMgr != nil {
			m.monitorMgr.SetProbeConcurrency(oldConcurrency)
			m.monitorMgr.SetProbeTarget(oldProbeTarget, oldSkipCert)
		}
	}

	// Pre-build and pre-validate the replacement options before closing oldBox
	// so invalid configs fail fast with zero downtime.
	var preparedOpts option.Options
	hasPreparedOpts := false
	if !useFactory {
		opts, err := m.prepareSingBoxOptions(ctx, newCfg)
		if err != nil {
			return fmt.Errorf("create new box: %w", err)
		}
		preparedOpts = opts
		hasPreparedOpts = true
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("box manager closed")
	}
	if ctx.Err() != nil {
		m.mu.Unlock()
		return ctx.Err()
	}
	m.currentBox = nil // Mark as reloading only once replacement options are ready
	m.mu.Unlock()

	// For multi-port mode, we must close old instance first to release ports
	if oldBox != nil {
		m.logger.Infof("stopping old instance to release ports...")
		if err := oldBox.Close(); err != nil {
			m.logger.Warnf("error closing old instance: %v", err)
		}
	}

	// Stop GeoIP router before starting new box to release its port
	m.mu.Lock()
	oldRouter := m.geoRouter
	m.geoRouter = nil
	m.mu.Unlock()
	if oldRouter != nil {
		_ = oldRouter.Stop()
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	var finishReload func()
	if m.monitorMgr != nil {
		m.monitorMgr.SetProbeConcurrency(newCfg.ProbeConcurrencyOrDefault())
		m.monitorMgr.SetProbeTarget(newCfg.Management.ProbeTarget, newCfg.SkipCertVerify)
	}
	if sameProbeSettings {
		// Keep active bans/cooldowns for surviving node identities across reload.
		pool.RetainSharedStateForKeys(nodeIdentitySet(newCfg.Nodes))
		if m.monitorMgr != nil {
			finishReload = m.monitorMgr.BeginNodeReload()
			defer finishReload()
		}
	} else {
		pool.ResetSharedStateStore()
		if m.monitorMgr != nil {
			m.monitorMgr.ClearNodes()
		}
	}

	// Create and start new box instance.
	//
	// A bind conflict on start is almost always transient: the old box's
	// listeners (the hybrid listener on 2323 and every per-node port on 24000+)
	// were just closed and the OS may not yet have released them. On "address
	// already in use" we use progressive backoff and retry the SAME ports,
	// keeping every preserved port stable across the refresh. Reassigning a
	// node to a fresh port is a last-resort escape hatch (only once we've waited
	// through several attempts): moving a port silently breaks clients pointed
	// at the old one and is exactly the failure this guards against.
	var instance managedBox
	started := false
	var lastStartErr error
	maxRetries := 10
	for retry := 0; retry < maxRetries; retry++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		if !useFactory && hasPreparedOpts {
			instance, err = m.createBoxFromOptions(ctx, preparedOpts)
		} else {
			instance, err = m.createInstance(ctx, newCfg)
		}
		if err != nil {
			if finishReload != nil {
				finishReload()
			}
			restoreProbeSettings()
			m.rollbackToOldConfig(ctx, oldCfg)
			return fmt.Errorf("create new box: %w", err)
		}
		if err = instance.Start(); err == nil {
			started = true
			break // Success
		}
		_ = instance.Close()
		lastStartErr = err

		conflictPort := extractPortFromBindError(err)
		if conflictPort == 0 {
			// Not a port conflict: unrecoverable by retrying. Roll back now.
			if finishReload != nil {
				finishReload()
			}
			restoreProbeSettings()
			m.rollbackToOldConfig(ctx, oldCfg)
			return fmt.Errorf("start new box: %w", err)
		}

		// Give the OS progressive time to release the just-closed listener,
		// then retry the same port assignment.
		backoff := min(300*time.Millisecond, 50*time.Millisecond*time.Duration(retry+1))
		m.logger.Warnf("port %d still in use on start attempt %d/%d, waiting %s and retrying...", conflictPort, retry+1, maxRetries, backoff)
		if err := waitForContext(ctx, backoff); err != nil {
			return err
		}

		// Only after we've waited through the first half of our attempts do we
		// treat the conflict as persistent (some other process owns the port)
		// and reassign the offending node. The listener port cannot be
		// reassigned this way; if it is the conflict we simply keep waiting.
		if retry >= maxRetries/2 {
			if reassignConflictingPort(newCfg, conflictPort) {
				m.logger.Warnf("port %d persistently in use; reassigned the affected node to a fresh port", conflictPort)
				if sameProbeSettings {
					pool.RetainSharedStateForKeys(nodeIdentitySet(newCfg.Nodes))
				} else {
					pool.ResetSharedStateStore()
				}
				hasPreparedOpts = false
			}
		}
	}

	if !started {
		// Never commit a closed / non-running instance as the current box: doing
		// so silently kills every port (2323 and all 24000+) with no error. Fall
		// back to the previous configuration instead.
		m.logger.Errorf("new box failed to start after %d attempts: %v", maxRetries, lastStartErr)
		if finishReload != nil {
			finishReload()
		}
		restoreProbeSettings()
		m.rollbackToOldConfig(ctx, oldCfg)
		return fmt.Errorf("start new box: exhausted %d attempts: %w", maxRetries, lastStartErr)
	}

	if err := ctx.Err(); err != nil {
		_ = instance.Close()
		return err
	}
	m.mu.Lock()
	m.applyConfigSettings(newCfg)
	m.currentBox = instance
	m.cfg = newCfg
	m.mu.Unlock()

	// Sync config to monitor server so future WebUI settings changes target the current config pointer
	if m.monitorServer != nil {
		m.monitorServer.SetConfig(m.cfg)
	}

	// Probe only newly added/unchecked nodes when probe settings stayed unchanged;
	// otherwise sweep everything immediately.
	if m.monitorMgr != nil {
		if sameProbeSettings {
			go m.monitorMgr.ProbeUncheckedNow(periodicHealthTimeout)
		} else {
			go m.monitorMgr.ProbeAllNow(periodicHealthTimeout)
		}
	}

	m.logger.Infof("reload completed successfully with %d nodes", len(newCfg.Nodes))

	// Restart GeoIP router with new pools
	if newCfg.GeoIP.Enabled {
		m.startGeoIPRouter(ctx, newCfg)
	} else {
		m.mu.Lock()
		oldRouter := m.geoRouter
		m.geoRouter = nil
		m.mu.Unlock()
		if oldRouter != nil {
			_ = oldRouter.Stop()
		}
	}

	return nil
}

// rollbackToOldConfig attempts to restart with the previous configuration.
func (m *Manager) rollbackToOldConfig(ctx context.Context, oldCfg *config.Config) {
	if oldCfg == nil || ctx.Err() != nil {
		return
	}
	m.logger.Warnf("attempting rollback to previous config...")
	pool.ResetSharedStateStore()
	if m.monitorMgr != nil {
		m.monitorMgr.ClearNodes()
	}

	// The rollback binds the same ports the failed start attempted, which may
	// still be draining. Retry with backoff so a transient bind conflict does
	// not leave the manager with no running box at all.
	var instance managedBox
	const rollbackAttempts = 5
	for attempt := 0; attempt < rollbackAttempts; attempt++ {
		if ctx.Err() != nil {
			return
		}
		var err error
		instance, err = m.createInstance(ctx, oldCfg)
		if err != nil {
			m.logger.Errorf("rollback failed to create box: %v", err)
			return
		}
		if err = instance.Start(); err == nil {
			break
		}
		_ = instance.Close()
		instance = nil
		m.logger.Warnf("rollback start attempt %d/%d failed: %v", attempt+1, rollbackAttempts, err)
		if waitForContext(ctx, 300*time.Millisecond) != nil {
			return
		}
	}
	if instance != nil && ctx.Err() != nil {
		_ = instance.Close()
		return
	}
	if instance == nil {
		m.logger.Errorf("rollback failed to start box after %d attempts", rollbackAttempts)
		return
	}
	m.mu.Lock()
	m.currentBox = instance
	m.cfg = oldCfg
	m.mu.Unlock()
	// Sync config pointer to monitor server after rollback
	if m.monitorServer != nil {
		m.monitorServer.SetConfig(m.cfg)
	}
	if oldCfg.GeoIP.Enabled {
		m.startGeoIPRouter(ctx, oldCfg)
	}
	if m.monitorMgr != nil {
		go m.monitorMgr.ProbeAllNow(periodicHealthTimeout)
	}
	m.logger.Infof("rollback successful")
}

// Close terminates the active instance and auxiliary components.
func (m *Manager) Close() error {
	// Cancel before waiting for the lifecycle lock: a reload/startup waiting
	// for ports or health checks must not delay shutdown or revive the service.
	m.mu.Lock()
	m.closed = true
	cancel := m.baseCancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	return m.closeComponents()
}

// closeComponents runs with lifecycleMu held, but not mu during shutdown.
func (m *Manager) closeComponents() error {
	m.mu.Lock()
	instance, server, manager, router := m.currentBox, m.monitorServer, m.monitorMgr, m.geoRouter
	m.currentBox, m.monitorServer, m.monitorMgr, m.geoRouter = nil, nil, nil, nil
	m.healthCheckStarted = false
	m.baseCtx = nil
	cancel := m.baseCancel
	m.baseCancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	// Do not hold the manager lock while HTTP shutdown waits for handlers:
	// active settings/node requests may themselves be waiting for that lock.
	var err error
	if manager != nil {
		manager.Stop()
	}
	if instance != nil {
		err = instance.Close()
	}
	if server != nil {
		server.Shutdown(context.Background())
	}
	if router != nil {
		router.Stop()
	}
	if m.routingStore != nil {
		m.routingStore.Clear()
	}
	return err
}

// LockSettings synchronizes management writes with node CRUD and configuration
// snapshots. The management server always takes this lock before its own
// config lock, matching the manager -> monitor lock order used on reload.
func (m *Manager) LockSettings() func() {
	m.lifecycleMu.Lock()
	m.mu.Lock()
	return func() {
		m.mu.Unlock()
		m.lifecycleMu.Unlock()
	}
}

// MonitorManager returns the shared monitor manager.
func (m *Manager) MonitorManager() *monitor.Manager {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.monitorMgr
}

// MonitorServer returns the monitor HTTP server.
func (m *Manager) MonitorServer() *monitor.Server {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.monitorServer
}

// startGeoIPRouter starts the GeoIP region-routing HTTP proxy server.
func (m *Manager) startGeoIPRouter(ctx context.Context, cfg *config.Config) {
	// Stop existing router if any
	m.mu.Lock()
	oldRouter := m.geoRouter
	m.geoRouter = nil
	m.mu.Unlock()
	if oldRouter != nil {
		_ = oldRouter.Stop()
	}

	geoipPort := cfg.GeoIP.Port
	if geoipPort == 0 {
		geoipPort = 1221 // Default GeoIP router port
	}
	// Avoid conflict with the pool listener port
	if geoipPort == cfg.Listener.Port {
		geoipPort = 1221
		if geoipPort == cfg.Listener.Port {
			geoipPort = cfg.Listener.Port + 1
		}
		log.Printf("⚠️  GeoIP port conflicts with listener port %d, using %d instead", cfg.Listener.Port, geoipPort)
	}
	geoipListen := cfg.GeoIP.Listen
	if geoipListen == "" {
		geoipListen = cfg.Listener.Address
	}

	routerCfg := geoip.RouterConfig{
		Listen:   geoipListen,
		Port:     geoipPort,
		Username: cfg.Listener.Username,
		Password: cfg.Listener.Password,
	}

	router := geoip.NewRouter(routerCfg, nil)

	// Register region pool dialers
	for _, region := range geoip.AllRegions() {
		poolTag := fmt.Sprintf("pool-%s", region)
		if dialer, ok := pool.GetDialer(poolTag); ok {
			router.SetPool(region, dialer)
			log.Printf("   GeoIP: registered pool %s for region /%s", poolTag, region)
		}
	}

	// Register global pool dialer (for requests without region path)
	if dialer, ok := pool.GetDialer(pool.Tag); ok {
		router.SetGlobalPool(dialer)
	}

	if err := router.Start(ctx); err != nil {
		m.logger.Warnf("failed to start GeoIP router: %v", err)
		return
	}

	m.mu.Lock()
	m.geoRouter = router
	m.mu.Unlock()
}

// newBoxRecover wraps box.New and converts panics into errors. Some malformed
// subscription nodes make the sing-box library panic during outbound
// initialization (e.g. stringifying an unexpected *string while formatting its
// own error) instead of returning an error. Without this guard such a node
// crashes the whole process and the service never starts.
func newBoxRecover(opts box.Options) (instance *box.Box, err error) {
	defer func() {
		if r := recover(); r != nil {
			instance = nil
			err = fmt.Errorf("sing-box panicked during initialization: %v", r)
		}
	}()
	return box.New(opts)
}

// prepareSingBoxOptions builds sing-box options and pre-validates proxy
// outbounds in chunks before any running instance is stopped.
func (m *Manager) prepareSingBoxOptions(ctx context.Context, cfg *config.Config) (option.Options, error) {
	if cfg == nil {
		return option.Options{}, errors.New("config is nil")
	}
	opts, err := builder.Build(cfg)
	if err != nil {
		return option.Options{}, fmt.Errorf("build sing-box options: %w", err)
	}
	return prevalidateOptions(ctx, opts)
}

func newPrevalidateBoxContext(ctx context.Context) context.Context {
	inboundRegistry := include.InboundRegistry()
	outboundRegistry := include.OutboundRegistry()
	endpointRegistry := include.EndpointRegistry()
	dnsRegistry := include.DNSTransportRegistry()
	serviceRegistry := include.ServiceRegistry()
	return box.Context(ctx, inboundRegistry, outboundRegistry, endpointRegistry, dnsRegistry, serviceRegistry)
}

func isPrevalidateProxyOutbound(ob option.Outbound) bool {
	switch ob.Type {
	case pool.Type, C.TypeDirect, C.TypeBlock, C.TypeDNS, C.TypeSelector, C.TypeURLTest:
		return false
	default:
		return true
	}
}

// prevalidateOptions validates base proxy outbounds in side-effect-free chunks
// (no listeners, pools, monitor, or ClashAPI) and strips any invalid ones in O(N).
func prevalidateOptions(ctx context.Context, opts option.Options) (option.Options, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	proxyOutbounds := make([]option.Outbound, 0, len(opts.Outbounds))
	for _, ob := range opts.Outbounds {
		if isPrevalidateProxyOutbound(ob) {
			proxyOutbounds = append(proxyOutbounds, ob)
		}
	}
	if len(proxyOutbounds) == 0 {
		return opts, nil
	}

	validateChunk := func(chunk []option.Outbound) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		boxCtx := newPrevalidateBoxContext(ctx)
		instance, err := newBoxRecover(box.Options{
			Context: boxCtx,
			Options: option.Options{
				Log:       &option.LogOptions{Disabled: true},
				Outbounds: chunk,
			},
		})
		if err == nil && instance != nil {
			_ = instance.Close()
		}
		return err
	}

	var badTags map[string]struct{}
	var isolateBad func([]option.Outbound) error
	isolateBad = func(slice []option.Outbound) error {
		if len(slice) == 0 {
			return nil
		}
		err := validateChunk(slice)
		if err == nil {
			return nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if len(slice) == 1 {
			tag := slice[0].Tag
			log.Printf("⚠️  Outbound '%s' failed sing-box validation: %v (removing)", tag, err)
			if badTags == nil {
				badTags = make(map[string]struct{})
			}
			badTags[tag] = struct{}{}
			return nil
		}
		mid := len(slice) / 2
		if err := isolateBad(slice[:mid]); err != nil {
			return err
		}
		return isolateBad(slice[mid:])
	}

	const validationChunkSize = 64
	for start := 0; start < len(proxyOutbounds); start += validationChunkSize {
		end := min(start+validationChunkSize, len(proxyOutbounds))
		if err := isolateBad(proxyOutbounds[start:end]); err != nil {
			return option.Options{}, err
		}
	}

	if len(badTags) == 0 {
		return opts, nil
	}
	if len(badTags) >= len(proxyOutbounds) {
		return option.Options{}, fmt.Errorf("create sing-box instance: all %d proxy outbounds failed validation", len(proxyOutbounds))
	}

	pruned, err := pruneOutboundsAndRoutes(opts, badTags)
	if err != nil {
		return option.Options{}, err
	}
	log.Printf("✅ Pre-validated outbounds: removed %d invalid outbound(s)", len(badTags))
	return pruned, nil
}

func pruneOutboundsAndRoutes(opts option.Options, badTags map[string]struct{}) (option.Options, error) {
	if len(badTags) == 0 {
		return opts, nil
	}
	removedSet := make(map[string]struct{}, len(badTags))
	for tag := range badTags {
		removedSet[tag] = struct{}{}
	}

	newOutbounds := make([]option.Outbound, 0, len(opts.Outbounds))
	for _, ob := range opts.Outbounds {
		if _, isBad := badTags[ob.Tag]; isBad {
			continue
		}
		if ob.Type == pool.Type {
			if poolOpts, ok := ob.Options.(*pool.Options); ok {
				filteredMembers := make([]string, 0, len(poolOpts.Members))
				for _, m := range poolOpts.Members {
					if _, isBad := badTags[m]; !isBad {
						filteredMembers = append(filteredMembers, m)
					}
				}
				poolOpts.Members = filteredMembers
				for badTag := range badTags {
					delete(poolOpts.Metadata, badTag)
				}
				if len(poolOpts.Members) == 0 {
					log.Printf("⚠️  Removing empty pool '%s'", ob.Tag)
					removedSet[ob.Tag] = struct{}{}
					continue
				}
			}
		}
		newOutbounds = append(newOutbounds, ob)
	}
	if len(newOutbounds) == 0 {
		return option.Options{}, errors.New("create sing-box instance: no valid outbounds remain")
	}
	opts.Outbounds = newOutbounds

	if opts.Route != nil {
		if _, removedFinal := removedSet[opts.Route.Final]; removedFinal {
			return option.Options{}, fmt.Errorf("create sing-box instance: final outbound %q has no valid members", opts.Route.Final)
		}
		newRules := make([]option.Rule, 0, len(opts.Route.Rules))
		for _, r := range opts.Route.Rules {
			if r.Type == C.RuleTypeDefault {
				outboundTarget := r.DefaultOptions.RuleAction.RouteOptions.Outbound
				if _, removed := removedSet[outboundTarget]; removed {
					continue
				}
			}
			newRules = append(newRules, r)
		}
		opts.Route.Rules = newRules
	}
	return opts, nil
}

// createBoxFromOptions instantiates a sing-box Box from pre-validated options.
func (m *Manager) createBoxFromOptions(ctx context.Context, opts option.Options) (*box.Box, error) {
	if m.monitorMgr == nil {
		return nil, errors.New("monitor manager not initialized")
	}

	maxRetries := len(opts.Outbounds) + 50
	outboundErrRe := regexp.MustCompile(`initialize outbound\[(\d+)\]`)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		inboundRegistry := include.InboundRegistry()
		session.Register(inboundRegistry)
		outboundRegistry := include.OutboundRegistry()
		pool.Register(outboundRegistry)
		endpointRegistry := include.EndpointRegistry()
		dnsRegistry := include.DNSTransportRegistry()
		serviceRegistry := include.ServiceRegistry()

		boxCtx := box.Context(ctx, inboundRegistry, outboundRegistry, endpointRegistry, dnsRegistry, serviceRegistry)
		boxCtx = monitor.ContextWith(boxCtx, m.monitorMgr)
		boxCtx = routing.WithStore(boxCtx, m.routingStore)

		instance, err := newBoxRecover(box.Options{Context: boxCtx, Options: opts})
		if err == nil {
			if attempt > 0 {
				log.Printf("✅ sing-box instance created after removing %d invalid outbound(s)", attempt)
			}
			return instance, nil
		}

		matches := outboundErrRe.FindStringSubmatch(err.Error())
		if matches == nil {
			return nil, fmt.Errorf("create sing-box instance: %w", err)
		}

		idx, convErr := strconv.Atoi(matches[1])
		if convErr != nil || idx < 0 || idx >= len(opts.Outbounds) {
			return nil, fmt.Errorf("create sing-box instance: %w", err)
		}

		badTag := opts.Outbounds[idx].Tag
		log.Printf("⚠️  Outbound '%s' failed sing-box validation: %v (removing and retrying)", badTag, err)

		opts, err = pruneOutboundsAndRoutes(opts, map[string]struct{}{badTag: {}})
		if err != nil {
			return nil, err
		}
	}

	return nil, fmt.Errorf("create sing-box instance: too many invalid outbounds (exceeded %d retries)", maxRetries)
}

// createBox builds and instantiates a sing-box instance from config.
func (m *Manager) createBox(ctx context.Context, cfg *config.Config) (*box.Box, error) {
	if m.monitorMgr == nil {
		return nil, errors.New("monitor manager not initialized")
	}
	opts, err := m.prepareSingBoxOptions(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return m.createBoxFromOptions(ctx, opts)
}

func nodeIdentitySet(nodes []config.NodeConfig) map[string]struct{} {
	keep := make(map[string]struct{}, len(nodes))
	for i := range nodes {
		sum := sha256.Sum256([]byte(nodes[i].NodeKey()))
		keep[fmt.Sprintf("%x", sum)] = struct{}{}
	}
	return keep
}

// waitForHealthCheck polls until enough nodes are available or timeout.
func (m *Manager) waitForHealthCheck(ctx context.Context, timeout time.Duration) error {
	m.mu.RLock()
	manager, minimum := m.monitorMgr, m.minAvailableNodes
	m.mu.RUnlock()
	if manager == nil || minimum <= 0 {
		return nil
	}
	if timeout <= 0 {
		timeout = defaultHealthCheckTimeout
	}

	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(healthCheckPollInterval)
	defer ticker.Stop()

	for {
		available, total := m.availableNodeCount()
		if available >= minimum {
			m.logger.Infof("health check passed: %d/%d nodes available", available, total)
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout: %d/%d nodes available (need >= %d)", available, total, minimum)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// availableNodeCount returns (available, total) node counts.
func (m *Manager) availableNodeCount() (int, int) {
	m.mu.RLock()
	manager := m.monitorMgr
	m.mu.RUnlock()
	if manager == nil {
		return 0, 0
	}
	snapshots := manager.Snapshot()
	total := len(snapshots)
	available := 0
	for _, snap := range snapshots {
		if snap.InitialCheckDone && snap.Available {
			available++
		}
	}
	return available, total
}

// ensureMonitor initializes monitor manager and server if needed.
func (m *Manager) ensureMonitor(ctx context.Context) error {
	m.mu.Lock()
	if m.monitorMgr != nil {
		m.mu.Unlock()
		return nil
	}

	monitorMgr, err := monitor.NewManager(m.monitorCfg)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("init monitor manager: %w", err)
	}
	monitorMgr.SetLogger(monitorLoggerAdapter{logger: m.logger})
	if m.cfg != nil {
		monitorMgr.Metadata.Configure(m.cfg.IPMetadata)
	}
	m.monitorMgr = monitorMgr

	var serverToStart *monitor.Server
	if m.monitorCfg.Enabled {
		if m.monitorServer == nil {
			serverToStart = monitor.NewServer(m.monitorCfg, monitorMgr, log.Default())
			m.monitorServer = serverToStart
		}
		// Set config early so WebUI has data before Start() completes
		if m.monitorServer != nil && m.cfg != nil {
			m.monitorServer.SetConfig(m.cfg)
		}
		// Set NodeManager for config CRUD endpoints
		if m.monitorServer != nil {
			m.monitorServer.SetNodeManager(m)
			m.monitorServer.SetRoutingStore(m.routingStore)
			m.monitorServer.SetOutboundConverter(builder.SubscriptionOutbound)
		}
		// Note: StartPeriodicHealthCheck is called after nodes are registered in Start()
	}
	m.mu.Unlock()

	if serverToStart != nil {
		serverToStart.Start(ctx)
	}
	return nil
}

// applyConfigSettings extracts runtime settings from config.
func (m *Manager) applyConfigSettings(cfg *config.Config) {
	if cfg == nil {
		return
	}
	if m.routingStore != nil {
		m.routingStore.Configure(cfg.Sticky.MaxSessionsOrDefault(), cfg.Sticky.SessionTTLOrDefault())
	}
	if cfg.SubscriptionRefresh.DrainTimeout > 0 {
		m.drainTimeout = cfg.SubscriptionRefresh.DrainTimeout
	} else if m.drainTimeout == 0 {
		m.drainTimeout = defaultDrainTimeout
	}
	m.minAvailableNodes = cfg.SubscriptionRefresh.MinAvailableNodes
}

// defaultLogger is the fallback logger using standard log.
type defaultLogger struct{}

func (defaultLogger) Infof(format string, args ...any) {
	log.Printf("[boxmgr] "+format, args...)
}

func (defaultLogger) Warnf(format string, args ...any) {
	log.Printf("[boxmgr] WARN: "+format, args...)
}

func (defaultLogger) Errorf(format string, args ...any) {
	log.Printf("[boxmgr] ERROR: "+format, args...)
}

// monitorLoggerAdapter adapts Logger to monitor.Logger interface.
type monitorLoggerAdapter struct {
	logger Logger
}

func (a monitorLoggerAdapter) Info(args ...any) {
	if a.logger != nil {
		a.logger.Infof("%s", fmt.Sprint(args...))
	}
}

func (a monitorLoggerAdapter) Warn(args ...any) {
	if a.logger != nil {
		a.logger.Warnf("%s", fmt.Sprint(args...))
	}
}

// --- NodeManager interface implementation ---

var errConfigUnavailable = errors.New("config is not initialized")

// ListConfigNodes returns a copy of all configured nodes.
func (m *Manager) ListConfigNodes(ctx context.Context) ([]config.NodeConfig, error) {
	_ = ctx
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.cfg == nil {
		return nil, errConfigUnavailable
	}
	return cloneNodes(m.cfg.Nodes), nil
}

// CreateNode adds a new node to the config and saves it.
func (m *Manager) CreateNode(ctx context.Context, node config.NodeConfig) (config.NodeConfig, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return config.NodeConfig{}, err
		}
	}

	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg == nil {
		return config.NodeConfig{}, errConfigUnavailable
	}

	normalized, err := m.prepareNodeLocked(node, "")
	if err != nil {
		return config.NodeConfig{}, err
	}

	// A node added through the WebUI is an explicit user configuration, so it is
	// always persisted as an inline node in config.yaml — regardless of whether
	// subscriptions are configured. Classifying it as a subscription/file source
	// would route it to nodes.txt, which the next subscription refresh overwrites
	// (createNewConfig preserves only inline nodes), silently losing the node.
	normalized.Source = config.NodeSourceInline

	m.cfg.Nodes = append(m.cfg.Nodes, normalized)
	if err := m.cfg.Save(); err != nil {
		m.cfg.Nodes = m.cfg.Nodes[:len(m.cfg.Nodes)-1]
		return config.NodeConfig{}, fmt.Errorf("save config: %w", err)
	}
	return normalized, nil
}

// UpdateNode updates an existing node by name and saves the config.
func (m *Manager) UpdateNode(ctx context.Context, name string, node config.NodeConfig) (config.NodeConfig, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return config.NodeConfig{}, err
		}
	}

	name = strings.TrimSpace(name)
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg == nil {
		return config.NodeConfig{}, errConfigUnavailable
	}

	idx := m.nodeIndexLocked(name)
	if idx == -1 {
		return config.NodeConfig{}, monitor.ErrNodeNotFound
	}

	normalized, err := m.prepareNodeLocked(node, name)
	if err != nil {
		return config.NodeConfig{}, err
	}

	// Preserve the original source
	normalized.Source = m.cfg.Nodes[idx].Source

	prev := m.cfg.Nodes[idx]
	m.cfg.Nodes[idx] = normalized
	if err := m.cfg.Save(); err != nil {
		m.cfg.Nodes[idx] = prev
		return config.NodeConfig{}, fmt.Errorf("save config: %w", err)
	}
	return normalized, nil
}

// DeleteNode removes a node by name and saves the config.
func (m *Manager) DeleteNode(ctx context.Context, name string) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	name = strings.TrimSpace(name)
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg == nil {
		return errConfigUnavailable
	}

	idx := m.nodeIndexLocked(name)
	if idx == -1 {
		return monitor.ErrNodeNotFound
	}

	backup := cloneNodes(m.cfg.Nodes)
	m.cfg.Nodes = append(m.cfg.Nodes[:idx], m.cfg.Nodes[idx+1:]...)
	if err := m.cfg.Save(); err != nil {
		m.cfg.Nodes = backup
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}

// TriggerReload reloads the sing-box instance with current config.
func (m *Manager) TriggerReload(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.RLock()
	cfgCopy := m.copyConfigLocked()
	var portMap map[string]uint16
	if m.cfg != nil {
		portMap = m.cfg.BuildPortMap()
	}
	m.mu.RUnlock()

	if cfgCopy == nil {
		return errConfigUnavailable
	}
	return m.reloadWithPortMapLocked(cfgCopy, portMap)
}

// ReloadWithPortMap gracefully switches to a new configuration, preserving port assignments.
func (m *Manager) ReloadWithPortMap(newCfg *config.Config, portMap map[string]uint16) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	return m.reloadWithPortMapLocked(newCfg, portMap)
}

func (m *Manager) reloadWithPortMapLocked(newCfg *config.Config, portMap map[string]uint16) error {
	if newCfg == nil {
		return errors.New("new config is nil")
	}

	// Apply port mapping and assign ports. NormalizeWithPortMap preserves the
	// port of any node present in portMap and assigns fresh, collision-free
	// ports to the rest. It is always run (an empty map simply means "assign
	// all ports fresh"), since createNewConfig no longer pre-assigns them.
	if err := newCfg.NormalizeWithPortMap(portMap); err != nil {
		return fmt.Errorf("normalize config with port map: %w", err)
	}

	if err := m.reloadLocked(newCfg); err != nil {
		return err
	}

	// Persist the (possibly updated) assignments so a restart keeps the same
	// port per node. Best-effort: a write failure does not affect the running
	// proxy, only the next restart's ability to restore ports.
	if err := newCfg.SaveNodePortMap(); err != nil {
		m.logger.Warnf("failed to persist node ports: %v", err)
	}
	return nil
}

// ReloadWithCurrentConfig applies a transformation to the latest configuration
// as one lifecycle transaction. Management writes and node CRUD cannot be lost
// between the snapshot and the reload. Callbacks must not call manager methods.
// persist owns its disk transaction; failure restores the previous runtime.
func (m *Manager) ReloadWithCurrentConfig(update func(*config.Config) error, persist func(*config.Config) error) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	m.mu.RLock()
	oldCfg := m.copyConfigLocked()
	closed, running := m.closed, m.currentBox != nil
	m.mu.RUnlock()
	if closed {
		return errors.New("box manager closed")
	}
	if oldCfg == nil {
		return errConfigUnavailable
	}
	if !running {
		return errors.New("manager not started")
	}
	// A second independent snapshot keeps the rollback configuration pristine.
	m.mu.RLock()
	candidate := m.copyConfigLocked()
	m.mu.RUnlock()
	if update != nil {
		if err := update(candidate); err != nil {
			return err
		}
	}
	if err := candidate.NormalizeWithPortMap(oldCfg.BuildPortMap()); err != nil {
		return fmt.Errorf("normalize updated config: %w", err)
	}
	if err := m.reloadLocked(candidate); err != nil {
		return err
	}
	if persist != nil {
		if err := persist(candidate); err != nil {
			if rollbackErr := m.reloadLocked(oldCfg); rollbackErr != nil {
				return fmt.Errorf("persist updated config: %w; runtime rollback failed: %v", err, rollbackErr)
			}
			return fmt.Errorf("persist updated config: %w; runtime rolled back", err)
		}
	}
	if err := candidate.SaveNodePortMap(); err != nil {
		m.logger.Warnf("failed to persist node ports: %v", err)
	}
	return nil
}

// CurrentConfig returns an independent snapshot of the latest configuration.
// Background refreshes must base their updates on this snapshot, not the
// startup pointer which becomes stale after a management reload.
func (m *Manager) CurrentConfig() *config.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.copyConfigLocked()
}

// CurrentSubscriptionConfig returns only worker-owned settings and file paths.
// Status polling and timer reconciliation must not clone thousands of nodes.
// Like CurrentConfig, this uses only mu, never the lifecycle lock.
func (m *Manager) CurrentSubscriptionConfig() *config.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cfg == nil {
		return nil
	}
	snapshot := &config.Config{
		NodesFile:           m.cfg.NodesFile,
		Subscriptions:       append([]string(nil), m.cfg.Subscriptions...),
		SubscriptionRefresh: m.cfg.SubscriptionRefresh,
	}
	if m.cfg.SubscriptionRefresh.PreScreenEnabled != nil {
		value := *m.cfg.SubscriptionRefresh.PreScreenEnabled
		snapshot.SubscriptionRefresh.PreScreenEnabled = &value
	}
	snapshot.SetFilePath(m.cfg.FilePath())
	return snapshot
}

// CurrentPortMap returns the current port mapping from the active configuration.
func (m *Manager) CurrentPortMap() map[string]uint16 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.cfg == nil {
		return nil
	}
	return m.cfg.BuildPortMap()
}

// --- Helper functions ---

// portBindErrorRegex matches "listen tcp4 0.0.0.0:24282: bind: address already in use"
var portBindErrorRegex = regexp.MustCompile(`listen tcp[46]? (?:\[[^\]]*\]|[^:]+):(\d+): bind: address already in use`)

// extractPortFromBindError extracts the port number from a bind error message.
func extractPortFromBindError(err error) uint16 {
	if err == nil {
		return 0
	}
	matches := portBindErrorRegex.FindStringSubmatch(err.Error())
	if len(matches) < 2 {
		return 0
	}
	var port int
	fmt.Sscanf(matches[1], "%d", &port)
	if port > 0 && port <= 65535 {
		return uint16(port)
	}
	return 0
}

// reassignConflictingPort finds the node using the conflicting port and assigns a new port.
func reassignConflictingPort(cfg *config.Config, conflictPort uint16) bool {
	// Build set of used ports
	usedPorts := make(map[uint16]bool)
	if cfg.Mode == "hybrid" {
		usedPorts[cfg.Listener.Port] = true
	}
	if cfg.Sticky.Enabled {
		port := cfg.Sticky.Port
		if port == 0 && cfg.Listener.Port < 65535 {
			port = cfg.Listener.Port + 1
		}
		usedPorts[port] = true
	}
	if cfg.GeoIP.Enabled {
		port := cfg.GeoIP.Port
		if port == 0 {
			port = 1221
		}
		if port == cfg.Listener.Port {
			port = 1221
			if port == cfg.Listener.Port {
				port = cfg.Listener.Port + 1
			}
		}
		usedPorts[port] = true
	}
	for _, node := range cfg.Nodes {
		usedPorts[node.Port] = true
	}

	// Find and reassign the conflicting node
	for idx := range cfg.Nodes {
		if cfg.Nodes[idx].Port == conflictPort {
			// Find next available port
			newPort := int(conflictPort) + 1
			address := cfg.MultiPort.Address
			if address == "" {
				address = "0.0.0.0"
			}
			for newPort <= 65535 && (usedPorts[uint16(newPort)] || !config.IsPortAvailable(address, uint16(newPort))) {
				newPort++
			}
			if newPort > 65535 {
				log.Printf("❌ No available port found for node %q", cfg.Nodes[idx].Name)
				return false
			}
			log.Printf("⚠️  Port %d in use, reassigning node %q to port %d", conflictPort, cfg.Nodes[idx].Name, newPort)
			cfg.Nodes[idx].Port = uint16(newPort)
			return true
		}
	}
	return false
}

func cloneNodes(nodes []config.NodeConfig) []config.NodeConfig {
	if len(nodes) == 0 {
		return []config.NodeConfig{} // Return empty slice, not nil, for proper JSON serialization
	}
	out := make([]config.NodeConfig, len(nodes))
	copy(out, nodes)
	return out
}

func (m *Manager) copyConfigLocked() *config.Config {
	if m.cfg == nil {
		return nil
	}
	cloned := *m.cfg
	cloned.Nodes = cloneNodes(m.cfg.Nodes)
	if m.cfg.Management.Enabled != nil {
		value := *m.cfg.Management.Enabled
		cloned.Management.Enabled = &value
	}
	if m.cfg.Pool.RetryEnabled != nil {
		value := *m.cfg.Pool.RetryEnabled
		cloned.Pool.RetryEnabled = &value
	}
	if m.cfg.Pool.BlacklistFailedPin != nil {
		value := *m.cfg.Pool.BlacklistFailedPin
		cloned.Pool.BlacklistFailedPin = &value
	}
	if m.cfg.Sticky.SessionEnabled != nil {
		value := *m.cfg.Sticky.SessionEnabled
		cloned.Sticky.SessionEnabled = &value
	}
	if m.cfg.SubscriptionRefresh.PreScreenEnabled != nil {
		value := *m.cfg.SubscriptionRefresh.PreScreenEnabled
		cloned.SubscriptionRefresh.PreScreenEnabled = &value
	}
	if len(m.cfg.DNS.FallbackServers) > 0 {
		cloned.DNS.FallbackServers = make([]string, len(m.cfg.DNS.FallbackServers))
		copy(cloned.DNS.FallbackServers, m.cfg.DNS.FallbackServers)
	}
	// Clone Subscriptions slice to avoid shared backing array issues
	if len(m.cfg.Subscriptions) > 0 {
		cloned.Subscriptions = make([]string, len(m.cfg.Subscriptions))
		copy(cloned.Subscriptions, m.cfg.Subscriptions)
	}
	cloned.SetFilePath(m.cfg.FilePath())
	return &cloned
}

func (m *Manager) nodeIndexLocked(name string) int {
	for idx, node := range m.cfg.Nodes {
		if node.Name == name {
			return idx
		}
	}
	return -1
}

func (m *Manager) portInUseLocked(port uint16, currentName string) bool {
	if port == 0 {
		return false
	}
	for _, node := range m.cfg.Nodes {
		if node.Name == currentName {
			continue
		}
		if node.Port == port {
			return true
		}
	}
	return false
}

func (m *Manager) nextAvailablePortLocked() uint16 {
	base := m.cfg.MultiPort.BasePort
	if base == 0 {
		base = 24000
	}
	used := make(map[uint16]struct{}, len(m.cfg.Nodes))
	for _, node := range m.cfg.Nodes {
		if node.Port > 0 {
			used[node.Port] = struct{}{}
		}
	}
	port := base
	for i := 0; i < 1<<16; i++ {
		if _, ok := used[port]; !ok && port != 0 {
			return port
		}
		port++
		if port == 0 {
			port = 1
		}
	}
	return base
}

func (m *Manager) prepareNodeLocked(node config.NodeConfig, currentName string) (config.NodeConfig, error) {
	node.Name = strings.TrimSpace(node.Name)
	node.URI = strings.TrimSpace(node.URI)

	if node.URI == "" {
		return config.NodeConfig{}, fmt.Errorf("%w: URI 不能为空", monitor.ErrInvalidNode)
	}

	// Extract name from URI if not provided
	if node.Name == "" {
		if currentName != "" {
			node.Name = currentName
		} else {
			node.Name = config.ExtractNodeName(node.URI)
		}
		// Fallback to auto-generated name
		if node.Name == "" {
			node.Name = fmt.Sprintf("node-%d", len(m.cfg.Nodes)+1)
		}
	}

	// Check for name conflict (excluding current node when updating)
	if idx := m.nodeIndexLocked(node.Name); idx != -1 {
		if currentName == "" || m.cfg.Nodes[idx].Name != currentName {
			return config.NodeConfig{}, fmt.Errorf("%w: 节点 %s 已存在", monitor.ErrNodeConflict, node.Name)
		}
	}

	// Handle multi-port mode specifics
	if m.cfg.Mode == "multi-port" {
		if node.Port == 0 {
			node.Port = m.nextAvailablePortLocked()
		} else if m.portInUseLocked(node.Port, currentName) {
			return config.NodeConfig{}, fmt.Errorf("%w: 端口 %d 已被占用", monitor.ErrNodeConflict, node.Port)
		}
		if node.Username == "" {
			node.Username = m.cfg.MultiPort.Username
			node.Password = m.cfg.MultiPort.Password
		}
	}

	return node, nil
}

// waitForContext bounds retry backoff by the runtime lifetime.
func waitForContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (m *Manager) createInstance(ctx context.Context, cfg *config.Config) (managedBox, error) {
	if m.boxFactory != nil {
		return m.boxFactory(ctx, cfg)
	}
	return m.createBox(ctx, cfg)
}
