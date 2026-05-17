package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/proxy/socks5"
)

type ShadowLinkEngine struct {
	cl        *client.Client
	stream    client.StreamTransport // WebSocketTransport or SplitTransport
	socks     *socks5.Server
	socksAddr string
	cfg       *Config
	cancel    context.CancelFunc

	// W8: error channel — signals main loop when engine dies
	errCh         chan error
	once          sync.Once
	pollWG        sync.WaitGroup   // tracks poll worker goroutines for clean shutdown
	pollTransport client.Transport // dedicated transport for polls (separate from CONNECTs)

	// Pre-warmed WS pool for per-stream CF CDN mode. Nil in other transport modes.
	// Keeps ~20 WS connections upgraded-and-idle so each SOCKS5 CONNECT can grab
	// one instantly instead of paying the ~250ms TCP+TLS+WS-upgrade cost.
	readyPool *client.WSReadyPool

	// Download stream coordination: poll pauses when download stream is active.
	downloadActive atomic.Bool
	streamCtx      context.Context // stored for deferred download stream start
}

func NewShadowLinkEngine(cfg *Config) (*ShadowLinkEngine, error) {
	return &ShadowLinkEngine{
		socksAddr: cfg.SOCKS,
		cfg:       cfg,
		errCh:     make(chan error, 1),
	}, nil
}

// ErrorCh returns channel that receives a fatal error if engine dies.
func (e *ShadowLinkEngine) ErrorCh() <-chan error { return e.errCh }

// signalError sends error to main loop (once, non-blocking).
func (e *ShadowLinkEngine) signalError(err error) {
	e.once.Do(func() {
		select {
		case e.errCh <- err:
		default:
		}
	})
}

func (e *ShadowLinkEngine) Connect(ctx context.Context) error {
	slCfg := e.cfg.ShadowLink
	if slCfg == nil {
		return fmt.Errorf("конфиг ShadowLink не задан")
	}

	pubKey, err := hex.DecodeString(slCfg.PubKey)
	if err != nil {
		return fmt.Errorf("неверный pubkey: %w", err)
	}

	// ClientID должен быть ровно 16 байт (UUID) — сервер v1 (post Phase 0/1) не принимает
	// legacy v0 handshake. Раньше тут было []byte("nixavpn-client") = 14 bytes,
	// что роняло handshake на server retire'нувшем v0. Генерируем UUIDv4 per-process;
	// сервер в open-mode (authorized_clients пуст) принимает любой UUID.
	u := uuid.New()
	clientID := u[:]

	clientCfg := client.ClientConfig{
		ServerAddr:   slCfg.Server,
		ServerPubKey: pubKey,
		ClientID:     clientID,
		UseTLS:       slCfg.TLS,
		CDNDomain:    slCfg.CDN,
		ECHEnabled:   slCfg.ECH,
	}
	// Full-direct mode: client dials to IP (slCfg.Server), TLS SNI = slCfg.SNI.
	// In this mode we do NOT go through CF — both handshake and WS are direct.
	// SNI override takes precedence over CDN: don't wrap in CDNTransport.
	if slCfg.SNI != "" {
		clientCfg.SNIOverride = slCfg.SNI
		clientCfg.CDNDomain = "" // force direct transport path
		slog.Info("ShadowLink full-direct", "dial", slCfg.Server, "sni", slCfg.SNI)
	}

	ctx2, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	// Build ordered list of endpoints: primary first, then backup_servers.
	// Each backup must share the same X25519 pubkey (different CF domain).
	// Auto-probe mode doesn't support backups (it already probes internally).
	endpoints := append([]string{slCfg.Server}, slCfg.BackupServers...)

	if slCfg.Auto {
		probeCfg := client.ProbeConfig{
			ServerAddr: slCfg.Server,
			CDNDomain:  slCfg.CDN,
			Timeout:    3 * time.Second,
		}
		e.cl, err = client.AutoConnect(ctx2, clientCfg, probeCfg)
	} else if len(endpoints) == 1 {
		// Fast path: single endpoint, no fallback — unchanged behavior.
		e.cl = client.NewClient(clientCfg)
		err = e.cl.Connect(ctx2)
	} else {
		// Multi-endpoint: try primary, then each backup in order.
		// On success, slCfg.Server is updated to the working endpoint so
		// downstream code (WS pool, escape routes) uses the same host.
		var usedServer string
		usedServer, err = tryServers(ctx2, endpoints,
			func(ctx context.Context, server string) error {
				cfg := clientCfg
				cfg.ServerAddr = server
				// CDN domain tracks host if CDN was derived from server.
				// We intentionally do not auto-rewrite CDN — caller controls
				// it: if backup points to a different CF-protected domain
				// they should include it in backup_servers "host:port" form
				// and set cdn= to the primary (since CF SNI matches the
				// primary cert for the same account). Advanced users can
				// override via YAML per-backup config in future iterations.
				cl := client.NewClient(cfg)
				if connectErr := cl.Connect(ctx); connectErr != nil {
					return connectErr
				}
				e.cl = cl
				return nil
			})
		if err == nil && usedServer != slCfg.Server {
			slog.Warn("ShadowLink primary unreachable — using backup",
				"primary", slCfg.Server, "using", usedServer)
			slCfg.Server = usedServer
		}
	}
	if err != nil {
		cancel()
		return fmt.Errorf("ошибка подключения ShadowLink: %w", err)
	}

	slog.Info("ShadowLink подключен", "transport", e.cl.TransportName())

	// Start periodic stats logger — prints counter deltas every 5s so we can
	// see at a glance how much each subsystem (cover traffic, UDP poll,
	// per-stream WS, session encrypt/decrypt) is generating right now.
	client.StartStatsLogger(ctx2, 5*time.Second)

	// System VPN or WebSocket mode: use WS Pool (preferred) or SplitHTTP (fallback).
	// If origin IP is set, WS goes directly to origin (bypasses CF CDN for speed).
	if e.cfg.SystemVPN || slCfg.WebSocket {
		// Determine WS target: origin IP (direct) or server address (through CF).
		// When origin is set: WS connects to origin:443 with SNI=CDN domain.
		// This bypasses CF CDN entirely — full speed, no 30s kill.
		wsTarget := slCfg.Server
		if slCfg.Origin != "" {
			wsTarget = slCfg.Origin + ":443"
			slog.Info("WS direct к origin IP", "origin", slCfg.Origin, "sni", slCfg.Server)
		}
		if slCfg.CFIP != "" {
			slog.Info("WS через конкретный CF edge", "cfip", slCfg.CFIP, "domain", slCfg.Server)
		}

		// Mode selection.
		//
		// History: 2026-04-14 introduced a `viaCF` branch that switched CDN
		// URLs to per-stream WS "to fix Telegram stalls". Field test on
		// 2026-04-15 showed this was a regression: browsing dropped from
		// ~300Mbps (WS Pool through CF, known working on 2026-04-13) to
		// 10-20 KB/s (per-stream). Rolled back: CDN URLs use WS Pool again.
		//
		// Opt-in per-stream WS (experimental only) via env flag:
		//   NIXAVPN_FORCE_PER_STREAM_WS=1
		// Useful if someone wants to test whether per-stream helps for
		// specific low-throughput workloads (Telegram, single HTTP requests).
		forcePerStream := os.Getenv("NIXAVPN_FORCE_PER_STREAM_WS") == "1"

		poolOK := false

		if forcePerStream {
			// Experimental: per-stream WS — each SOCKS5 CONNECT gets a dedicated WS.
			sniHost := ""
			h, _, _ := net.SplitHostPort(slCfg.Server)
			if h != "" {
				sniHost = h
			}

			disableReadyPool := os.Getenv("NIXAVPN_DISABLE_WS_POOL") == "1"
			readyPoolSize := slCfg.WSPoolSize
			if readyPoolSize < 1 {
				readyPoolSize = 6
			}

			var readyPoolForCfg *client.WSReadyPool
			if !disableReadyPool {
				e.readyPool = client.NewWSReadyPool(e.cl, client.WSReadyPoolConfig{
					Size:       readyPoolSize,
					ServerAddr: wsTarget,
					UseTLS:     slCfg.TLS,
					SkipVerify: false,
					SNIHost:    sniHost,
					CFIP:       slCfg.CFIP,
				})
				e.readyPool.Start()
				readyPoolForCfg = e.readyPool
				slog.Info("EXPERIMENTAL per-stream WS + ready pool",
					"size", readyPoolSize, "server", wsTarget)
			} else {
				slog.Info("EXPERIMENTAL per-stream WS, no pool")
			}

			e.socks = &socks5.Server{
				Client: e.cl,
				PerStreamWS: &socks5.PerStreamWSConfig{
					ServerAddr: wsTarget,
					UseTLS:     slCfg.TLS,
					SkipVerify: false,
					SNIHost:    sniHost,
					CFIP:       slCfg.CFIP,
					Pool:       readyPoolForCfg,
				},
				Router:   nil, // set below
				Addr:     e.socksAddr,
				Username: e.cfg.ProxyUser,
				Password: e.cfg.ProxyPass,
				ViaCDN:   slCfg.CDN != "" && slCfg.Origin == "" && slCfg.SNI == "",
			}
			poolOK = true
		} else {
			// Default: WS Pool (multiplexed). Works for both direct/SNI and
			// originally also CDN — but TSPU 2026 freezes per-TCP at ~15-20KB
			// which makes pooled long-lived WSs unreliable through CF.
			// viaCF now defaults to SplitHTTP (fresh TCP per POST = TSPU-immune).
			// User can force WS Pool via NIXAVPN_FORCE_WS_POOL=1 for A/B testing.
			viaCFDefault := slCfg.CDN != "" && slCfg.Origin == "" && slCfg.SNI == ""
			forceWSPool := os.Getenv("NIXAVPN_FORCE_WS_POOL") == "1"
			usePool := (slCfg.CDN != "" || slCfg.WSPool || slCfg.WebSocket || slCfg.SNI != "") &&
				(!viaCFDefault || forceWSPool)
			if viaCFDefault && !forceWSPool {
				slog.Info("viaCF: using SplitHTTP (TSPU-immune fresh-TCP-per-POST)")
			}
			poolSize := slCfg.WSPoolSize
			if poolSize < 1 {
				poolSize = 8
			}
			if usePool {
				// Decide TLS SNI for the WS dial:
				//   - SNI override: use it directly (full-direct mode)
				//   - Origin IP with CDN domain: SNI = domain from slCfg.Server
				//   - Through CF: no SNI override (dial domain, gorilla sets SNI from URL)
				sniHost := ""
				switch {
				case slCfg.SNI != "":
					sniHost = slCfg.SNI
				case slCfg.Origin != "":
					h, _, _ := net.SplitHostPort(slCfg.Server)
					if h != "" {
						sniHost = h
					} else {
						sniHost = slCfg.Server
					}
				}

				// Cap streams-per-slot for CF CDN mode. Without this, a
				// browser burst of 15+ concurrent connections piles onto a
				// single slot (stream assigned ... streams=15 pending=11 in
				// field-test 2026-04-15) → data stalls, decrypts stop
				// arriving. 4 streams/slot × 8 slots = 32 concurrent streams
				// which covers a typical page load while keeping each WS light.
				maxStreamsPerSlot := 0         // unlimited for direct
				maxPendingPerSlot := 0         // default 4 for direct
				var writeTimeout time.Duration // 0 → 30s default for direct
				var staggerDelay time.Duration // 0 → no stagger for direct
				var maxBytesPerSlot int64      // 0 = disabled (direct has no TSPU limit)
				viaCF := slCfg.CDN != "" && slCfg.Origin == "" && slCfg.SNI == ""
				if viaCF {
					maxStreamsPerSlot = 4
					maxPendingPerSlot = 2
					// 5s write deadline (vs 30s default): under CF
					// backpressure we want to declare the slot dead fast
					// and let the pool route around the bad edge.
					writeTimeout = 5 * time.Second
					// 300ms × idx so 8 TCP SYNs don't arrive at CF in
					// the same millisecond and trip burst heuristics.
					staggerDelay = 300 * time.Millisecond
					// Russia TSPU 2026 mitigation: DPI silently freezes
					// foreign-IP TCP after ~15-20KB downstream over TLS 1.3.
					// Rotate each slot at 15KB so we get a fresh TCP before
					// the censor's counter triggers. See habr.com/990236
					// ("Clumsy Hands or a New Level of DPI") for background.
					maxBytesPerSlot = 15 * 1024

					// R4 reverted 2026-04-15 after field test: pinning all 8
					// slots to a single pre-resolved CF edge turned out to
					// guarantee the very outage we were trying to avoid —
					// when the chosen edge degrades, every slot dies together
					// (meltdown deaths=6/6 observed). Letting gorilla's dial
					// do its own DNS per slot gives us CF's round-robin back;
					// some slots land on healthy edges and keep traffic
					// flowing while writer_timeout kills slots on bad ones.
					// Users can still pin manually via &cfip= in the URL.
				}

				pool := client.NewWSPoolTransport(e.cl, client.WSPoolConfig{
					Size:              poolSize,
					ServerAddr:        wsTarget,
					UseTLS:            slCfg.TLS,
					SkipVerify:        false,
					SNIHost:           sniHost,
					CFIP:              slCfg.CFIP,
					MaxStreamsPerSlot: maxStreamsPerSlot,
					MaxPendingPerSlot: maxPendingPerSlot,
					MaxBytesPerSlot:   maxBytesPerSlot,
					WriteTimeout:      writeTimeout,
					StaggerDelay:      staggerDelay,
				})
				if err := pool.Connect(ctx2); err != nil {
					slog.Warn("WS Pool не удался, fallback на SplitHTTP", "err", err)
					// Critical: Connect() already spawned reconnectLoop goroutines
					// for every failed slot (ws_pool.go:225). Without Close() those
					// zombie loops keep hammering the dead CF IP forever, sharing
					// p.client.transport with the SplitTransport flow. Close cancels
					// p.ctx so all reconnect loops exit cleanly.
					pool.Close()
				} else {
					e.stream = pool
					go e.streamReaderLoop(ctx2)
					slog.Info("WS Pool подключён",
						"slots", pool.HealthySlots(),
						"total", poolSize,
						"maxStreamsPerSlot", maxStreamsPerSlot,
						"viaCF", viaCF,
						"writeTimeout", writeTimeout,
						"staggerDelay", staggerDelay,
						"cfIP", slCfg.CFIP)
					poolOK = true
				}
			}
		}

		// Fallback: SplitHTTP if pool failed or not requested.
		if !poolOK && e.cfg.SystemVPN {
			token := e.cl.Token()
			if token == nil {
				cancel()
				return fmt.Errorf("SplitHTTP: нет токена после handshake")
			}
			splitAddr := slCfg.Server
			if slCfg.CDN != "" {
				splitAddr = slCfg.CDN + ":443"
			}
			// Pass cfIP so SplitHTTP pins TCP dials to the user-scanned edge
			// instead of resolving CDN domain each POST (CF DNS round-robins
			// through many blocked IPs from Russian ISPs in 2026).
			split := client.NewSplitTransport(splitAddr, token, slCfg.CFIP)
			if slCfg.CFIP != "" {
				slog.Info("SplitHTTP pinned to CF edge", "cfip", slCfg.CFIP)
			}

			split.SetOnResponse(func(encResp []byte) {
				session := e.cl.Session()
				if session == nil {
					return
				}
				chunk, err := session.DecryptChunkSafe(encResp)
				if err != nil || len(chunk.Payload) < 2 {
					return
				}
				streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])
				if chunk.Flags == core.FlagUDP {
					e.cl.RouteToStream(streamID, chunk.Payload)
				} else {
					e.cl.RouteToStream(streamID, chunk.Payload[2:])
				}
			})

			pollTransport := client.NewCDNTransport(splitAddr)
			e.pollTransport = pollTransport

			e.stream = split

			e.startPollWorkers(ctx2, pollTransport)
			go e.streamReaderLoop(ctx2)
			e.streamCtx = ctx2

			// V5 / P0.3: start decoy GET traffic only after the session is
			// wired up. If anything above had failed we would not reach here,
			// so the goroutine is not leaked on handshake/setup failure.
			split.StartDecoyTraffic()

			slog.Info("SplitHTTP транспорт: stream (primary) + poll (fallback)")
		} else if !poolOK {
			// Non-system-VPN fallback: try single WS
			wst, wsErr := e.cl.UpgradeToWebSocket(wsTarget, slCfg.TLS, false)
			if wsErr != nil {
				slog.Warn("Single WS не удался, используем poll-mode", "err", wsErr)
			} else {
				e.stream = wst
				go e.streamReaderLoop(ctx2)
			}
		}
	}

	// C4: wait for SOCKS5 listener to actually start before declaring success.
	//
	// Default bypass list for CIS TLDs: these are not subject to RKN blocking
	// and don't benefit from being tunneled. Bypassing them significantly
	// reduces WS pool load in CF mode and speeds up RU/CIS site access in
	// all modes. User-provided routing is merged on top (user bypass takes
	// precedence over defaults when rules conflict).
	defaultBypass := []string{
		"*.ru",
		"*.рф",
		"*.su",
		"*.by",
		"*.kz",
		"*.ua",
		"*.am",
	}
	routingCfg := client.RoutingConfig{Bypass: defaultBypass}
	if slCfg.Routing != nil {
		// Merge: user rules + defaults. User rules are evaluated first by
		// matcher order, so they effectively override.
		routingCfg.Block = slCfg.Routing.Block
		routingCfg.Force = slCfg.Routing.Force
		routingCfg.Bypass = append(slCfg.Routing.Bypass, defaultBypass...)
	}
	router := client.NewRouter(routingCfg)

	if e.socks != nil {
		// CDN per-stream mode: SOCKS server was already created above, just set router.
		e.socks.Router = router
	} else {
		e.socks = &socks5.Server{
			Client:   e.cl,
			WST:      e.stream,
			Router:   router,
			Addr:     e.socksAddr,
			Username: e.cfg.ProxyUser,
			Password: e.cfg.ProxyPass,
			ViaCDN:   slCfg.CDN != "" && slCfg.Origin == "",
		}
	}

	socksErrCh := make(chan error, 1)
	go func() { socksErrCh <- e.socks.ListenAndServe(ctx2) }()

	// C4: give SOCKS5 time to bind — if it fails immediately, catch the error.
	select {
	case err := <-socksErrCh:
		cancel()
		return fmt.Errorf("SOCKS5 не запустился: %w", err)
	case <-time.After(300 * time.Millisecond):
		if e.socks.ListenAddr() == nil {
			cancel()
			return fmt.Errorf("SOCKS5 не смог создать listener на %s", e.socksAddr)
		}
	}

	// W8: monitor SOCKS5 for unexpected death.
	go func() {
		err := <-socksErrCh
		if ctx2.Err() != nil {
			return // normal shutdown
		}
		e.signalError(fmt.Errorf("SOCKS5 упал: %w", err))
	}()

	return nil
}

// streamReaderLoop restarts the stream reader (SplitHTTP or WS) on disconnect.
// Sets downloadActive=true while stream is alive so poll fallback pauses.
func (e *ShadowLinkEngine) streamReaderLoop(ctx context.Context) {
	backoff := 2 * time.Second
	maxBackoff := 30 * time.Second

	for {
		e.downloadActive.Store(true)
		startedAt := time.Now()
		err := e.stream.StartReader(ctx, e.cl)
		e.downloadActive.Store(false)
		if ctx.Err() != nil {
			return // normal shutdown
		}
		uptime := time.Since(startedAt).Round(time.Second)
		// If reader ran for >30s, it was working — reset backoff.
		if time.Since(startedAt) > 30*time.Second {
			backoff = 2 * time.Second
		}
		slog.Warn("Download stream завершился, poll fallback активен", "err", err, "backoff", backoff, "uptime", uptime)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		// For SplitTransport: just reconnect the download stream (StartReader opens a new GET).
		// For WSPoolTransport: pool handles per-slot reconnection internally.
		// For WebSocketTransport: need to create a new WS connection.
		if _, isSplit := e.stream.(*client.SplitTransport); isSplit {
			// SplitTransport reconnects automatically in StartReader (opens new GET).
			backoff = min(backoff*2, maxBackoff)
			slog.Info("SplitHTTP download stream переподключается...", "nextBackoff", backoff)
			continue
		}

		// WSPoolTransport: all slot readers exited. DON'T destroy the pool —
		// it has its own internal recovery via handleSlotDeath → reconnectLoop
		// for each slot. Just restart StartReader so it picks up the slots
		// as they come back online. Creating a new pool (and especially
		// Close()ing the old one) kills the recovery goroutines and makes
		// things worse: the new pool connects into the same CF edge that
		// just RST'd us, dies immediately, and we loop forever.
		if _, isPool := e.stream.(*client.WSPoolTransport); isPool {
			slog.Info("WS Pool: все reader'ы вышли, перезапуск StartReader",
				"backoff", backoff)
			// Pool's reconnectLoops are already running for dead slots.
			// Just let backoff pass and re-enter the for loop to call
			// StartReader again on the same pool.
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		// Single WebSocket: need full reconnect.
		slCfg := e.cfg.ShadowLink
		wsReconnTarget := slCfg.Server
		if slCfg.Origin != "" {
			wsReconnTarget = slCfg.Origin + ":443"
		}
		newWST, reconnErr := e.cl.UpgradeToWebSocket(wsReconnTarget, slCfg.TLS, false)
		if reconnErr != nil {
			slog.Error("WS reconnect не удался", "err", reconnErr)
			backoff = min(backoff*2, maxBackoff)
			if backoff >= maxBackoff && e.cfg.SystemVPN {
				e.signalError(fmt.Errorf("reconnect не удался: %w", reconnErr))
				return
			}
			continue
		}

		e.stream = newWST
		if e.socks != nil {
			e.socks.WST = newWST
		}
		backoff = 2 * time.Second
		slog.Info("WS переподключён")
	}
}

// startPollWorkers launches a poll fallback goroutine through a dedicated CDNTransport.
// Active ONLY when the download stream is dead (reconnecting).
// When download stream is alive, poll sleeps to avoid dual-path data corruption.
func (e *ShadowLinkEngine) startPollWorkers(ctx context.Context, pollTransport client.Transport) {
	e.pollWG.Add(1)
	go func() {
		defer e.pollWG.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			// Pause when download stream is active — it handles all download data.
			if e.downloadActive.Load() {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			if e.cl.Session() == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			if err := e.cl.PollVia(ctx, pollTransport); err != nil {
				slog.Debug("poll fallback error", "err", err)
				time.Sleep(50 * time.Millisecond)
				continue
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
}

// StartDownloadStream starts the download stream reader loop.
// Must be called AFTER TUN + LeakGuard are configured in system VPN mode,
// otherwise the TCP connection to CF breaks when TUN changes the routing table.
func (e *ShadowLinkEngine) StartDownloadStream() {
	if e.streamCtx != nil && e.stream != nil {
		go e.streamReaderLoop(e.streamCtx)
		slog.Info("download stream started (post-TUN)")
	}
}

func (e *ShadowLinkEngine) SOCKSAddr() string { return e.socksAddr }
func (e *ShadowLinkEngine) Name() string      { return "shadowlink" }

func (e *ShadowLinkEngine) Close() error {
	if e.cancel != nil {
		e.cancel()
	}
	// Wait for poll workers to exit before closing transport (prevents panic on closed ConnManagers).
	e.pollWG.Wait()
	if e.socks != nil {
		e.socks.Close()
	}
	if e.readyPool != nil {
		// Close the pool before cl.Close() so pool workers don't race with
		// the client shutting down its transport while they're mid-upgrade.
		e.readyPool.Close()
	}
	if e.pollTransport != nil {
		e.pollTransport.Close()
	}
	if e.stream != nil {
		e.stream.Close()
	}
	if e.cl != nil {
		e.cl.Close()
	}
	return nil
}
