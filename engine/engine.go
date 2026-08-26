package engine

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/proxy/socks5"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
)

type ShadowLinkEngine struct {
	cl        *client.Client
	socks     *socks5.Server
	socksAddr string
	cfg       *Config
	cancel    context.CancelFunc
	engineCtx context.Context // long-lived engine ctx; relay lifetime for in-process dialer (Bug #5)

	// streamMu защищает stream. Транспорт переставляется на лету из
	// streamReaderLoop (реконнект одиночного WS), а читается из Close() и
	// InProcessDialer() — другие горутины. Без лока Close() мог закрыть СТАРЫЙ
	// транспорт, а новый оставался висеть: утечка TLS-соединения к origin, а это
	// P0-класс по модели угроз (policing по числу соединений).
	streamMu sync.Mutex
	stream   client.StreamTransport // WebSocketTransport or SplitTransport

	// W8: error channel — signals main loop when engine dies
	errCh  chan error
	once   sync.Once
	pollWG sync.WaitGroup // tracks poll worker goroutines for clean shutdown
	// streamWG считает горутины streamReaderLoop. ОТДЕЛЬНО от pollWG намеренно:
	// ждать их в одной точке нельзя. pollWG.Wait() стоит ДО socks.Close(), а
	// stream-ридер в момент останова может висеть внутри UpgradeToWebSocket до
	// HandshakeTimeout (10 с) — ожидание там заблокировало бы закрытие SOCKS5 на
	// всё это время. Поэтому streamWG ждётся ПОСЛЕ socks.Close() и с таймаутом.
	streamWG      sync.WaitGroup
	pollTransport client.Transport // dedicated transport for polls (separate from CONNECTs)

	// Pre-warmed WS pool for per-stream CF CDN mode. Nil in other transport modes.
	// Keeps ~20 WS connections upgraded-and-idle so each SOCKS5 CONNECT can grab
	// one instantly instead of paying the ~250ms TCP+TLS+WS-upgrade cost.
	readyPool *client.WSReadyPool

	// pool публикует поднятый WS-пул для наблюдателей здоровья (ReadySlots).
	// Пишется один раз, при успешном Connect пула; nil в остальных режимах.
	//
	// Отдельное поле, а не чтение stream под streamMu: наблюдателю здоровья
	// нужен дешёвый неблокирующий доступ (его зовут из UI-потока мобильного
	// клиента), а stream перезаписывается на каждом реконнекте.
	pool atomic.Pointer[client.WSPoolTransport]

	// Download stream coordination: poll pauses when download stream is active.
	downloadActive atomic.Bool
	streamCtx      context.Context // stored for deferred download stream start

	// closed делает Close() идемпотентным. Нужен именно как флаг, а не sync.Once:
	// Close() возвращает error, и Once скрыл бы факт повторного вызова.
	closed atomic.Bool

	// closeRuns считает, сколько раз тело Close() было исполнено ПОЛНОСТЬЮ.
	// Заведён ради наблюдаемости гейта: без него «идемпотентность» проверялась бы
	// по числу закрытий транспорта, а то зануляется в самом Close() и потому
	// молчит о повторном проходе — зелёный сторож, ничего не измеряющий.
	closeRuns atomic.Int32
}

func NewShadowLinkEngine(cfg *Config) (*ShadowLinkEngine, error) {
	// Конструктор разыменовывает cfg сразу, поэтому nil здесь — паника, а не
	// отложенная ошибка на Connect. Сигнатура уже возвращает error; вернуть его
	// дешевле, чем ронять вызывающего, тем более что у мобильного фасада
	// конфиг приходит с другой стороны языковой границы.
	if cfg == nil {
		return nil, fmt.Errorf("engine: config is nil")
	}
	return &ShadowLinkEngine{
		socksAddr: cfg.SOCKS,
		cfg:       cfg,
		errCh:     make(chan error, 1),
	}, nil
}

// setStream переставляет активный транспорт и синхронно — тот же транспорт в
// SOCKS5-сервере. Обе записи в одном месте, потому что рассинхрон между ними
// означал бы, что CONNECT'ы уходят в закрытый WS.
func (e *ShadowLinkEngine) setStream(t client.StreamTransport) {
	// После Close() установка ЗАПРЕЩЕНА, и запрет обязан быть здесь, а не только
	// в ожидании ридера. Ожидание ограничено сверху (streamReaderShutdownGrace),
	// поэтому зависший ридер может проснуться уже ПОСЛЕ того, как Close() снял
	// поле, и поставить свежий транспорт — тот не закрыл бы никто, и это ровно
	// та утечка TLS-соединения к origin, ради которой правка и делалась.
	// Закрываем такой транспорт сразу: владельца у него больше нет.
	if e.closed.Load() {
		if t != nil {
			t.Close()
		}
		return
	}
	e.streamMu.Lock()
	e.stream = t
	e.streamMu.Unlock()
	if e.socks != nil {
		e.socks.SetWST(t)
	}
}

// getStream возвращает текущий транспорт.
func (e *ShadowLinkEngine) getStream() client.StreamTransport {
	e.streamMu.Lock()
	defer e.streamMu.Unlock()
	return e.stream
}

// spawnStreamReader запускает streamReaderLoop под учётом streamWG.
//
// Единая точка запуска заведена намеренно: до неё `go e.streamReaderLoop(...)`
// стояло в трёх местах, и любое четвёртое (или забытое при правке) молча
// выпадало бы из учёта, а Close() не имел бы способа это заметить.
func (e *ShadowLinkEngine) spawnStreamReader(ctx context.Context) {
	e.streamWG.Add(1)
	go func() {
		defer e.streamWG.Done()
		e.streamReaderLoop(ctx)
	}()
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

// Connect поднимает сессию ShadowLink: handshake, транспорт, SOCKS5.
//
// При ЛЮБОМ неуспехе после подключения клиента вызывается Close() — иначе
// повисали client.Client, WS-пул из 8 слотов, горутина streamReaderLoop и
// stats-логгер. Отдельно важен pool.Close(): без него серверу не уходит
// session-FIN, и на нём остаются ghost-сессии до idle-таймаута. Раньше ранние
// return звали только cancel(), который отменяет контекст, но ничего не
// закрывает: отменённый контекст сам по себе не шлёт FIN и не рвёт TLS.
//
// Именованный результат нужен именно для этого defer — по err он отличает
// неуспех от успеха.
func (e *ShadowLinkEngine) Connect(ctx context.Context) (retErr error) {
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
	// Вызывающий может передать свой ID (Config.ClientID): у мобильного клиента
	// процесс переживает десятки подключений, и UUID на каждый Connect означал бы
	// новую идентичность при каждом выходе из фона. ID остаётся НЕПРОЗРАЧНЫМ —
	// движок его не интерпретирует; предсказуемые (аккаунтные) ID требуют правки
	// handshake (§4.4 спеки) и здесь не подразумеваются.
	clientID := e.cfg.ClientID
	if len(clientID) != 16 {
		if len(clientID) != 0 {
			slog.Warn("engine: ClientID не 16 байт — игнорирую, генерирую UUID",
				"len", len(clientID))
		}
		u := uuid.New()
		clientID = u[:]
	}

	clientCfg := client.ClientConfig{
		ServerAddr:   slCfg.Server,
		ServerPubKey: pubKey,
		ClientID:     clientID,
		UseTLS:       slCfg.TLS,
		CDNDomain:    slCfg.CDN,
		// Пустая строка = не персистить (поведение CLI). Мобильный фасад сюда
		// передаёт системный каталог: без него профиль отпечатка выбирается
		// заново на каждый старт, а дрейф отпечатка — это сигнал (hard rule 2).
		FPCacheDir: e.cfg.StateDir,
	}
	// Resolve full-direct mode parameters. Two URL inputs activate it:
	//   1. Explicit ?sni=<domain> + Server=<IP:port> — caller knew enough to
	//      hand-craft a direct-to-IP target with a domain-shaped TLS SNI.
	//   2. ?origin=<IP> alongside ?cdn=<domain> — the URL gives us both
	//      pieces (CDN-protected domain for SNI, origin IP for dial); the
	//      intent is identical to (1) but the user didn't need to know the
	//      "sni" knob existed.
	//
	// Without case (2), origin= used to take effect ONLY for the WS pool's
	// dial target (engine sets wsTarget below) while handshake/reconnect-
	// handshake POSTs went through the CDNTransport — meaning DNS on the
	// CDN domain returned CF edge IPs and reconnect POSTs sometimes landed
	// at CF instead of origin. Field log 2026-05-18 captured this leak:
	//   Post "https://datacanvases.com/api/v2/batch" ... 51152->104.21.5.211:443
	// where 104.21.5.211 is CF and 104.222.177.67 is origin.
	//
	// By forcing full-direct when origin is present, both the data path
	// (handshake POST + reconnect POST + WS pool) dial origin IP with the
	// CDN domain as TLS ServerName — there is no DNS for the data path.
	if slCfg.SNI == "" && slCfg.Origin != "" && slCfg.CDN != "" {
		host, port, splitErr := net.SplitHostPort(slCfg.Server)
		if splitErr != nil {
			host = slCfg.CDN
			port = "443"
		}
		_ = host // currently unused; kept for symmetry if we later need it
		clientCfg.ServerAddr = slCfg.Origin + ":" + port
		clientCfg.SNIOverride = slCfg.CDN
		clientCfg.CDNDomain = "" // force direct transport path (no CDNTransport wrap)
		slog.Info("ShadowLink full-direct (auto from origin=)",
			"dial", clientCfg.ServerAddr, "sni", slCfg.CDN)
	} else if slCfg.SNI != "" {
		// Full-direct mode: client dials to IP (slCfg.Server), TLS SNI = slCfg.SNI.
		// In this mode we do NOT go through CF — both handshake and WS are direct.
		// SNI override takes precedence over CDN: don't wrap in CDNTransport.
		clientCfg.SNIOverride = slCfg.SNI
		clientCfg.CDNDomain = "" // force direct transport path
		slog.Info("ShadowLink full-direct", "dial", slCfg.Server, "sni", slCfg.SNI)
	}

	ctx2, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	// Единая точка уборки на всех путях неуспеха. Ставится сразу после
	// присвоения e.cancel, потому что первый же отказ ниже (handshake) случается
	// уже после того, как клиент мог поднять соединения.
	//
	// Close() идемпотентен, поэтому вызывающему не нужно знать, убрались мы уже
	// или нет: его собственный defer Close() безопасен.
	defer func() {
		if retErr != nil {
			e.Close()
		}
	}()
	// engineCtx is the long-lived context for the whole engine session. The
	// in-process tun2socks dialer (Bug #5) uses it as the relay lifetime ctx so
	// streams aren't bound to tun2socks' 5s dial ctx (review HIGH-5).
	e.engineCtx = ctx2

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
		// cancel() здесь больше не нужен — его зовёт Close() из defer-cleanup.
		return fmt.Errorf("ошибка подключения ShadowLink: %w", err)
	}

	slog.Info("ShadowLink подключен", "transport", e.cl.TransportName())

	// DomainPool wire-up: if the YAML/URL config supplied a CDN rotation pool
	// (slCfg.CDNs), install it on the transport's ConnManager so each reconnect
	// picks a fresh SNI from the pool. Gated on len > 0 so existing single-CDN
	// configs keep the static SNI behavior. TTL=5min matches the DomainPool
	// blacklist default — failed domains rest for 5min before reentering Pick.
	if len(slCfg.CDNs) > 0 {
		type cmAccessor interface {
			ConnManager() *client.ConnManager
		}
		if acc, ok := e.cl.Transport().(cmAccessor); ok {
			if cm := acc.ConnManager(); cm != nil {
				pool := client.NewDomainPool(slCfg.CDNs, 5*time.Minute)
				cm.SetDomainPool(pool)
				slog.Info("ShadowLink DomainPool installed",
					"size", cm.DomainPoolSize(), "cdns", slCfg.CDNs)
			}
		}
	}

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
				var maxBytesPerSlot int64      // 0 = disabled
				var maxSlotAge time.Duration   // 0 = disabled
				viaCF := slCfg.CDN != "" && slCfg.Origin == "" && slCfg.SNI == ""
				viaDirect := slCfg.Origin != "" || slCfg.SNI != ""
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
					// CDN-mode: byte budget alone handles the short TSPU window.

					// R4 reverted 2026-04-15 after field test: pinning all 8
					// slots to a single pre-resolved CF edge turned out to
					// guarantee the very outage we were trying to avoid —
					// when the chosen edge degrades, every slot dies together
					// (meltdown deaths=6/6 observed). Letting gorilla's dial
					// do its own DNS per slot gives us CF's round-robin back;
					// some slots land on healthy edges and keep traffic
					// flowing while writer_timeout kills slots on bad ones.
					// Users can still pin manually via &cfip= in the URL.
				} else if viaDirect {
					// Direct-mode rotation (2026-05-18 field analysis).
					// Field logs show foreign-origin TCP getting `close 1006`
					// from middleboxes (NAT age timers, stateful firewalls,
					// TSPU's age heuristic for long-lived flows) every 2-5
					// minutes. Self-rotating BEFORE that window keeps the
					// kill signal off the wire. 8 MiB byte budget + 75s
					// age budget cover both heavy-upload and long-idle cases.
					// 75s rotates slots well inside the ~130s TSPU freeze
					// window (spec 2026-06-05). Per-slot stagger inside the
					// pool (capped 6s × idx, see StaggerStep/StaggerOffsetCap
					// below) keeps rotations spread out — never a handshake
					// storm — while keeping high-idx uniform-cells under the
					// freeze window. Field-tunable via SHADOWLINK_MAX_SLOT_AGE.
					maxBytesPerSlot = 8 * 1024 * 1024
					maxSlotAge = envDurationDefault("SHADOWLINK_MAX_SLOT_AGE", 75*time.Second)
					// A2 (2026-05-18): spread INITIAL connect handshakes
					// by 300ms × idx so 8 TCP SYNs don't arrive at origin
					// in the same millisecond. Same value as viaCF mode
					// uses (line 348). The post-meltdown reconnect path
					// has its own jitter (see reconnectJitterOffset in
					// client/ws_pool.go) — these two cover initial connect
					// and reconnect storm respectively.
					staggerDelay = 300 * time.Millisecond
					// A4 anti-TSPU debt (2026-05-18): rebalance hint for
					// stream distribution across the pool. Pre-A4 saw
					// active_streams peak at 85+ on a single slot under
					// burst load — non-browser-like frame rate per conn,
					// detectable signature. With this hint AssignStream
					// PASS-1 routes streams to slots under the threshold;
					// at saturation it soft-overflows (AssignStream "all
					// slots at capacity" path picks the slot with fewest
					// streams, NEVER refuses a stream). Net effect:
					// smoother distribution (~10 streams/slot for 80
					// concurrent), no hard stop on burst, no failed
					// CONNECTs.
					//
					// CAP IS A HINT NOT A LIMIT. Soft band = 8 × poolSize
					// streams (64 for poolSize=8) below which PASS-1
					// honors the cap; streams ABOVE this overflow to the
					// least-loaded slot via the soft-overflow path —
					// never refused. Real speedtest sees 50-60 parallel
					// CONNECTs, within the soft band; overflow only kicks
					// in under heavier burst.
					//
					// If field test shows throughput drop >5%, revert to
					// 0 (unlimited) and the score-min PASS-1 handles
					// distribution implicitly. One-line code change +
					// redeploy on pl1 — no env-flag needed.
					maxStreamsPerSlot = 8
				}

				// Phase 3 (2026-05-20): WS pool graceful drain — DEFAULT ON
				// after three canaries on uniform-cells architecture (2026-05-19
				// 14:54 baseline, 17:19 uniform-cells, 18:01 + F1 fix). Metrics:
				// natural finish ratio 53%, storm-brake capacity-floor defers 0,
				// "all readers exited" regressions 0, decrypt_fails 0, downlink
				// write errors 0. SHADOWLINK_GRACEFUL_DRAIN=0 (or false/no/off)
				// is the emergency opt-out — restores legacy hard-rotation path.
				// SHADOWLINK_DRAIN_HARD_CAP is field-tunable without redeploy.
				// Lowered to 30s (2026-06-05): worst-case teardown is now
				// maxSlotAge(75s, or up to 120s for the highest-idx uniform
				// cell) + 30s drain = ≤150s, keeping the forced teardown near
				// the ~130s TSPU freeze edge. Streams still in flight RESUME
				// onto a live slot via the migration watchdog — no data loss.
				gracefulDrain := envBoolDefault("SHADOWLINK_GRACEFUL_DRAIN", true)
				drainHardCap := envDurationDefault("SHADOWLINK_DRAIN_HARD_CAP", 30*time.Second)
				// Invariant guard (final-review MEDIUM-1): the lowered drain hard-cap
				// only stays safe because in-flight streams RESUME onto a live slot
				// via the migration watchdog when the draining slot is torn down. If
				// stream migration is OFF, a slot torn down at maxSlotAge+drainHardCap
				// can land inside the ~130s TSPU freeze window and drop its streams by
				// close(chan). Warn loudly so an operator who disabled migration also
				// reconsiders the aggressive drain cap.
				if gracefulDrain && !envBoolDefault("SHADOWLINK_STREAM_MIGRATION", true) &&
					maxSlotAge+drainHardCap >= 120*time.Second {
					slog.Warn("aggressive drain hard-cap WITHOUT stream migration: in-flight streams may be dropped near the TSPU freeze window — raise SHADOWLINK_DRAIN_HARD_CAP or enable SHADOWLINK_STREAM_MIGRATION",
						"maxSlotAge", maxSlotAge, "drainHardCap", drainHardCap)
				}
				// Drain idle-finish heuristic — defaults derived from 2026-05-22
				// 8h canary: 79.6% of hard-cap drains held ≤2 streams that were
				// keepalive-idle for the entire 90s window. 30s idle threshold
				// leaves room for a real 25s browser keepalive ping to land
				// inside the window.
				drainIdleThreshold := envDurationDefault("SHADOWLINK_DRAIN_IDLE_THRESHOLD", 30*time.Second)
				drainIdleStreamsMax := int32(envIntDefault("SHADOWLINK_DRAIN_IDLE_STREAMS_MAX", 2))
				// Deprecation notice (spec 2026-05-25-drain-per-stream-idle-decision-design §2.5):
				// SHADOWLINK_DRAIN_IDLE_STREAMS_MAX is no longer consulted in the drain
				// decision after Step 2. Emit a one-time WARN if operator set it
				// explicitly so they know to migrate to SHADOWLINK_DRAIN_IDLE_THRESHOLD=0.
				if _, set := os.LookupEnv("SHADOWLINK_DRAIN_IDLE_STREAMS_MAX"); set {
					slog.Warn("SHADOWLINK_DRAIN_IDLE_STREAMS_MAX is deprecated and no longer affects drain behavior. " +
						"Use SHADOWLINK_DRAIN_IDLE_THRESHOLD=0 to disable the idle gate.")
				}
				// Bug #6 sticky stream (adaptive backstop). Defaults live in
				// NewWSPoolTransport; these env vars override for field tuning
				// without a rebuild.
				//
				// Kill switch: set SHADOWLINK_STICKY_MAX_DRAIN_AGE=0 to disable
				// sticky (deadline reverts to blind hard-cap). We translate an
				// explicit "0" to -1 here because NewWSPoolTransport treats a
				// cfg value of exactly 0 as "unset → default 10m"; only a
				// negative value reaches the watchdog's `<= 0` kill gate. Unset
				// env → envDurationDefault returns 10m (not 0), so the default
				// path is unaffected (final review M-1).
				// Дефолт из client — единый источник. Раньше здесь была вторая
				// копия литерала 10m: правка в одном месте не затрагивала
				// другое. 2026-07-31 значение пересчитано по замеру age-cut,
				// см. client.DefaultStickyMaxDrainAge.
				stickyMaxDrainAge := envDurationDefault("SHADOWLINK_STICKY_MAX_DRAIN_AGE",
					client.DefaultStickyMaxDrainAge)
				if stickyMaxDrainAge == 0 {
					stickyMaxDrainAge = -1
				}
				stickyMaxTotalBytes := int64(envIntDefault("SHADOWLINK_STICKY_MAX_TOTAL_BYTES", 256*1024*1024))
				stickyMaxSlots := envIntDefault("SHADOWLINK_STICKY_MAX_SLOTS", 0)
				// Bug #9 (2026-05-31): keepalive base. Window = [base/2, base*2]
				// under the log-normal sampler, so base=5s caps the worst-case
				// silence on a quiet slot at 10s — under the ~10-15s direct-mode
				// silent-cut window of the РФ TSPU. Was effectively 20s (window up
				// to 40s) before the fix, which let quiet AI-agent streams die
				// unrecoverably. Field-tunable without redeploy; 0/unset → 5s.
				keepaliveInterval := envDurationDefault("SHADOWLINK_KEEPALIVE_INTERVAL", 5*time.Second)

				// TSPU age-window tuning (2026-06-05): rotate slots BEFORE the ~130s
				// middlebox freeze window. staggerOffsetCap keeps high-idx uniform-cells
				// (idx up to 2*Size-1) under the window. ageCutMinAge is the slot-age
				// floor for classifying a terminal read error as an expected age-cut
				// (vs a genuine early failure) — kept in lockstep with the 75s rotation
				// and the 45s migration threshold so the classification window doesn't
				// collapse. Field-tunable without rebuild.
				staggerStep := envDurationDefault("SHADOWLINK_STAGGER_STEP", 6*time.Second)
				staggerOffsetCap := envDurationDefault("SHADOWLINK_STAGGER_OFFSET_CAP", 45*time.Second)
				ageCutMinAge := envDurationDefault("SHADOWLINK_AGE_CUT_MIN_AGE", 45*time.Second)

				// Доля пола storm-brake. 0 → константа 0.75. Выведена ради A/B:
				// при MaxSlotAge=70s пул штатно балансирует НА полу (alive=6 при
				// floor=6), и отложки гейта удлиняют жизнь слота в полосу
				// ненулевого hazard — 3 реза из 4 в прогоне 20260813-153638
				// следуют за отложкой той же ячейки в пределах 7s. Дефолт НЕ
				// изменён: занижение пола — это риск clinch'а, ради которого гейт
				// и заводился. Обоснование у client.readyCapacityFloorFraction.
				readyCapacityFloorFraction := envFloatDefault("SHADOWLINK_READY_CAPACITY_FLOOR_FRACTION", 0)

				pool := client.NewWSPoolTransport(e.cl, client.WSPoolConfig{
					Size:                       poolSize,
					ServerAddr:                 wsTarget,
					UseTLS:                     slCfg.TLS,
					SkipVerify:                 false,
					SNIHost:                    sniHost,
					CFIP:                       slCfg.CFIP,
					MaxStreamsPerSlot:          maxStreamsPerSlot,
					MaxPendingPerSlot:          maxPendingPerSlot,
					MaxBytesPerSlot:            maxBytesPerSlot,
					MaxSlotAge:                 maxSlotAge,
					WriteTimeout:               writeTimeout,
					StaggerDelay:               staggerDelay,
					KeepaliveInterval:          keepaliveInterval,
					StaggerStep:                staggerStep,
					StaggerOffsetCap:           staggerOffsetCap,
					AgeCutMinAge:               ageCutMinAge,
					ReadyCapacityFloorFraction: readyCapacityFloorFraction,
					GracefulDrain:              gracefulDrain,
					DrainHardCap:               drainHardCap,
					DrainIdleThreshold:         drainIdleThreshold,
					DrainIdleStreamsMax:        drainIdleStreamsMax,
					StickyMaxDrainAge:          stickyMaxDrainAge,
					StickyMaxTotalBytes:        stickyMaxTotalBytes,
					StickyMaxSlots:             stickyMaxSlots,
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
					e.setStream(pool)
					// Публикуем пул для наблюдателей здоровья (ReadySlots).
					e.pool.Store(pool)
					e.spawnStreamReader(ctx2)
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

			e.setStream(split)

			e.startPollWorkers(ctx2, pollTransport)
			e.spawnStreamReader(ctx2)
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
				e.setStream(wst)
				e.spawnStreamReader(ctx2)
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
			Router:   router,
			Addr:     e.socksAddr,
			Username: e.cfg.ProxyUser,
			Password: e.cfg.ProxyPass,
			ViaCDN:   slCfg.CDN != "" && slCfg.Origin == "",
		}
		e.socks.SetWST(e.getStream())
	}

	socksErrCh := make(chan error, 1)
	go func() { socksErrCh <- e.socks.ListenAndServe(ctx2) }()

	// C4: give SOCKS5 time to bind — if it fails immediately, catch the error.
	select {
	case err := <-socksErrCh:
		return fmt.Errorf("SOCKS5 не запустился: %w", err)
	case <-time.After(300 * time.Millisecond):
		if e.socks.ListenAddr() == nil {
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
		cur := e.getStream()
		err := cur.StartReader(ctx, e.cl)
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
		if _, isSplit := cur.(*client.SplitTransport); isSplit {
			// SplitTransport reconnects automatically in StartReader (opens new GET).
			backoff = min(backoff*2, maxBackoff)
			slog.Info("SplitHTTP download stream переподключается...", "nextBackoff", backoff)
			continue
		}

		// WSPoolTransport: F1 architectural fix (2026-05-20) — StartReader
		// now polls and supervises readers for the pool's lifetime, returning
		// ONLY on ctx.Done. Any non-nil return here means VPN shutdown.
		if _, isPool := cur.(*client.WSPoolTransport); isPool {
			slog.Info("WS Pool: StartReader вернулся (ctx.Done)",
				"err", err)
			return // exit streamReaderLoop — context is cancelled
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

		e.setStream(newWST)
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
	if e.streamCtx != nil && e.getStream() != nil {
		e.spawnStreamReader(e.streamCtx)
		slog.Info("download stream started (post-TUN)")
	}
}

func (e *ShadowLinkEngine) SOCKSAddr() string { return e.socksAddr }
func (e *ShadowLinkEngine) Name() string      { return "shadowlink" }

// SOCKSListenAddr возвращает ФАКТИЧЕСКИЙ адрес листенера SOCKS5 или nil, пока
// его нет.
//
// Отличие от SOCKSAddr() существенно и ради него метод и заведён: тот отдаёт
// строку из конфига, а вызывающий может передать порт 0 ("127.0.0.1:0") —
// единственный безопасный вариант на телефоне, где 1080 может быть занят
// другим VPN-приложением. Узнать выбранный ядром порт можно только у листенера.
func (e *ShadowLinkEngine) SOCKSListenAddr() net.Addr {
	if e.socks == nil {
		return nil
	}
	return e.socks.ListenAddr()
}

// ReadySlots возвращает число готовых слотов WS-пула, или -1 если транспорт не
// пуловый либо ещё не поднят.
//
// Нужен потребителю, который показывает здоровье туннеля: SOCKS5-порт
// продолжает принимать соединения и при мёртвом пуле, поэтому «сессия жива»
// без этой величины наблюдаемостью не является (§4.8.2 спеки — в прод-режиме
// ErrorCh не сигналит вовсе).
func (e *ShadowLinkEngine) ReadySlots() int {
	if p := e.pool.Load(); p != nil {
		return p.HealthySlots()
	}
	return -1
}

// InProcessDialer returns the in-process tun2socks dialer (Bug #5), tunnelling
// TUN traffic over the WS transport without a loopback SOCKS5 socket — which
// eliminates Windows ephemeral port exhaustion at high throughput. Returns nil
// if the engine isn't ready (no SOCKS server / transport yet), so callers fall
// back to the loopback dialer. Implements InProcessDialerProvider.
func (e *ShadowLinkEngine) InProcessDialer() proxy.Dialer {
	if e.socks == nil || e.socks.WST() == nil || e.cl == nil || e.engineCtx == nil {
		return nil
	}
	return socks5.NewInProcessDialer(e.engineCtx, e.socks)
}

// NetworkChanged форсирует переустановку слотов пула после смены сети (Wi-Fi↔LTE,
// Wi-Fi↔Ethernet, выход из сна). Без неё слоты держат TCP со старого локального
// адреса и ЗАВИСАЮТ до TCP-таймаута — туннель встаёт на десятки секунд. Метод
// платформо-независим (чистый Go): его зовут NIC-вотчер десктопа, а на мобильных —
// фасад из ConnectivityManager.NetworkCallback / NWPathMonitor.
//
// No-op вне режима пула: одиночный WS-транспорт своей ротации слотов не имеет,
// а poll-режим переустанавливается собственным контуром. Тип проверяется через
// интерфейс NetworkChangeNotifier, а не жёстким assertion, чтобы добавление
// второго его носителя не потребовало правки здесь.
func (e *ShadowLinkEngine) NetworkChanged() {
	if n, ok := e.getStream().(interface{ NetworkChanged() }); ok {
		n.NetworkChanged()
	}
}

// streamReaderShutdownGrace — сколько Close() ждёт выхода streamReaderLoop.
//
// Не тайминговая константа протокола (hard rule 8 не про неё): она не влияет ни
// на один кадр на проводе, а только на длительность собственного останова. Взята
// с запасом к HandshakeTimeout=10с из ws_transport: ридер, висящий в
// UpgradeToWebSocket, освободится по своему дедлайну, а не по нашему. Верхняя
// граница нужна, чтобы Close() был конечен при любом зависании — на iOS весь
// бюджет stopTunnel исчисляется секундами.
const streamReaderShutdownGrace = 2 * time.Second

func (e *ShadowLinkEngine) Close() error {
	// Идемпотентность обязательна, а не желательна: defer-cleanup неуспешного
	// Connect зовёт Close(), и следом его же зовёт вызывающий по своему defer.
	// Второй проход раньше закрывал уже закрытый listener и закрытые транспорты.
	if !e.closed.CompareAndSwap(false, true) {
		return nil
	}
	e.closeRuns.Add(1)
	if e.cancel != nil {
		e.cancel()
	}
	// Wait for poll workers to exit before closing transport (prevents panic on closed ConnManagers).
	e.pollWG.Wait()
	if e.socks != nil {
		e.socks.Close()
	}
	// streamWG ждётся ЗДЕСЬ, а не рядом с pollWG: ридер может висеть в
	// UpgradeToWebSocket до HandshakeTimeout, и ожидание перед socks.Close()
	// удерживало бы SOCKS5-листенер открытым всё это время. Ждём с потолком,
	// потому что нам важно не «дождаться любой ценой», а гарантировать, что
	// после Close() не осталось горутины, способной переставить e.stream уже
	// после того, как мы его закрыли, — а этого не будет: ридер сам смотрит на
	// отменённый ctx.
	if !e.waitStreamReaders(streamReaderShutdownGrace) {
		slog.Warn("stream reader не завершился в отведённое окно — закрываем транспорт всё равно",
			"grace", streamReaderShutdownGrace)
	}
	if e.readyPool != nil {
		// Close the pool before cl.Close() so pool workers don't race with
		// the client shutting down its transport while they're mid-upgrade.
		e.readyPool.Close()
	}
	if e.pollTransport != nil {
		e.pollTransport.Close()
	}
	// Забираем транспорт ПОД ЛОКОМ и обнуляем поле: после этого никакой
	// припозднившийся ридер не закроет объект второй раз и не подставит новый.
	e.streamMu.Lock()
	stream := e.stream
	e.stream = nil
	e.streamMu.Unlock()
	if stream != nil {
		stream.Close()
	}
	if e.cl != nil {
		e.cl.Close()
	}
	return nil
}

// waitStreamReaders ждёт выхода всех streamReaderLoop не дольше d.
// Возвращает false, если окно истекло.
func (e *ShadowLinkEngine) waitStreamReaders(d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		e.streamWG.Wait()
		close(done)
	}()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

// envBoolDefault reads a boolean env var with the same lenient semantics
// as bypassEnabledFromEnv / adminOverrideEnabled (case-insensitive,
// whitespace-trimmed). Unset / empty / unrecognized values return def;
// recognized truthy/falsy keywords ("0", "false", "no", "off" / "1",
// "true", "yes", "on") map as expected.
func envBoolDefault(name string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "":
		return def
	case "0", "false", "no", "off":
		return false
	case "1", "true", "yes", "on":
		return true
	default:
		return def
	}
}

// envDurationDefault reads a time.Duration env var (any value
// time.ParseDuration accepts: "90s", "2m", "1h30m", "500ms"). Unset,
// empty, or unparseable values return def.
func envDurationDefault(name string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

// envFloatDefault reads a float64 env var. Unset, empty, or unparseable values
// return def. Диапазон НЕ проверяется — валидация на вызывающем (для доли пола
// это client.normalizeFloorFraction, которая клампит и мусор, и >= 1).
func envFloatDefault(name string, def float64) float64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

// envIntDefault reads a base-10 int env var. Unset, empty, or
// unparseable values return def. Negative values are returned verbatim
// — the caller is responsible for any non-negative validation.
func envIntDefault(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
