package client

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nixavpn/shadowlink/client/slotobs"
	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
)

// Stats holds live counters for debugging throughput/contention issues.
//
// Counters are package-global and accessed via atomic ops so hot paths pay
// nothing more than a CAS. The StartStatsLogger goroutine periodically logs
// *deltas* (not totals) so you can tell at a glance how much traffic each
// subsystem is generating right now — e.g. "is UDP poll storm dominating
// the HTTP transport?" or "how many per-stream WSs open per second?".
//
// Type convention: legacy fields use atomic.Int64 because StartStatsLogger
// computes delta = current − previous and stores prev as int64. Newer
// monotonic-only counters added since Phase 2 (PQ handshake) and Phase 0
// (WS lifecycle) use atomic.Uint64 — no overflow concerns at the edge,
// and they don't participate in the delta arithmetic (they're dumped raw
// or via separate aggregation, see §5.2 of the WS lifecycle design).
type statsRegistry struct {
	// Cover traffic HTTP POSTs from DirectTransport/CDNTransport.
	CoverPosts atomic.Int64
	// UDP ASSOCIATE poll ticker fires (20ms each) sending a poll POST.
	UdpPolls atomic.Int64
	// Per-stream WebSocket connections opened (fresh WS per SOCKS5 CONNECT).
	WsCreated atomic.Int64
	// Per-stream WebSocket connections died (reader/writer exit).
	WsDied atomic.Int64
	// Per-stream WS upgrades via the ready pool (Acquire returned a warmed WS).
	WsFromPool atomic.Int64
	// Session.EncryptChunk calls (every outgoing data/control frame).
	Encrypts atomic.Int64
	// Session.DecryptChunkSafe calls (every incoming frame).
	Decrypts atomic.Int64
	// Session.DecryptChunkSafe that failed — high number ⇒ wrong key, out-of-window
	// seq, or anti-replay rejection. A healthy client should see zero.
	DecryptFails atomic.Int64
	// SOCKS5 CONNECT requests accepted (both per-stream and pooled paths).
	SocksConnects atomic.Int64
	// Uplink bytes read from SOCKS5 client (before encryption).
	UplinkBytes atomic.Int64
	// Downlink bytes written to SOCKS5 client (after decryption).
	DownlinkBytes atomic.Int64
	// Async writer Run() exits — one of the two death causes for a pool slot.
	// A writer exit means the local 30s (or configured) WriteDeadline fired
	// because CF stalled our send buffer; we then close the conn ourselves.
	// Distinguishing this from a reader-side close is critical for telling
	// "CF closed us" apart from "we closed ourselves" — cross-check 2026-04-15.
	WriterExits atomic.Int64
	// Slot reader goroutine exits (terminal, not timeout continues). Paired
	// with WriterExits to attribute slot deaths. If WriterExits ≫ ReaderExits
	// then CF-side stall is the trigger, not a server-originated close.
	ReaderExits atomic.Int64

	// PQ ClientHello handshake outcomes (T1.1, Phase 2, 2026-04-26).
	// Counters only increment when SHADOWLINK_TLS_PQ=1 — they stay at zero in
	// default builds so a non-zero reading on the dashboard is itself a signal
	// that the PQ path is enabled in the field.
	//
	// PQClientHelloSent — count of TLS ClientHellos sent with X25519MLKEM768
	// in supported_groups + key_share where the subsequent TLS handshake also
	// completed. Was named PQHandshakeSuccess until 2026-05-17 (Wave 3.3);
	// renamed because CF edge may negotiate classical X25519 in ServerHello
	// while we still record the ClientHello attempt — the metric tracks what
	// we send, not what completes with PQ on the server side. See
	// docs/superpowers/plans/2026-05-17-pq-wireshark-check.md for the
	// one-time wire-level verification procedure.
	//
	// Three labels in the Prom exposition (shadowlink_tls_pq_handshake_total):
	//   - clienthello_sent : pqClientHelloSpec applied + Handshake completed
	//                        (was "success" prior to 2026-05-17 rename)
	//   - fallback         : pqClientHelloSpec returned an error so we used
	//                        helloID (Handshake itself succeeded on the
	//                        fallback spec)
	//   - error            : the dial errored on either ApplyPreset or
	//                        Handshake while in the PQ branch (regardless of
	//                        whether the PQ spec or the fallback spec was
	//                        loaded — both count as "PQ branch exposed an
	//                        error to the caller")
	PQClientHelloSent   atomic.Uint64
	PQHandshakeFallback atomic.Uint64
	PQHandshakeError    atomic.Uint64

	// FrameAnomaliesTotal ticks shadowlink_ws_frame_anomaly_total{type=...}
	// when the slot reader receives a terminal (non-timeout) WS read error.
	// Cardinality is bounded by classifyWSReadError's known label set
	// (frameAnomalyReasons) — pre-created in init() so dashboards see a
	// complete label set from the very first error.
	FrameAnomaliesTotal sync.Map // map[string]*atomic.Uint64

	// RateLimitedFromServer ticks every time the WS upgrade or handshake POST
	// surfaces ErrRateLimited (server emitted X-SL-RL: 1 in the decoy response
	// because the per-IP rate limit fired). Task A2 (May audit, 2026-05-01).
	// Paired with the server's shadowlink_ratelimit_sentinel_emitted_total
	// counter on the dashboard so ops can correlate "client backed off" with
	// "server told it to back off". A non-zero rate is ALWAYS a signal the
	// pool is fighting the rate limit.
	RateLimitedFromServer atomic.Int64

	// Bypass routing decisions (Phase A, 2026-05-02). Each TCP/UDP dial
	// from tun2socks routes through BypassDialer; if dst IP is covered by
	// the embedded RIPE RU snapshot or admin override, the dial goes
	// "direct" (system physical interface) instead of through the SOCKS5
	// inner dialer (ShadowLink VPN). On dashboards, match/(match+miss)
	// approximates the fraction of traffic that bypassed the VPN — a
	// healthy Russian session should land between 0.4 and 0.7 depending
	// on which sites the user is hitting.
	BypassMatchTotal atomic.Int64
	BypassMissTotal  atomic.Int64

	// === Phase 0+ (2026-05-14): WS lifecycle refactor metrics ===
	// See docs/superpowers/specs/2026-05-14-shadowlink-ws-lifecycle-design.md §5.2.
	// Counters log via existing 5-sec delta dump in StartStatsLogger.

	// --- Slot lifecycle (Phase 3+: ticked by SlotSupervisor) ---
	SlotTransitionsToReady       atomic.Uint64
	SlotTransitionsToDraining    atomic.Uint64
	SlotTransitionsToCoolingDown atomic.Uint64
	// SlotDrainForceTimeouts — increments when a slot enters Draining and
	// EventInflightDone doesn't arrive within 30s, forcing transition with
	// attempt++. Operational signal: persistent growth indicates zombie
	// streams or server-side overload preventing graceful drain.
	SlotDrainForceTimeouts atomic.Uint64
	// SlotStaleEvents — increments when reader/writer goroutine sends an
	// event after StopReaderWriter completed. Race indicator. Should stay
	// near zero in steady state; non-zero rate suggests supervisor
	// blocking-action contract violated.
	SlotStaleEvents atomic.Uint64

	// --- Reconnect dynamics (Phase 3+) ---
	ReconnectAttemptsSuccess          atomic.Uint64
	ReconnectAttemptsFail             atomic.Uint64
	ReconnectCoolDownSourceRLDirected atomic.Uint64
	ReconnectCoolDownSourceBackoff    atomic.Uint64

	// Reconnect backoff distribution — bucketed counters as histogram
	// approximation. On each scheduled backoff, increment the smallest
	// bucket whose upper bound >= duration. Lets slog post-processors
	// derive approximate P50/P95 without TSDB.
	ReconnectBackoffBucketLe2s  atomic.Uint64
	ReconnectBackoffBucketLe5s  atomic.Uint64
	ReconnectBackoffBucketLe15s atomic.Uint64
	ReconnectBackoffBucketLe30s atomic.Uint64
	ReconnectBackoffBucketLe60s atomic.Uint64
	ReconnectBackoffBucketGt60s atomic.Uint64

	// --- Rate-limit detection (Phase 2+) ---
	RateLimitDetectedByBody   atomic.Uint64
	RateLimitDetectedByHeader atomic.Uint64

	// === Phase 2 (2026-05-14) per-path rate-limit counters ===
	// Split detection events by transport path so ops can triage "which gate is
	// being throttled?" without guessing. The aggregate counters above
	// (RateLimitDetectedBy{Body,Header}) are preserved for back-compat
	// and always equal the sum of the corresponding per-path fields.
	//
	// "handshake" path: transport.go DirectTransport.SendHandshake /
	//   SendHandshakeRaw — POST-only.
	// "ws_upgrade" path: ws_transport.go WebSocketTransport.UpgradeToWS —
	//   WS Dial response.
	//
	// Both paths run DetectCarriersOnly() — only a genuine Schema.org body
	// marker or X-SL-RL header triggers a rate-limit signal.
	RateLimitDetectedByBody_Handshake   atomic.Uint64
	RateLimitDetectedByBody_WS          atomic.Uint64
	RateLimitDetectedByHeader_Handshake atomic.Uint64
	RateLimitDetectedByHeader_WS        atomic.Uint64

	// --- WS reader/writer health (Phase −1 partial, full Phase 3+) ---
	WSReaderExitsEOF     atomic.Uint64
	WSReaderExitsTimeout atomic.Uint64
	WSReaderExitsOther   atomic.Uint64
	// WSReaderPanics MUST stay at 0 in production. Tracks gorilla's
	// defensive "repeated read on failed websocket connection" panic
	// recovery. Phase −1 fix eliminated the known trigger; counter
	// remains as canary. Non-zero value = unrecognized bug.
	WSReaderPanics atomic.Uint64
	WSWriterExits  atomic.Uint64

	// === WS Pool Graceful Drain metrics (2026-05-19) ===
	// See docs/superpowers/specs/2026-05-19-shadowlink-ws-pool-graceful-drain-design.md.
	// Populated by drainWatchdog (Task 8). Monotonic event counters →
	// atomic.Uint64 per the Phase 0+ convention (not part of delta dump).
	//
	// DrainStartedTotal — every startDrain invocation (a slot transitioned
	// from slotReady to slotDraining). Pairs with the sum of the two
	// finish counters: in steady state Started == NaturalFinish + HardCap.
	// A persistent gap is the signal that a watchdog goroutine leaked.
	DrainStartedTotal atomic.Uint64
	// DrainNaturalFinishTotal — drains that completed because in-flight
	// stream count reached zero before the hard cap. Healthy field
	// operation expects this to dominate DrainHardCapTotal (long-tail
	// streams are uncommon).
	DrainNaturalFinishTotal atomic.Uint64
	// DrainHardCapTotal — drains that were force-torn-down by the hard
	// cap deadline (SHADOWLINK_DRAIN_HARD_CAP, default 90s). A growing
	// ratio of HardCap / Started indicates long-lived SOCKS5 streams
	// (file downloads, persistent connections) that survive rotation
	// — review whether to extend the cap or rotate less aggressively.
	DrainHardCapTotal atomic.Uint64
	// Bug #6 sticky stream counters.
	// DrainStickyExtendedTotal — times the deadline branch extended a drain
	// because an active stream was still flowing (incremented in Task 6).
	DrainStickyExtendedTotal atomic.Uint64
	// DrainStickyBackstopAgeTotal — sticky drains torn down because the
	// per-drain age backstop (StickyMaxDrainAge) fired on an active stream.
	DrainStickyBackstopAgeTotal atomic.Uint64
	// DrainStickyBackstopBytesTotal — sticky drains torn down because the
	// per-TCP byte backstop (StickyMaxTotalBytes) fired on an active stream.
	DrainStickyBackstopBytesTotal atomic.Uint64
	// DrainStickyQuotaDeniedTotal — sticky drains torn down because the
	// sticky quota / readyCapacity gate denied (or revoked) the extension.
	DrainStickyQuotaDeniedTotal atomic.Uint64
	// DrainPhantomCounterTotal — дренажи, порванные по КАРТЕ при ненулевом
	// счётчике слота: slot.streams держит привязки, которых в streamMap уже
	// нет (утёкший декремент).
	//
	// Счётчик диагностический, а не декоративный: пока причина утечки не
	// найдена, он единственный способ увидеть, жив ли дефект. Замер
	// 2026-08-11 (3ч38м): 408 из 431 sticky-teardown были такими, 396 из них
	// стоили полных 25s удержания ячейки. Если после починки утечки это
	// значение не упадёт до нуля — починили не то.
	DrainPhantomCounterTotal atomic.Uint64
	// DrainDurationSeconds — distribution of drain durations from
	// startDrain → terminal teardown (either natural finish or hard
	// cap). Bucket boundaries 1/5/10/30/60/90/120s match the operational
	// regimes: <5s = trivial, 5-30s = nominal, 30-90s = stretched, >90s
	// only possible under future hard-cap raise. Initialized in init().
	DrainDurationSeconds *Histogram

	// StaleFrameDroppedTotal — frames arriving on a slot whose
	// streamMap lookup returns a different idx (post-teardown
	// streamID reuse race). See spec 2026-05-20 §2.4.1. A non-zero
	// rate is expected during heavy rotation; sustained high rate is
	// a bug.
	StaleFrameDroppedTotal atomic.Uint64

	// DownlinkReplayDroppedTotal — downlink chunks dropped because their
	// transport-level chunk.SeqNum failed the session anti-replay window
	// (already-seen or too-old). M1 (2026-06-11): AEAD proves authenticity but
	// NOT freshness; an on-path injector can re-inject a captured authentic
	// chunk to duplicate bytes in the proxied TCP stream. This counter MUST stay
	// ~0 in a healthy canary — a sustained non-zero rate means either an
	// on-path replay attempt OR the server is genuinely re-sending seqs (then a
	// separate diagnostic is warranted).
	DownlinkReplayDroppedTotal atomic.Uint64

	// MigrationFrameUnparseable — H-C2 (audit 2026-06-11). A decrypted FlagData
	// frame on a migration-negotiated slot that matched NEITHER the legacy
	// control-string path NOR ParseStreamDataSeq (len<10 / malformed seq shape).
	// Pre-fix this frame was silently dropped — a hole in the proxied TCP byte
	// stream (the Bug#8 class: app-side TLS decrypt failure / broken download)
	// with NO telemetry. The frame is now NOT dropped silently: the owning
	// stream is deterministically torn down (handleStreamClose → EOF → app
	// retry) and this counter is bumped. MUST stay ~0 in a healthy canary; a
	// sustained non-zero rate means a wire-format contract gap (e.g. a server
	// build emitting a control frame our matcher doesn't recognize, or a
	// per-slot/pool decode-shape desync — see H-C3).
	MigrationFrameUnparseable atomic.Uint64

	// SnapshotNegativeAgeTotal — counts cases where drainStreamSnapshot
	// observed lastWriteNs > now (clock went backwards under NTP adjust,
	// or, worse, arbitrary value stored). Clamped to 0 in snapshot logic;
	// counter exposes the underlying event for observability. Non-zero
	// rate at >1/h indicates clock skew or a stamping bug worth investigating.
	// Spec 2026-05-25 (drain-per-stream-diagnostics).
	SnapshotNegativeAgeTotal atomic.Uint64

	// InflightCapDeferredTotal — drain attempts deferred because
	// inflightDrains already at maxConcurrentDrains. Indicates the
	// rotation scheduler is healthy but at peak concurrency. High rate
	// is OK if bounded; persistent saturation suggests poolSize is too
	// small for the current rotation cadence. Counter increments on
	// EVERY defer; log emission is rate-limited (drainDeferredLogInterval).
	// Spec 2026-05-24 (drain-diagnostics-counter-split).
	InflightCapDeferredTotal atomic.Uint64

	// CapacityFloorDeferredTotal — drain attempts deferred because
	// readyCapacity fell below readyCapacityFloor (poolSize *
	// readyCapacityFloorFraction, see ws_pool.go). Counter increments on
	// EVERY defer; log emission rate-limited. Spec 2026-05-24
	// (drain-diagnostics-counter-split, updated by concurrency-lift-and-backoff
	// to use the decoupled fraction constant).
	//
	// ⚠ ПЕРЕЧИТАНО 2026-08-14. Здесь стояло «Catastrophic path — pool losing
	// slots faster than reconnectLoop heals», и это описание сделало счётчик
	// нечитаемым: при пороге 70s гейт срабатывает 25 раз за 2ч в ОТСУТСТВИЕ
	// катастрофы (пул штатно балансирует НА полу: alive=6 при floor=6,
	// poolSize=8), поэтому оператор, следуя этому тексту, прочёл бы штатный
	// режим как каскадную смерть слотов.
	//
	// Что счётчик значит на самом деле: ротация уже признана нужной, но
	// отложена — слот вернулся в slotReady и ПРОДОЛЖАЕТ стареть. Разбор
	// лога nixavpn-DEBUG-20260813-153638: 3 реза из 4 за прогон следуют за
	// отложкой той же ячейки в пределах 7s (79.6s → рез на 86.6s; 79.8s →
	// 84.4s; 79.7s → 82.7s). Резов среди отложенных 3/22, среди всех 4/622 —
	// относительный риск ×21 (гипергеометрический p ≈ 1.5e-4, n=3, поэтому
	// указание, а не доказательство). Механизм статистики не требует: отсрочка
	// на 79.7s гарантирует ≥3s экспозиции в полосе 80-85s, где hazard впервые
	// перестаёт быть нулём.
	//
	// Величина этой полосы (прогон 153638, по экспозиции): rate_exp
	// 14.4e-3 1/с, то есть p_pass ≈ 6.94% при проходе полосы целиком.
	// ⚠ Не путать с 2.1% = Cut/Reached — это доля на ВХОД в полосу при
	// экспозиции 0.2s, единицы разные. Ровно на этой подмене единиц уже
	// строился неверный вывод (разбор 2026-08-14).
	//
	// ⚠ Уточнено 2026-08-14: причина отложек — НЕ порог 70s, как считалось выше, а
	// утечка ячеек в reconnect/recycle. До первой потери ячейки (15:42:12) гейт не
	// срабатывал ни разу, первая отложка — 15:44:32, все 22 при ready=5 floor=6, а
	// ready=5 достижимо только после потери двух ячеек. Полная цепочка: утечка →
	// alive до пола → отложка → +возраст → рез. Утечка исправлена, и в следующем
	// прогоне отложек стало 0 при неизменной доле 0.75.
	//
	// Читать так: ненулевой rate = слоты платят возрастом за исправность пула.
	// Смотреть вместе с ready_capacity / ready_capacity_floor и возрастами резов,
	// а не как индикатор «каскад/не каскад»: ready_capacity == floor означает,
	// что пул балансирует НА полу и любая плановая ротация будет отклонена.
	CapacityFloorDeferredTotal atomic.Uint64

	// HealingRetargetTotal — сколько раз цепочка reconnectLoop переприцелилась на
	// другую ячейку, потому что её собственную забрал дренаж.
	//
	// Заведён 2026-08-14 вместе с исправлением утечки ячеек (D1). До правки
	// такой обрыв означал ПОТЕРЮ ячейки навсегда: периодического healer'а в пуле
	// нет, каждая цепочка reconnectLoop одноразова. В поле это давало
	// empty 8 → 9 → 10 → 11 и mean alive 7.21 → 5.80 за 2 часа, а на конце
	// цепочки — пул на полу storm-brake, отклонённые ротации и резы посредника.
	//
	// Ненулевое значение = утечка ПРОИЗОШЛА БЫ, но была вылечена. Это не тревога,
	// а доказательство работы правки: сравнивать с ReserveConnectFailuresTotal
	// (поводов войти в ветку) и с alive в health snapshot.
	HealingRetargetTotal atomic.Uint64

	// HealingRetargetGaveUpTotal — лечение исчерпало maxHealingRetargets и
	// отказалось. Пул идёт на одну ячейку меньше до следующей естественной смерти
	// слота.
	//
	// Отдельный счётчик, а не общий с HealingRetargetTotal: «вылечили» и «сдались»
	// — противоположные исходы, и складывать их значило бы завести поле, чьё имя
	// врёт о механизме (в этом проекте — повторяющийся класс дефектов). В поле
	// ожидается ноль; ненулевое означает, что дренажи забирают ячейки быстрее,
	// чем лечение успевает их занимать, и предел надо пересмотреть замером.
	HealingRetargetGaveUpTotal atomic.Uint64

	// ⚠ Здесь был SweepPhaseJitterAppliedTotal — счётчик подтиковых отсрочек
	// дренажа. Удалён 2026-08-14 вместе с самой ручкой: она не размазывала фазу
	// (единственный читатель nextDrainAttemptNs — свип, а свип просыпается по
	// тому же тикеру, поэтому отсрочка меньше тика всегда переносила дренаж
	// ровно на следующий тик, в ту же фазу). Причина лечится срезкой
	// rotationWatchdogTick — см. обоснование у этой константы.

	// StreamBufferOverflowsTotal — cumulative count of frames dropped at
	// client.RouteToStream when the per-stream buffered channel (cap 512)
	// is full. Counter increments once per dropped frame, surfaced at
	// stream UnregisterStream as an aggregated INFO log. Non-zero rate
	// indicates SOCKS consumer death races (most often local app closing
	// TCP early) — see spec 2026-05-23.
	StreamBufferOverflowsTotal atomic.Uint64

	// Bug #8 flow control client-side counters.
	FlowWindowUpdatesSent   atomic.Uint64
	FlowWindowUpdateDropped atomic.Uint64 // TryEnqueueControl full → delta kept
	FlowNegotiationTimeout  atomic.Uint64 // ack not received within negotiationAckTimeout

	// Bug #9 §5.4 downlink-reassembler client-side counters.
	// StreamReassemblyOverflow: per-stream reassembler buffered past its byte cap
	// (unfillable gap grew the pending set) → stream broken (degradation).
	// StreamReassemblyGapTimeout: a downlink hole did not close within the gap
	// timeout → stream broken instead of hanging (NEW-1).
	StreamReassemblyOverflow   atomic.Uint64
	StreamReassemblyGapTimeout atomic.Uint64
	// StreamReassemblyBufferedBytes (gauge, Task 19): most-recent total bytes
	// held out-of-order across all active reassemblers. A persistently high
	// reading means downlink holes are common (frequent migration mid-stream
	// or reordering on the WS path); it's the leading indicator before an
	// overflow/gap-timeout teardown actually fires. Stored as the latest
	// observed snapshot — last writer wins, like FirstStreamMS.
	StreamReassemblyBufferedBytes atomic.Int64

	// Bug #9 Task 15 — client MIGRATE/RESUME send-side counters. (Full client
	// migration metrics land in Task 19; these are the minimum the send path
	// needs to surface ack-await outcomes.)
	//   MigrateAttempt: a MIGRATE/RESUME frame was enqueued and we began ack-await.
	//   MigrateOK / MigrateFail: server replied OK / FAIL within the window.
	//   MigrateTimeout: no reply within migrateAckTimeout → stream degraded.
	//   MigrateCapabilityDropped: 3 consecutive timeouts tripped the hysteresis.
	MigrateAttempt           atomic.Uint64
	MigrateOK                atomic.Uint64
	MigrateFail              atomic.Uint64
	MigrateTimeout           atomic.Uint64
	MigrateCapabilityDropped atomic.Uint64
	// MigrateScheduled: count of (stream, slot) preemptive migrations the
	// age-watchdog armed via scheduleSlotMigration (Bug #9 Task 16). Full
	// migration telemetry lands in Task 19; this is the minimum the watchdog
	// trigger surfaces.
	MigrateScheduled atomic.Uint64

	// MigrateResumeOnDeathOK / Fail: outcomes of the reactive RESUME-on-slot-death
	// path (Bug #9 Task 17, §5.5). OK = a stream survived a sudden slot death by
	// re-homing onto a live slot; Fail = no live target or the server refused, so
	// the stream broke (legacy degradation). Full migration telemetry lands in
	// Task 19; these are the minimum the slot-death path surfaces.
	MigrateResumeOnDeathOK   atomic.Uint64
	MigrateResumeOnDeathFail atomic.Uint64

	// DrainForceEvictedTotal — every time startDrain force-evicted an
	// idle slotReady cell (streams==0) because claimFreeSlot returned -1
	// (slice fully occupied). Spec 2026-05-20 §2.2.3 (slice-full
	// eviction policy). Non-zero rate is expected in long-running
	// sessions where stable network keeps cells alive past natural
	// rotation; required to keep anti-fingerprint rotation moving when
	// no natural reader-error frees a cell.
	DrainForceEvictedTotal atomic.Uint64

	// DrainForceEvictedActiveTotal — emergency eviction of a slotReady
	// cell that had ACTIVE streams (streams > 0) because (a) no idle
	// cell was available AND (b) the drain target's slot age exceeded
	// 2× maxSlotAge (over-aged threshold). Spec 2026-05-20 §2.2.3
	// (emergency eviction policy). Each increment represents one or
	// more user-visible SOCKS5 streams killed to break the deadlock —
	// anti-fingerprint priority wins over UX after the over-aged
	// threshold. Sustained non-zero rate means the pool is chronically
	// saturated; consider raising slice size.
	DrainForceEvictedActiveTotal atomic.Uint64

	// EmergencyEvictMigratedTotal — streams SAVED by PREEMPTIVELY migrating them
	// off an emergency-eviction victim cell BEFORE its forced teardown, while the
	// aging TCP is still healthy (spec 2026-06-01 emergency-evict-migrate).
	// Reuses the Bug#9 MIGRATE primitive at the tier-2 eviction site. A healthy
	// non-zero value means capacity-pressure evictions no longer break
	// user-visible flows that had a younger slot to move onto. Streams NOT moved
	// by this pass fall through to handleSlotDeath's RESUME-on-death attempt
	// (counted as MigrateResumeOnDeathOK/Fail) — there is deliberately no
	// separate "killed" counter here, which would double-count streams the
	// teardown's RESUME still rescues.
	EmergencyEvictMigratedTotal atomic.Uint64

	// ReserveConnectFailuresTotal — cumulative count of connectReserveSlot
	// failures (across all cells). High rate suggests TIME_WAIT exhaustion
	// or origin endpoint instability — investigate before raising
	// maxConcurrentDrainsFraction further. Spec 2026-05-24
	// (concurrency-lift-and-backoff).
	ReserveConnectFailuresTotal atomic.Uint64

	// DrainIdleFinishTotal — drains that completed because the slot showed
	// no decrypt/write activity for SHADOWLINK_DRAIN_IDLE_THRESHOLD AND the
	// remaining stream count was ≤ SHADOWLINK_DRAIN_IDLE_STREAMS_MAX. Logged
	// as natural finish (keeps the existing dashboard meaning intact); this
	// counter exposes WHY the natural finish fired so we can distinguish
	// the streams-reached-zero path from the keepalive-idle path. Subset
	// of DrainNaturalFinishTotal: in steady state, NaturalFinish ≥
	// IdleFinish always.
	DrainIdleFinishTotal atomic.Uint64

	// Pool capacity-dip fix (spec 2026-06-01-pool-capacity-dip-fix-design.md).
	//
	// AgeCutReconnectsTotal — slots that died to an EXPECTED TSPU age-cut
	// (mature slot, close 1006) and were reconnected via the fast path
	// (reconnectLoopFast attempt-0 success). The cascade of mature-slot cuts is
	// driven by the middlebox, not us; this counter measures how often the fast
	// reconnect healed the slot near-instantly instead of sitting in the old
	// 5-10s exponential. A steady non-zero rate in direct mode is EXPECTED and
	// healthy (it is the TSPU age-cutting bare-origin TCP).
	AgeCutReconnectsTotal atomic.Uint64

	// AgeCutReconnectFail — age-cut fast reconnect whose attempt-0 connect FAILED
	// (so the loop fell into the exponential ladder). A rising rate is the canary
	// signal that "age-cut" is masking a GENUINE failure (the origin is actually
	// down, not just the middlebox cutting a mature TCP) — if it climbs, the
	// classification (isAgeCut) or the ageCutMinAgeMs threshold needs review.
	// Healthy steady state: near zero (age-cuts reconnect cleanly).
	AgeCutReconnectFail atomic.Uint64

	// CapacityDipTotal — observability counter for the residual capacity dip
	// (Lever 4, counter-only). Incremented when an age-cut would drop the pool's
	// ready capacity below the floor while streams are active — the condition the
	// fast reconnect is meant to shorten. The canary uses this to PROVE the dip
	// is gone after Levers 1+3 ship; a non-zero residual rate gates the (deferred)
	// headroom-mechanism iteration.
	CapacityDipTotal atomic.Uint64

	// FP population mimicry — age-cut split by selected TLS fingerprint profile.
	// Populated by handleSlotDeath (deathCauseAgeCut branch) using p.lockedFP.
	// If Firefox-cohort age-cuts exceed Chrome-cohort in the canary → a regional
	// TSPU is targeting the Firefox fingerprint specifically; use this signal to
	// weight Chrome higher. A/B metric for Task D1 (2026-06-09).
	AgeCutChrome  atomic.Uint64
	AgeCutFirefox atomic.Uint64
	AgeCutOther   atomic.Uint64

	// FP population — какой профиль выбран этим клиентом (gauge: ровно один = 1).
	// Stamped by NewClient via SetActiveProfile; lets the ops dashboard observe the
	// actual population distribution across fleet instances in real time (D3).
	// ActiveProfileChrome — агрегат: =1 для ЛЮБОГО chrome-family профиля
	// (chrome120/131/133). Сохранён для обратной совместимости дашборда и как
	// проверяемая сумма per-major gauge (O-2).
	ActiveProfileChrome  atomic.Uint64
	ActiveProfileFirefox atomic.Uint64

	// Per-major gauge популяции (diversity D3). Ровно один из трёх = 1 на
	// экземпляр клиента; позволяет наблюдать фактическое распределение
	// 120/131/133 по парку.
	ActiveProfileChrome120 atomic.Uint64
	ActiveProfileChrome131 atomic.Uint64
	ActiveProfileChrome133 atomic.Uint64
}

// Histogram is a fixed-bucket histogram for duration-style observations.
// Buckets are inclusive upper bounds: an observation x lands in counts[i]
// where i is the smallest index such that x <= buckets[i]. Observations
// exceeding the largest bucket fall into the overflow bucket
// (counts[len(buckets)]). Sum is stored as milliseconds (int64) so atomic
// arithmetic stays exact on a 64-bit integer; convert back to seconds at
// exposition time.
//
// Concurrency: Observe is lock-free (atomic ops on the bucket slice +
// the sum/count); safe for use from any number of goroutines once the
// histogram is published via NewHistogram.
type Histogram struct {
	buckets []float64
	counts  []atomic.Uint64
	sumMs   atomic.Int64
	count   atomic.Uint64
}

// NewHistogram constructs a histogram with the given inclusive upper-bound
// buckets. Buckets MUST be sorted ascending; this is a developer
// invariant, not a runtime check. The slice is retained (not copied) but
// is treated as immutable post-construction.
func NewHistogram(buckets []float64) *Histogram {
	return &Histogram{
		buckets: buckets,
		counts:  make([]atomic.Uint64, len(buckets)+1),
	}
}

// Observe records a single observation in seconds. The observation
// increments exactly one bucket counter (the first whose upper bound is
// >= seconds, or the overflow bucket), plus the running sum (in ms),
// and the total count LAST.
//
// Ordering matters: bucket → sum → count. A concurrent reader that
// samples count first and then walks buckets will see the invariant
// count >= sum(buckets) hold, because every count.Add is published
// strictly after its corresponding bucket.Add. Reading in the opposite
// order (bucket-sum-then-count) would briefly observe count == sum-1.
// Observe itself is not snapshot-atomic across fields — that's
// acceptable for monotonic event counters consumed eventually.
func (h *Histogram) Observe(seconds float64) {
	for i, b := range h.buckets {
		if seconds <= b {
			h.counts[i].Add(1)
			h.sumMs.Add(int64(seconds * 1000))
			h.count.Add(1)
			return
		}
	}
	h.counts[len(h.buckets)].Add(1)
	h.sumMs.Add(int64(seconds * 1000))
	h.count.Add(1)
}

// Cold-start observability counters (Task D5, 2026-05-02 plan).
//
// Captures the time-to-first-byte the user actually perceives during cold
// start, plus the underlying pool warmup duration. Two related counters
// expose the cold-start failure modes the pool was designed to absorb:
//   - rate-limit decoys received during handshake / WS upgrade,
//   - SOCKS5 demand getting batched by the coalescing dispatcher.
//
// All five live as package-level atomics + helpers (mirrors the spec in the
// 2026-05-02 plan §D5). FirstStreamMS / PoolWarmupMS are gauges holding the
// most-recent observed duration — a fresh cold start overwrites the prior
// value. The decoy/coalesce counters are monotonic since process start.
var (
	// FirstStreamMS — gauge: ms from Client.Connect() success to the first
	// SOCKS5 stream being attached (CONNECT_OK sent back to the SOCKS5
	// caller). Stamped exactly once per Connect() cycle via
	// firstStreamOnce on the Client; subsequent SOCKS5 CONNECTs do not
	// touch the gauge until the next Connect().
	FirstStreamMS atomic.Int64

	// PoolWarmupMS — gauge: ms from WSReadyPool.Start() to all
	// RequireDone=true phases having every slot publish to the ready
	// channel. Tail (RequireDone=false) phases are NOT included — the
	// gauge measures "the moment the pool is ready to serve a SOCKS5
	// burst", and best-effort tail slots are bonus capacity that arrives
	// later.
	PoolWarmupMS atomic.Int64

	// HandshakeDecoyReceived — counter: number of times the client's
	// handshake POST or WS upgrade got a server-emitted decoy response
	// (HTTP 200 + X-SL-RL header). Incremented at the first detection
	// site (transport.go SendHandshake AND ws_transport.go UpgradeToWS)
	// — both paths can independently trip the per-IP rate limiter. Paired
	// with Stats.RateLimitedFromServer on dashboards: this counter is the
	// "saw a decoy" event, RateLimitedFromServer ticks per reconnect-loop
	// cool-down. Dashboards plot decoys/min as the leading indicator.
	HandshakeDecoyReceived atomic.Int64

	// SOCKS5CoalesceGrouped — counter: number of SOCKS5 CONNECTs that
	// joined an in-flight coalescing window in
	// proxy/socks5/coalesce.go::CoalescingDispatcher. Counts every queued
	// joiner including the first caller of the window, so
	// SOCKS5CoalesceGroups is always ≤ SOCKS5CoalesceGrouped. The ratio
	// (Grouped - Groups) / Grouped is the fraction of CONNECTs that
	// benefited from batching (avoided a redundant pool acquire under
	// burst).
	SOCKS5CoalesceGrouped atomic.Int64

	// SOCKS5CoalesceGroups — counter: number of distinct coalescing
	// windows (groups) created. Ticks once per dispatcher window
	// (regardless of how many CONNECTs end up in it).
	SOCKS5CoalesceGroups atomic.Int64
)

// SetFirstStreamMS stamps the gauge with the elapsed duration. Caller is
// expected to gate the call with a sync.Once so only the very first
// SOCKS5 stream-attached event of the Connect cycle wins.
func SetFirstStreamMS(d time.Duration) { FirstStreamMS.Store(d.Milliseconds()) }

// SetPoolWarmupMS stamps the pool-warmup gauge. Called once per
// WSReadyPool.Start() lifecycle from a dedicated watcher goroutine when
// every RequireDone=true phase has tallied to its target.
func SetPoolWarmupMS(d time.Duration) { PoolWarmupMS.Store(d.Milliseconds()) }

// IncHandshakeDecoyReceived ticks the decoy-received counter. Called at
// the rate-limit detection sites in transport.go (handshake POST) and
// ws_transport.go (WS upgrade) — both surface ErrRateLimited to the caller.
func IncHandshakeDecoyReceived() { HandshakeDecoyReceived.Add(1) }

// IncSOCKS5CoalesceGrouped accepts the joiner count for a single
// coalescing window. n must be ≥ 0; values ≤ 0 are no-ops.
func IncSOCKS5CoalesceGrouped(n int) {
	if n <= 0 {
		return
	}
	SOCKS5CoalesceGrouped.Add(int64(n))
}

// IncSOCKS5CoalesceGroups ticks the per-group counter — exactly one call
// per coalescing window, regardless of the number of joiners.
func IncSOCKS5CoalesceGroups() { SOCKS5CoalesceGroups.Add(1) }

// Stats is the singleton stats registry. All increments across the codebase
// use this variable directly.
var Stats statsRegistry

// globalPoolForStatsPtr publishes the running pool transport for the
// shadowlink_drain_inflight gauge. atomic.Pointer keeps reads cheap
// in the exporter hot path. nil if no pool is active.
var globalPoolForStatsPtr atomic.Pointer[WSPoolTransport]

// SetGlobalPoolForStats publishes the pool for gauge exposition.
// Idempotent — last writer wins. Pass nil on Close to clear.
func SetGlobalPoolForStats(p *WSPoolTransport) {
	globalPoolForStatsPtr.Store(p)
}

// frameAnomalyReasons enumerates the labels emitted under
// shadowlink_ws_frame_anomaly_total. Kept in sync with classifyWSReadError
// (ws_pool.go) so dashboards see all series at startup. Adding a new label
// here AND in the classifier is required.
var frameAnomalyReasons = []string{
	"rsv",             // gorilla "RSV1/2/3 set" — corrupted/non-conformant frame header
	"opcode",          // gorilla "bad opcode" — frame header parser saw unsupported opcode
	"html",            // first bytes look like HTTP/HTML — middlebox returned an error page on a WS conn
	"close_1011",      // explicit WS close 1011 (server going away / internal error)
	"close_other",     // other WS close codes (1000/1001/1006/1008/...)
	"closed_local",    // "use of closed network connection" — we Close()d this conn
	"reset_by_peer",   // TCP RST surfaced by kernel — distinct from orderly FIN (eof)
	"io_timeout",      // read/write deadline expired — stalled, not torn down
	"message_too_big", // gorilla "read limit exceeded" — frame larger than ReadLimit
	"eof",             // EOF / unexpected EOF — orderly TCP FIN
	"tls",             // TLS-layer error (handshake done but record layer failed)
	"other",           // catch-all — review log line for unknown patterns
}

func init() {
	// Wire core.Session encrypt/decrypt counters into our atomic stats without
	// making core/ depend on client/.
	core.SetStatsCallbacks(
		func() { Stats.Encrypts.Add(1) },
		func() { Stats.Decrypts.Add(1) },
		func() { Stats.DecryptFails.Add(1) },
	)
	for _, r := range frameAnomalyReasons {
		Stats.frameAnomalyCounter(r)
	}
	// Drain duration histogram — buckets in seconds, see field docstring
	// on statsRegistry.DrainDurationSeconds for rationale.
	Stats.DrainDurationSeconds = NewHistogram([]float64{1, 5, 10, 30, 60, 90, 120})
}

// frameAnomalyCounter returns (creating if needed) the counter for one of
// frameAnomalyReasons. sync.Map LoadOrStore guarantees one canonical entry
// under concurrent first-touch.
func (s *statsRegistry) frameAnomalyCounter(reason string) *atomic.Uint64 {
	if v, ok := s.FrameAnomaliesTotal.Load(reason); ok {
		return v.(*atomic.Uint64)
	}
	c := new(atomic.Uint64)
	actual, _ := s.FrameAnomaliesTotal.LoadOrStore(reason, c)
	return actual.(*atomic.Uint64)
}

// IncAgeCut increments the per-profile age-cut counter.
// profile must be one of "chrome" or "firefox"; any other value falls into
// the "other" bucket. Call-site: handleSlotDeath deathCauseAgeCut branch.
func (s *statsRegistry) IncAgeCut(profile string) {
	switch {
	case browser.IsChromeFamily(profile):
		// chrome120/131/133 (и legacy "chrome") → единая Chrome-когорта.
		s.AgeCutChrome.Add(1)
	case profile == "firefox":
		s.AgeCutFirefox.Add(1)
	default:
		s.AgeCutOther.Add(1)
	}
}

// SetActiveProfile выставляет gauge активного профиля (ровно один в 1, прочие в 0).
// Вызывается из NewClient сразу после resolveProfileWithEnv — отражает, какой
// профиль реально использует этот экземпляр клиента. Позволяет наблюдать
// фактическое распределение популяции по парку клиентов (D3, 2026-06-09).
func (s *statsRegistry) SetActiveProfile(profile string) {
	s.ActiveProfileChrome.Store(0)
	s.ActiveProfileChrome120.Store(0)
	s.ActiveProfileChrome131.Store(0)
	s.ActiveProfileChrome133.Store(0)
	s.ActiveProfileFirefox.Store(0)
	// Per-major gauge.
	switch profile {
	case "chrome120":
		s.ActiveProfileChrome120.Store(1)
	case "chrome131":
		s.ActiveProfileChrome131.Store(1)
	case "chrome133", "chrome": // legacy alias → 133
		s.ActiveProfileChrome133.Store(1)
	case "firefox":
		s.ActiveProfileFirefox.Store(1)
	}
	// Aggregate gauge: =1 для ЛЮБОГО chrome-family (включая будущие major).
	if browser.IsChromeFamily(profile) {
		s.ActiveProfileChrome.Store(1)
	}
}

// IncBypassMatch ticks shadowlink_bypass_match_total — set when a dial's
// destination IP is covered by the bypass trie and goes via the direct dialer.
func (s *statsRegistry) IncBypassMatch() { s.BypassMatchTotal.Add(1) }

// IncBypassMiss ticks shadowlink_bypass_miss_total — set when a dial goes
// via the SOCKS5 inner dialer (i.e. through the VPN tunnel).
func (s *statsRegistry) IncBypassMiss() { s.BypassMissTotal.Add(1) }

// IncFrameAnomaly ticks shadowlink_ws_frame_anomaly_total{type=<reason>}.
// reason MUST come from frameAnomalyReasons; unknown values collapse to
// "other" so cardinality stays bounded.
func (s *statsRegistry) IncFrameAnomaly(reason string) {
	if !slices.Contains(frameAnomalyReasons, reason) {
		reason = "other"
	}
	s.frameAnomalyCounter(reason).Add(1)
}

// WritePromMetrics emits the post-T1.1 client-side counters in the
// Prometheus text exposition format (v0.0.4). Only the counters whose
// underlying source-of-truth lives in the client package are exported here;
// server-side counters are exposed by server.Metrics.ServeHTTP.
//
// Mirrors the server/metrics.go writePromMetrics pattern (zero-dep, no
// promauto) so a test harness or future client-side admin endpoint can
// scrape this without a registry.
//
// T1.1 (Phase 2, 2026-04-26) introduces shadowlink_tls_pq_handshake_total
// with three labels: success / fallback / error. The counter only ticks when
// SHADOWLINK_TLS_PQ=1; default builds emit zeros across all three labels.
func WritePromMetrics(w io.Writer) {
	fmt.Fprintf(w, "# HELP shadowlink_tls_pq_handshake_total PQ ClientHello handshake outcomes (only ticks when SHADOWLINK_TLS_PQ=1)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_tls_pq_handshake_total counter\n")
	fmt.Fprintf(w, "shadowlink_tls_pq_handshake_total{result=\"clienthello_sent\"} %d\n", Stats.PQClientHelloSent.Load())
	fmt.Fprintf(w, "shadowlink_tls_pq_handshake_total{result=\"fallback\"} %d\n", Stats.PQHandshakeFallback.Load())
	fmt.Fprintf(w, "shadowlink_tls_pq_handshake_total{result=\"error\"} %d\n", Stats.PQHandshakeError.Load())

	// T1.6 cover-GET scheduler series retired 2026-05-02 (F3 wire/transport
	// DPI followup). The cover-GET periodic emission was itself an FFT-visible
	// signal and the peer tools we benchmark against (Reality, Hysteria2,
	// TrustTunnel) ship with no cover GETs and operate cleanly in Russia.
	// Counters dropped: shadowlink_cover_get_sent_total{path},
	// shadowlink_cover_get_send_errors_total{reason},
	// shadowlink_cover_get_ratio_observed. Dashboards must drop these series.

	// R.3a frame-anomaly classifier series. Iteration order is the
	// frameAnomalyReasons slice so the exposition output is deterministic.
	fmt.Fprintf(w, "# HELP shadowlink_ws_frame_anomaly_total WS slot read errors classified by failure mode (rsv|opcode|html|close_1011|close_other|closed_local|reset_by_peer|io_timeout|message_too_big|eof|tls|other)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_ws_frame_anomaly_total counter\n")
	for _, r := range frameAnomalyReasons {
		fmt.Fprintf(w, "shadowlink_ws_frame_anomaly_total{type=\"%s\"} %d\n", r, Stats.frameAnomalyCounter(r).Load())
	}

	fmt.Fprintf(w, "# HELP shadowlink_bypass_match_total Dials routed via direct dialer (bypassing the VPN) because dst IP matched the bypass trie\n")
	fmt.Fprintf(w, "# TYPE shadowlink_bypass_match_total counter\n")
	fmt.Fprintf(w, "shadowlink_bypass_match_total %d\n", Stats.BypassMatchTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_bypass_miss_total Dials routed via the SOCKS5 inner dialer (through the VPN tunnel)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_bypass_miss_total counter\n")
	fmt.Fprintf(w, "shadowlink_bypass_miss_total %d\n", Stats.BypassMissTotal.Load())

	// Cold-start observability series (Task D5, 2026-05-02 plan).
	fmt.Fprintf(w, "# HELP shadowlink_first_stream_ms Milliseconds from Client.Connect() to first SOCKS5 stream attached (most recent observation)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_first_stream_ms gauge\n")
	fmt.Fprintf(w, "shadowlink_first_stream_ms %d\n", FirstStreamMS.Load())

	fmt.Fprintf(w, "# HELP shadowlink_pool_warmup_ms Milliseconds from WSReadyPool.Start() to all RequireDone=true phases ready (most recent observation)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_pool_warmup_ms gauge\n")
	fmt.Fprintf(w, "shadowlink_pool_warmup_ms %d\n", PoolWarmupMS.Load())

	fmt.Fprintf(w, "# HELP shadowlink_handshake_decoy_received_total Handshake POST or WS upgrade responses tagged X-SL-RL by the server (rate-limit decoy)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_handshake_decoy_received_total counter\n")
	fmt.Fprintf(w, "shadowlink_handshake_decoy_received_total %d\n", HandshakeDecoyReceived.Load())

	fmt.Fprintf(w, "# HELP shadowlink_socks5_coalesce_grouped_total SOCKS5 CONNECTs that joined a coalescing window (includes first-of-window callers)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_socks5_coalesce_grouped_total counter\n")
	fmt.Fprintf(w, "shadowlink_socks5_coalesce_grouped_total %d\n", SOCKS5CoalesceGrouped.Load())

	fmt.Fprintf(w, "# HELP shadowlink_socks5_coalesce_groups_total Distinct coalescing windows created in CoalescingDispatcher\n")
	fmt.Fprintf(w, "# TYPE shadowlink_socks5_coalesce_groups_total counter\n")
	fmt.Fprintf(w, "shadowlink_socks5_coalesce_groups_total %d\n", SOCKS5CoalesceGroups.Load())

	// === WS Pool Graceful Drain metrics (2026-05-19) ===
	// See docs/superpowers/specs/2026-05-19-shadowlink-ws-pool-graceful-drain-design.md.
	// Without these exposed in the metrics dump, pl1 canary cannot observe
	// Phase 1 behavior (whether drains are dominated by natural finish or
	// hard cap, and the duration distribution).
	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_started_total Total startDrain invocations (slot transitioned slotReady→slotDraining)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_started_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_started_total %d\n", Stats.DrainStartedTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_natural_finish_total Drains that completed because in-flight stream count reached zero before the hard cap\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_natural_finish_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_natural_finish_total %d\n", Stats.DrainNaturalFinishTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_hard_cap_total Drains force-torn-down by the hard-cap deadline (SHADOWLINK_DRAIN_HARD_CAP, default 90s)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_hard_cap_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_hard_cap_total %d\n", Stats.DrainHardCapTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_drain_sticky_extended_total Times the drain deadline was extended because an active stream was still flowing (Bug #6)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_drain_sticky_extended_total counter\n")
	fmt.Fprintf(w, "shadowlink_drain_sticky_extended_total %d\n", Stats.DrainStickyExtendedTotal.Load())
	fmt.Fprintf(w, "# HELP shadowlink_drain_sticky_backstop_age_total Sticky drains torn down by the per-drain age backstop on an active stream\n")
	fmt.Fprintf(w, "# TYPE shadowlink_drain_sticky_backstop_age_total counter\n")
	fmt.Fprintf(w, "shadowlink_drain_sticky_backstop_age_total %d\n", Stats.DrainStickyBackstopAgeTotal.Load())
	fmt.Fprintf(w, "# HELP shadowlink_drain_sticky_backstop_bytes_total Sticky drains torn down by the per-TCP byte backstop on an active stream\n")
	fmt.Fprintf(w, "# TYPE shadowlink_drain_sticky_backstop_bytes_total counter\n")
	fmt.Fprintf(w, "shadowlink_drain_sticky_backstop_bytes_total %d\n", Stats.DrainStickyBackstopBytesTotal.Load())
	fmt.Fprintf(w, "# HELP shadowlink_drain_sticky_quota_denied_total Sticky drains torn down because the quota/readyCapacity gate denied the extension\n")
	fmt.Fprintf(w, "# TYPE shadowlink_drain_sticky_quota_denied_total counter\n")
	fmt.Fprintf(w, "shadowlink_drain_sticky_quota_denied_total %d\n", Stats.DrainStickyQuotaDeniedTotal.Load())
	fmt.Fprintf(w, "# HELP shadowlink_drain_phantom_counter_total Drains torn down by streamMap while slot.streams still held phantom entries (leaked decrement)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_drain_phantom_counter_total counter\n")
	fmt.Fprintf(w, "shadowlink_drain_phantom_counter_total %d\n", Stats.DrainPhantomCounterTotal.Load())

	// Histogram exposition: cumulative bucket counts with le-labels, plus
	// _sum (seconds) and _count. Matches Prometheus histogram conventions.
	if h := Stats.DrainDurationSeconds; h != nil {
		fmt.Fprintf(w, "# HELP shadowlink_slot_drain_duration_seconds Drain duration from startDrain to teardown (natural or hard cap)\n")
		fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_duration_seconds histogram\n")
		var cumulative uint64
		for i, b := range h.buckets {
			cumulative += h.counts[i].Load()
			fmt.Fprintf(w, "shadowlink_slot_drain_duration_seconds_bucket{le=\"%g\"} %d\n", b, cumulative)
		}
		cumulative += h.counts[len(h.buckets)].Load()
		fmt.Fprintf(w, "shadowlink_slot_drain_duration_seconds_bucket{le=\"+Inf\"} %d\n", cumulative)
		fmt.Fprintf(w, "shadowlink_slot_drain_duration_seconds_sum %g\n", float64(h.sumMs.Load())/1000.0)
		fmt.Fprintf(w, "shadowlink_slot_drain_duration_seconds_count %d\n", h.count.Load())
	}

	fmt.Fprintf(w, "# HELP shadowlink_stale_frame_dropped_total Frames dropped due to streamID reuse race after drain teardown\n")
	fmt.Fprintf(w, "# TYPE shadowlink_stale_frame_dropped_total counter\n")
	fmt.Fprintf(w, "shadowlink_stale_frame_dropped_total %d\n", Stats.StaleFrameDroppedTotal.Load())
	fmt.Fprintf(w, "shadowlink_downlink_replay_dropped_total %d\n", Stats.DownlinkReplayDroppedTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_migration_frame_unparseable_total Decrypted FlagData frames on a migration slot that matched neither the control path nor ParseStreamDataSeq; stream torn down (H-C2). Should stay ~0\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migration_frame_unparseable_total counter\n")
	fmt.Fprintf(w, "shadowlink_migration_frame_unparseable_total %d\n", Stats.MigrationFrameUnparseable.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_inflight_cap_deferred_total Drains deferred by storm-brake inflight-cap gate (concurrent drains >= maxConcurrentDrains)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_inflight_cap_deferred_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_inflight_cap_deferred_total %d\n", Stats.InflightCapDeferredTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_capacity_floor_deferred_total Drains deferred by storm-brake capacity-floor gate (readyCapacity < poolSize * readyCapacityFloorFraction)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_capacity_floor_deferred_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_capacity_floor_deferred_total %d\n", Stats.CapacityFloorDeferredTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_pool_healing_retargets_total Reconnect chains re-targeted to another cell after a drain claimed theirs (prevents permanent cell loss)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_pool_healing_retargets_total counter\n")
	fmt.Fprintf(w, "shadowlink_pool_healing_retargets_total %d\n", Stats.HealingRetargetTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_pool_healing_gave_up_total Healing attempts abandoned after maxHealingRetargets — pool runs one cell short until next slot death\n")
	fmt.Fprintf(w, "# TYPE shadowlink_pool_healing_gave_up_total counter\n")
	fmt.Fprintf(w, "shadowlink_pool_healing_gave_up_total %d\n", Stats.HealingRetargetGaveUpTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_force_evicted_total Force-evictions of idle slotReady cells when claimFreeSlot would have returned -1 (slice full)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_force_evicted_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_force_evicted_total %d\n", Stats.DrainForceEvictedTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_stream_buffer_overflows_total Frames dropped at RouteToStream because the per-stream buffered channel was full (consumer dead/slow)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_stream_buffer_overflows_total counter\n")
	fmt.Fprintf(w, "shadowlink_stream_buffer_overflows_total %d\n", Stats.StreamBufferOverflowsTotal.Load())
	fmt.Fprintf(w, "# HELP shadowlink_flow_window_updates_sent_total WINDOW_UPDATE frames sent by the client credit sender (Bug #8)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_flow_window_updates_sent_total counter\n")
	fmt.Fprintf(w, "shadowlink_flow_window_updates_sent_total %d\n", Stats.FlowWindowUpdatesSent.Load())
	fmt.Fprintf(w, "# HELP shadowlink_flow_window_update_dropped_total WINDOW_UPDATE sends skipped because the control channel was full; delta retained (Bug #8)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_flow_window_update_dropped_total counter\n")
	fmt.Fprintf(w, "shadowlink_flow_window_update_dropped_total %d\n", Stats.FlowWindowUpdateDropped.Load())
	fmt.Fprintf(w, "# HELP shadowlink_flow_negotiation_timeout_total Flow-control negotiation acks not received within the timeout (old server / off) (Bug #8)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_flow_negotiation_timeout_total counter\n")
	fmt.Fprintf(w, "shadowlink_flow_negotiation_timeout_total %d\n", Stats.FlowNegotiationTimeout.Load())

	fmt.Fprintf(w, "# HELP shadowlink_stream_reassembly_overflow_total Migration downlink reassembler exceeded its per-stream byte cap; stream broken (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_stream_reassembly_overflow_total counter\n")
	fmt.Fprintf(w, "shadowlink_stream_reassembly_overflow_total %d\n", Stats.StreamReassemblyOverflow.Load())
	fmt.Fprintf(w, "# HELP shadowlink_stream_reassembly_gap_timeout_total Migration downlink hole did not close within the gap timeout; stream broken instead of hung (Bug #9, NEW-1)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_stream_reassembly_gap_timeout_total counter\n")
	fmt.Fprintf(w, "shadowlink_stream_reassembly_gap_timeout_total %d\n", Stats.StreamReassemblyGapTimeout.Load())
	fmt.Fprintf(w, "# HELP shadowlink_stream_reassembly_buffered_bytes Bytes currently held out-of-order across all downlink reassemblers (most recent observation) (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_stream_reassembly_buffered_bytes gauge\n")
	fmt.Fprintf(w, "shadowlink_stream_reassembly_buffered_bytes %d\n", Stats.StreamReassemblyBufferedBytes.Load())

	// Bug #9 MIGRATE/RESUME client send-side + watchdog + slot-death telemetry.
	// Counters defined incrementally across Tasks 15-17; Task 19 surfaces them
	// in the exposition so the pl1 canary can observe migration health
	// (attempt → ok/fail/timeout funnel, capability-drop hysteresis trips,
	// preemptive schedules, and reactive resume outcomes).
	fmt.Fprintf(w, "# HELP shadowlink_migrate_attempt_total MIGRATE/RESUME frames enqueued and entering ack-await (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_attempt_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_attempt_total %d\n", Stats.MigrateAttempt.Load())
	fmt.Fprintf(w, "# HELP shadowlink_migrate_ok_total MIGRATE/RESUME acks that returned OK within the window (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_ok_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_ok_total %d\n", Stats.MigrateOK.Load())
	fmt.Fprintf(w, "# HELP shadowlink_migrate_fail_total MIGRATE/RESUME acks that returned FAIL within the window (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_fail_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_fail_total %d\n", Stats.MigrateFail.Load())
	fmt.Fprintf(w, "# HELP shadowlink_migrate_timeout_total MIGRATE/RESUME ack-await expired without a reply; stream degraded (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_timeout_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_timeout_total %d\n", Stats.MigrateTimeout.Load())
	fmt.Fprintf(w, "# HELP shadowlink_migrate_capability_dropped_total Consecutive migrate timeouts tripped the hysteresis; migration capability dropped (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_capability_dropped_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_capability_dropped_total %d\n", Stats.MigrateCapabilityDropped.Load())
	fmt.Fprintf(w, "# HELP shadowlink_migrate_scheduled_total Preemptive (stream, slot) migrations armed by the age-watchdog (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_scheduled_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_scheduled_total %d\n", Stats.MigrateScheduled.Load())
	fmt.Fprintf(w, "# HELP shadowlink_migrate_resume_on_death_ok_total Streams that survived a sudden slot death by re-homing onto a live slot (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_resume_on_death_ok_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_resume_on_death_ok_total %d\n", Stats.MigrateResumeOnDeathOK.Load())
	fmt.Fprintf(w, "# HELP shadowlink_migrate_resume_on_death_fail_total Streams that broke on a sudden slot death (no live target or server refused) (Bug #9)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_migrate_resume_on_death_fail_total counter\n")
	fmt.Fprintf(w, "shadowlink_migrate_resume_on_death_fail_total %d\n", Stats.MigrateResumeOnDeathFail.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_force_evicted_active_total Emergency evictions of slotReady cells with active streams (over-aged drain target, no idle cell available)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_force_evicted_active_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_force_evicted_active_total %d\n", Stats.DrainForceEvictedActiveTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_emergency_evict_migrated_total Streams preemptively migrated off an emergency-eviction victim cell before its forced teardown (spec 2026-06-01). Reuses the Bug#9 MIGRATE primitive; non-zero means capacity-pressure evictions no longer break flows that had a younger slot to move onto. Streams not moved here fall through to RESUME-on-death (see migrate_resume_on_death_*).\n")
	fmt.Fprintf(w, "# TYPE shadowlink_emergency_evict_migrated_total counter\n")
	fmt.Fprintf(w, "shadowlink_emergency_evict_migrated_total %d\n", Stats.EmergencyEvictMigratedTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_reserve_connect_failures_total Cumulative count of connectReserveSlot failures across all cells. High sustained rate suggests TIME_WAIT exhaustion or origin endpoint instability — investigate before raising maxConcurrentDrainsFraction further.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_reserve_connect_failures_total counter\n")
	fmt.Fprintf(w, "shadowlink_reserve_connect_failures_total %d\n", Stats.ReserveConnectFailuresTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_slot_drain_idle_finish_total Drains classified as natural finish via the idle heuristic (no activity for SHADOWLINK_DRAIN_IDLE_THRESHOLD, ≤ SHADOWLINK_DRAIN_IDLE_STREAMS_MAX remaining streams). Subset of natural_finish_total.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_drain_idle_finish_total counter\n")
	fmt.Fprintf(w, "shadowlink_slot_drain_idle_finish_total %d\n", Stats.DrainIdleFinishTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_drain_inflight Drains currently in progress (atomic snapshot)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_drain_inflight gauge\n")
	if pool := globalPoolForStatsPtr.Load(); pool != nil {
		fmt.Fprintf(w, "shadowlink_drain_inflight %d\n", pool.inflightDrains.Load())
	} else {
		fmt.Fprintf(w, "shadowlink_drain_inflight 0\n")
	}

	// Pool capacity-dip fix (2026-06-01).
	fmt.Fprintf(w, "# HELP shadowlink_age_cut_reconnects_total Slots that died to an expected TSPU age-cut (mature slot, close 1006) and were reconnected via the fast path. Steady non-zero rate in direct mode is expected (TSPU age-cutting bare-origin TCP).\n")
	fmt.Fprintf(w, "# TYPE shadowlink_age_cut_reconnects_total counter\n")
	fmt.Fprintf(w, "shadowlink_age_cut_reconnects_total %d\n", Stats.AgeCutReconnectsTotal.Load())

	fmt.Fprintf(w, "# HELP shadowlink_age_cut_reconnect_fail_total Age-cut fast reconnects whose attempt-0 connect failed (fell into the exponential ladder). A rising rate signals age-cut is masking a genuine origin failure — review isAgeCut / ageCutMinAgeMs.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_age_cut_reconnect_fail_total counter\n")
	fmt.Fprintf(w, "shadowlink_age_cut_reconnect_fail_total %d\n", Stats.AgeCutReconnectFail.Load())

	fmt.Fprintf(w, "# HELP shadowlink_capacity_dip_total Times an age-cut would drop ready pool capacity below the floor while streams were active. Canary observability for the residual dip after the fast-reconnect fix; gates the deferred headroom-mechanism iteration.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_capacity_dip_total counter\n")
	fmt.Fprintf(w, "shadowlink_capacity_dip_total %d\n", Stats.CapacityDipTotal.Load())

	// Раунд 18 P0 (переформулирован 2026-07-31): распределение смертей слотов.
	//
	// Существующие счётчики (age_cut_reconnects_total и т.д.) отвечают «сколько»,
	// но не «где порог» — а именно порог зашит константой, не подтверждённой ни
	// одним источником. Эти серии показывают РАЗБРОС по двум осям: у той оси, по
	// которой реально режет цензор, коэффициент вариации будет заметно НИЖЕ
	// (жёсткий порог даёт кластер на своей оси и разброс на чужой).
	//
	// Считываются на месте (без агрегации по времени) — назначение
	// диагностическое: понять ось и порядок величины ДО того, как проектировать
	// адаптацию. Подробнее: client/slotobs, FIELD-CHECKS.md §2.
	emitSlotDeathDistribution(w)

	// D1 A/B metric: age-cut events split by TLS fingerprint profile (Task D1, 2026-06-09).
	// If Firefox-cohort cuts exceed Chrome-cohort in a region → that TSPU targets Firefox
	// specifically; use this signal to reweight the FP pool toward Chrome.
	fmt.Fprintf(w, "# HELP shadowlink_age_cut_by_profile_total Age-cut slot deaths split by the selected TLS fingerprint profile (chrome|firefox|other). A/B metric for FP population mimicry.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_age_cut_by_profile_total counter\n")
	fmt.Fprintf(w, "shadowlink_age_cut_by_profile_total{profile=\"chrome\"} %d\n", Stats.AgeCutChrome.Load())
	fmt.Fprintf(w, "shadowlink_age_cut_by_profile_total{profile=\"firefox\"} %d\n", Stats.AgeCutFirefox.Load())
	fmt.Fprintf(w, "shadowlink_age_cut_by_profile_total{profile=\"other\"} %d\n", Stats.AgeCutOther.Load())

	// D3 gauge: active FP profile for this client instance (exactly one = 1).
	// Lets the ops dashboard observe the actual population distribution across
	// fleet instances in real time. A persistent all-zero reading means the
	// client binary pre-dates D3 or NewClient did not call SetActiveProfile.
	fmt.Fprintf(w, "# HELP shadowlink_fingerprint_profile_active Which TLS fingerprint profile this client instance selected at startup (gauge: exactly one = 1). Fleet-wide aggregation shows actual population distribution.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_fingerprint_profile_active gauge\n")
	fmt.Fprintf(w, "shadowlink_fingerprint_profile_active{profile=\"chrome\"} %d\n", Stats.ActiveProfileChrome.Load())
	fmt.Fprintf(w, "shadowlink_fingerprint_profile_active{profile=\"firefox\"} %d\n", Stats.ActiveProfileFirefox.Load())

	// D3 per-major diversity gauge: which Chrome major this instance selected.
	// Fleet-wide aggregation должна показать распределение ≈ DefaultFPWeights
	// (10/30/60 для 120/131/133) — подтверждение, что монокультура разбита.
	fmt.Fprintf(w, "# HELP shadowlink_fingerprint_chrome_major_active Selected Chrome major for this client instance (gauge: exactly one of 120/131/133 = 1). Fleet aggregation shows the JA4-cluster split.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_fingerprint_chrome_major_active gauge\n")
	fmt.Fprintf(w, "shadowlink_fingerprint_chrome_major_active{major=\"120\"} %d\n", Stats.ActiveProfileChrome120.Load())
	fmt.Fprintf(w, "shadowlink_fingerprint_chrome_major_active{major=\"131\"} %d\n", Stats.ActiveProfileChrome131.Load())
	fmt.Fprintf(w, "shadowlink_fingerprint_chrome_major_active{major=\"133\"} %d\n", Stats.ActiveProfileChrome133.Load())
}

// emitSlotDeathDistribution exposes the slot-death distribution collected by
// client/slotobs (раунд 18 P0, reframed 2026-07-31).
//
// The point of these series is to answer "which AXIS does the censor key on",
// which no existing counter can: the CV (coefficient of variation) is LOW on the
// axis carrying a hard threshold and HIGH on the other. Percentiles then give
// the order of magnitude. Together they replace the unverified 130-190s constant
// with something derived from this user's own network.
//
// Emits zeros when no pool is published or nothing has died yet — a scrape must
// never fail just because the sample is empty.
func emitSlotDeathDistribution(w io.Writer) {
	var s slotobs.Summary
	if pool := globalPoolForStatsPtr.Load(); pool != nil && pool.slotDeaths != nil {
		s = pool.slotDeaths.Summarize()
	}

	fmt.Fprintf(w, "# HELP shadowlink_slot_death_samples Slot deaths currently held in the observation ring (bounded; oldest overwritten).\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_death_samples gauge\n")
	fmt.Fprintf(w, "shadowlink_slot_death_samples %d\n", s.Count)

	fmt.Fprintf(w, "# HELP shadowlink_slot_death_age_ms Slot age at death, percentiles over the observation ring. p10 is the actionable one for a future rotation threshold (rotate before the EARLIEST deaths, not the median).\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_death_age_ms gauge\n")
	fmt.Fprintf(w, "shadowlink_slot_death_age_ms{quantile=\"0.1\"} %d\n", s.AgeP10)
	fmt.Fprintf(w, "shadowlink_slot_death_age_ms{quantile=\"0.5\"} %d\n", s.AgeP50)
	fmt.Fprintf(w, "shadowlink_slot_death_age_ms{quantile=\"0.9\"} %d\n", s.AgeP90)

	fmt.Fprintf(w, "# HELP shadowlink_slot_death_down_bytes Downlink bytes carried at death, percentiles. Compare against the ~16-20 KB volume trigger described by net4people#490.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_death_down_bytes gauge\n")
	fmt.Fprintf(w, "shadowlink_slot_death_down_bytes{quantile=\"0.1\"} %d\n", s.BytesP10)
	fmt.Fprintf(w, "shadowlink_slot_death_down_bytes{quantile=\"0.5\"} %d\n", s.BytesP50)
	fmt.Fprintf(w, "shadowlink_slot_death_down_bytes{quantile=\"0.9\"} %d\n", s.BytesP90)

	fmt.Fprintf(w, "# HELP shadowlink_slot_death_cv Coefficient of variation (stddev/mean) of slot deaths per axis. The LOWER axis is the one the censor keys on: a hard threshold clusters values on its own axis and scatters them on the other. Needs >=2 samples; 0 otherwise.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_death_cv gauge\n")
	fmt.Fprintf(w, "shadowlink_slot_death_cv{axis=\"age\"} %.6f\n", s.AgeCV)
	fmt.Fprintf(w, "shadowlink_slot_death_cv{axis=\"down_bytes\"} %.6f\n", s.BytesCV)

	fmt.Fprintf(w, "# HELP shadowlink_slot_death_by_close_kind Slot deaths by classified close shape. Separates middlebox teardown (close_other / reset) from our own read deadline (io_timeout) — needed so noise is not mistaken for censorship.\n")
	fmt.Fprintf(w, "# TYPE shadowlink_slot_death_by_close_kind gauge\n")
	// Фиксированный порядок меток: карта в Go итерируется случайно, а
	// нестабильный порядок строк ломает diff'ы и пин alert-правил на список.
	for _, kind := range frameAnomalyReasons {
		fmt.Fprintf(w, "shadowlink_slot_death_by_close_kind{kind=%q} %d\n", kind, s.ByCloseKind[kind])
	}
}

// StartStatsLogger launches a goroutine that logs counter deltas every
// interval until ctx is cancelled. Called from the client engine after
// Connect() succeeds so we don't log while the session is still coming up.
//
// First line after the first interval is `delta over N.Ns` so it's obvious
// the numbers are per-interval, not cumulative.
func StartStatsLogger(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	go func() {
		var (
			lastCover, lastUDP, lastWSNew, lastWSDie, lastPool int64
			lastEnc, lastDec, lastDecFail                      int64
			lastSocks, lastUp, lastDown                        int64
			lastWriterExits, lastReaderExits                   int64
			lastBypassMatch, lastBypassMiss                    int64
		)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			cover := Stats.CoverPosts.Load()
			udp := Stats.UdpPolls.Load()
			wsNew := Stats.WsCreated.Load()
			wsDie := Stats.WsDied.Load()
			pool := Stats.WsFromPool.Load()
			enc := Stats.Encrypts.Load()
			dec := Stats.Decrypts.Load()
			decFail := Stats.DecryptFails.Load()
			socks := Stats.SocksConnects.Load()
			up := Stats.UplinkBytes.Load()
			down := Stats.DownlinkBytes.Load()
			writerExits := Stats.WriterExits.Load()
			readerExits := Stats.ReaderExits.Load()
			bypassMatch := Stats.BypassMatchTotal.Load()
			bypassMiss := Stats.BypassMissTotal.Load()

			slog.Info("shadowlink client stats (delta)",
				"interval", interval,
				"cover_posts", cover-lastCover,
				"udp_polls", udp-lastUDP,
				"ws_created", wsNew-lastWSNew,
				"ws_died", wsDie-lastWSDie,
				"ws_from_pool", pool-lastPool,
				"encrypts", enc-lastEnc,
				"decrypts", dec-lastDec,
				"decrypt_fails", decFail-lastDecFail,
				"socks_connects", socks-lastSocks,
				"uplink_kb", (up-lastUp)/1024,
				"downlink_kb", (down-lastDown)/1024,
				"writer_exits", writerExits-lastWriterExits,
				"reader_exits", readerExits-lastReaderExits,
				"bypass_match", bypassMatch-lastBypassMatch,
				"bypass_miss", bypassMiss-lastBypassMiss,
			)

			lastCover, lastUDP, lastWSNew, lastWSDie, lastPool = cover, udp, wsNew, wsDie, pool
			lastEnc, lastDec, lastDecFail = enc, dec, decFail
			lastSocks, lastUp, lastDown = socks, up, down
			lastWriterExits, lastReaderExits = writerExits, readerExits
			lastBypassMatch, lastBypassMiss = bypassMatch, bypassMiss

			logSlotDeathSummary()
		}
	}()
}

// shouldWarnRotationBudget решает, печатать ли строку о дефиците бюджета.
//
// С 2026-08-10 эта строка идёт на уровне INFO, а не WARN: она утверждает
// прогноз (верхняя оценка ниже окна реза), а не наблюдённый отказ — см.
// обоснование замером на месте вызова. Имя функции сохранено, потому что
// смысл гейта не изменился: он про то, ЕСТЬ ли дефицит, а не про уровень
// логирования.
//
// Гейт обязан висеть на ОЧИЩЕННОМ минимуме (`v.AgeMinMs`) — тех же данных, из
// которых посчитан margin. Раньше здесь стоял СЫРОЙ `s.AgeMin > 0`, и это была
// ровно та болезнь H-15, от которой лечится соседний расчёт margin: в поле
// 2026-08-10 дефицит держался все 86 минут (последняя строка `slot death
// inference` в 17:20:48 печатает margin_to_age_min=-1m3.789s), но WARN замолчал
// на 20-й минуте. Причина — в 16:36:18 в сырую выборку попала смерть с age=0
// (`cause=natural`, close в момент подключения), сырой минимум стал 0 и заглушил
// предупреждение. Дефицит не исчез — о нём перестали говорить: 237 WARN вместо
// ~772 возможных.
//
// Вынесено в функцию, а не оставлено выражением в `if`, чтобы гейт был проверяем
// тестом отдельно от глобального пула и slog: молчащий контур наблюдаемости
// нельзя сторожить тестом, который его не вызывает.
func shouldWarnRotationBudget(ageMinCleanMs int64, margin time.Duration) bool {
	return ageMinCleanMs > 0 && margin <= 0
}

// Дросселирование строк о бюджете ротации по ИЗМЕНЕНИЮ СОСТОЯНИЯ (2026-08-13).
//
// Замер 2026-08-13 (2ч40м): 1782 строки «rotation budget below observed cut
// window» и 176 строк «upper bound is no longer an upper bound» — обе горели
// на каждом тике StartStatsLogger (5s). Оба гейта СРАБОТАЛИ КОРРЕКТНО:
// worstCaseTeardown()=142.5s против age_min_clean=82.59s, дефицит 59.91s —
// он структурный и в этой конфигурации неустранимый.
//
// Дефект не в гейте, а в том, что предупреждение, горящее ВСЕГДА, не несёт
// информации. Это H-15 наоборот: там контур молчал и это приняли за здоровье,
// здесь контур кричит непрерывно и это перестают читать. Ровно та же логика,
// по которой 2026-08-10 понижали прогноз до INFO (237 WARN за час на 0.07%
// реальных пробоев) и по которой дросселировали строку нехватки наблюдений
// (9563dad, 720 строк/час).
//
// Выбран троттлинг ПО ИЗМЕНЕНИЮ, а не по времени и не дедупликация:
//
//   - Дефицит меняется только когда меняется одно из слагаемых бюджета
//     (адаптер сжал порог, сменился stagger) или приехали новые наблюдения.
//     Это редкие события — в замере адаптер дал 11 изменений за 2ч40м.
//     Значит «логировать при изменении» даёт ~10-20 строк вместо 1782,
//     не теряя ни одного перехода.
//   - Троттлинг по времени (раз в N минут) сохранил бы шум пропорционально
//     длительности сессии и всё равно размывал бы момент перехода.
//   - Чистая дедупликация по тексту не сработала бы: в строке есть поля,
//     которые дрожат на каждом тике (age_min_raw, samples), — она бы
//     печаталась почти каждый раз.
//
// Порог значимости 5s: дефицит дрожит на сотни миллисекунд от переоценки
// перцентилей, и без него троттлинг выродился бы обратно в поток. 5s заметно
// меньше самого дефицита (59.91s в замере), то есть реальный сдвиг бюджета
// не будет проглочен.
//
// ⚠ Гейты НЕ удалены и НЕ ослаблены: условие срабатывания то же, меняется
// только частота печати. Первое срабатывание печатается всегда, возврат в
// норму — тоже (иначе исчезновение дефицита осталось бы незамеченным).
const rotationBudgetLogEpsilon = 5 * time.Second

// budgetLogThrottle хранит последнее НАПЕЧАТАННОЕ состояние одной строки.
// Не atomic: единственный вызывающий — goroutine StartStatsLogger, она одна.
type budgetLogThrottle struct {
	active bool          // печаталось ли, что состояние «плохое»
	value  time.Duration // величина, при которой печатали в последний раз
}

// shouldLog решает, печатать ли строку в этом тике.
//
// Печатаем, когда: (а) состояние сменилось (норма↔дефицит) либо (б) величина
// сдвинулась заметнее epsilon. Во всех остальных случаях состояние то же,
// что уже в логе, и повтор ничего не добавляет.
func (t *budgetLogThrottle) shouldLog(active bool, value, epsilon time.Duration) bool {
	if active != t.active {
		t.active = active
		t.value = value
		return true
	}
	if !active {
		return false
	}
	if d := value - t.value; d >= epsilon || d <= -epsilon {
		t.value = value
		return true
	}
	return false
}

// Состояние троттлинга живёт на уровне пакета, потому что logSlotDeathSummary
// вызывается из одной goroutine StartStatsLogger и не имеет своего объекта.
// Обнуление между сессиями не требуется: клиент — один процесс на сессию.
var (
	budgetDeficitThrottle budgetLogThrottle
	budgetReachedThrottle budgetLogThrottle
)

// logSlotDeathSummary emits the slot-death distribution to the log (раунд 18 P0).
//
// The Prometheus exporter (WritePromMetrics) is NOT reachable on the client — no
// call site anywhere in cmd/, so the linker drops it and the client exposes no
// /metrics endpoint at all. The stats logger is the only channel the client
// actually has, so the distribution goes here or it is unobservable. Without this
// the recorder would collect data nobody can read — the same silent-failure shape
// this audit round kept finding.
//
// Emitted as a snapshot (not a delta): percentiles and CV are properties of the
// whole window, and subtracting them between ticks is meaningless.
//
// Silent until there are at least minSlotDeathSamplesToLog observations. Below
// that the CV is noise, and printing it would invite reading a threshold off two
// data points — exactly the mistake this rework exists to prevent.
//
// ⚠ «Silent» относится ТОЛЬКО к распределению и выводу порога. Ниже порога
// функция всё равно печатает строку о нехватке данных и всё равно скармливает
// вердикт адаптеру — см. обоснование у раннего return.
func logSlotDeathSummary() {
	pool := globalPoolForStatsPtr.Load()
	if pool == nil || pool.slotDeaths == nil {
		return
	}
	s := pool.slotDeaths.Summarize()

	// Hazard — ДО гейта: его знаменатель составляют ПЛАНОВЫЕ ротации, а не резы,
	// поэтому к порогу minSlotDeathSamplesToLog он отношения не имеет. Порог
	// существует для CV и перцентилей смертей.
	//
	// Первая версия (e1f8c3c) ставила этот вызов ниже раннего return, и полевой
	// прогон 20260812-140930 это поймал: 6 резов против порога 12, 601 плановая
	// ротация — и ни одной строки `slot death hazard` за 1ч43м. То есть правка,
	// лечившая «величину заперли за недостижимым порогом», сама повторила этот
	// дефект. Гейт наблюдаемости обязан быть узким: он про доверие к перцентилям,
	// а не про право что-либо печатать.
	logSlotDeathHazard(pool)

	if s.Count < minSlotDeathSamplesToLog {
		// Нехватка данных — СОСТОЯНИЕ, о котором надо сказать, а не молчать.
		//
		// До 2026-08-12 здесь стоял голый `return`, и он глушил не только
		// печать, но и `ageAdapter.Observe` ниже — единственный вызов адаптера в
		// кодовой базе. Полевой прогон 20260812-110200 (1ч58м): 8 наблюдений
		// против порога 12, поэтому за весь прогон не напечатано ни одной строки
		// `slot death distribution`/`inference`, а адаптация порога per-AS не
		// исполнялась ни секунды. По логу это выглядело как здоровье.
		//
		// Хуже того, обратная связь отрицательная: чем лучше работает плановый
		// дренаж, тем меньше резов, тем дальше выборка от порога. Фикс фантомного
		// счётчика (2026-08-11) срезал резы с 10.2/ч до 4.1/ч и тем самым добил
		// наблюдаемость — контур ослеп именно потому, что транспорт починили.
		//
		// Поэтому: распределение и порог по-прежнему молчат (на 8 точках CV — это
		// шум), но факт нехватки, знаменатель из плановых ротаций и фактически
		// применённый порог печатаются. Читатель должен видеть «работаю на
		// конфиге, потому что данных нет», а не пустоту.
		applied, configured, changes, reason := pool.ageAdapter.Stats()
		cutShare, shareTotal := pool.slotDeaths.CutShare()

		// Дросселирование по ИЗМЕНЕНИЮ состояния.
		//
		// logSlotDeathSummary зовётся из StartStatsLogger каждые 5s
		// (engine_shadowlink.go:216). Безусловная печать дала бы 720 строк в час
		// при нехватке данных — ровно тот шум, от которого лечились в b0ad357:
		// «предупреждение, которое срабатывает на три порядка чаще
		// предсказанного отказа, читатель перестаёт читать — а это тот же H-15,
		// только через шум, а не через молчание». Повторить эту ошибку внутри
		// правки, которая лечит H-15 через молчание, было бы иронично.
		//
		// Ключ по (samples, applied): пока не появилось нового наблюдения и порог
		// не сдвинулся, повторять нечего. Оба слагаемых нужны — samples растёт
		// при новых резах, applied меняется при адаптации, и пропуск любого
		// скрыл бы содержательное событие.
		//
		// Порог печатается по ПЕРЕХОДУ, поэтому первый тик после старта всегда
		// говорит: нулевое состояние отличается от «ещё не печатали».
		// plannedBucket в ключе: без него строка молчит, пока идут ТОЛЬКО плановые
		// ротации, — а `planned_rotations` и есть то число, которое объясняет,
		// почему резов мало. При 740 плановых и неизменных 8 резах читатель иначе
		// увидел бы одну строку и больше ничего, хотя знаменатель растёт.
		// Округление до сотен, чтобы не вернуть шум: печатаем на каждую сотню
		// плановых, а не на каждую.
		totalPlanned := pool.slotDeaths.TotalPlanned()
		key := insufficientSamplesKey{
			samples:       s.Count,
			applied:       applied,
			plannedBucket: totalPlanned / 100,
		}
		if pool.lastInsufficientLog.Swap(key) != key {
			totalCuts := pool.slotDeaths.Total()
			// Две доли, потому что это ДВЕ РАЗНЫЕ величины, и по имени `cut_share`
			// их не различить (ревью 2026-08-12).
			//
			// cut_share_lifetime — по пожизненным счётчикам, несмещённая.
			// cut_share_ring — по содержимому рингов; смещена при переполнении,
			// потому что ринги конечны и заполняются с разной скоростью. В поле
			// это 1.54% против истинных 1.07%, разница в 1.44 раза.
			//
			// Раньше печаталась только вторая, под нейтральным именем, рядом с
			// несмещённым planned_rotations — читатель не понимал, почему 8/748
			// не сходится с показанным числом.
			var lifetimeShare float64
			if totalCuts+totalPlanned > 0 {
				lifetimeShare = float64(totalCuts) / float64(totalCuts+totalPlanned)
			}
			// Бюджет печатается ЗДЕСЬ ТОЖЕ, а не только в полной сводке ниже
			// (ревью 2026-08-14, D2).
			//
			// Дефект, который это лечит: worst_case_teardown и его слагаемые жили
			// исключительно в строке «slot death inference», а та выходит лишь при
			// samples >= 12. Резов в прогоне 2026-08-14 не было вовсе → samples=0 →
			// строка молчала 3 часа, и правка бюджета (sweep = 2×tick) оказалась
			// НЕПРОВЕРЯЕМОЙ замером. Тот же контур, что уже описан для адаптера:
			// чем лучше работает порог, тем меньше видно и порог, и бюджет.
			//
			// Бюджет не зависит от выборки — он считается из конфигурации, — поэтому
			// прятать его за гейтом наблюдений было ошибкой категории.
			bBase, bStagger, bSweep, bDeferred, bTear, bTotal := pool.worstCaseTeardown()
			slog.Info("slot death observability: insufficient samples — adapter on configured threshold",
				"samples", s.Count,
				"required", minSlotDeathSamplesToLog,
				"total_deaths", totalCuts,
				"planned_rotations", totalPlanned,
				"cut_share_lifetime", fmt.Sprintf("%.4f", lifetimeShare),
				"cut_share_ring", fmt.Sprintf("%.4f", cutShare),
				"cut_share_ring_denom", shareTotal,
				"applied_max_slot_age", applied,
				"configured_max_slot_age", configured,
				"adapt_changes", changes,
				"adapt_reason", reason,
				// Слагаемые порознь: суммой одна ошибка в слагаемом неотличима от
				// другой, а именно так и родился H-15.
				"budget_base", bBase,
				"stagger_span", bStagger,
				"sweep_budget", bSweep,
				"sweep_tick", rotationWatchdogTick,
				"defer_backoff", bDeferred,
				"teardown_cap", bTear,
				"worst_case_teardown", bTotal,
				// ⚠ Запаса до окна реза здесь НЕТ намеренно: он требует
				// age_min_clean из выборки, которой в этой ветке недостаточно.
				// Печатать его с нулём значило бы показать «дефицит 142.5s»
				// (величина бюджета в проде; до джиттера свипа была 141.5s).
				"margin_to_age_min", "n/a (insufficient samples)",
			)
		}

		// Адаптер зовётся и здесь: на недостаточной выборке Infer вернёт
		// AxisUnknown, а Observe на AxisUnknown сбрасывает счётчик подтверждений.
		// Пропуск вызова оставил бы кандидата «подвешенным» между прогонами —
		// подтверждения копились бы через произвольные промежутки времени, что
		// ровно противоречит смыслу гистерезиса.
		pool.ageAdapter.Observe(pool.slotDeaths.InferWithMinAge(pool.ageCutFloor().Milliseconds()))
		return
	}

	// Which axis clusters tighter is THE question: a hard threshold produces a
	// tight cluster on its own axis and scatter on the other. Reported as a plain
	// label so the log line is readable without doing the comparison by hand —
	// but it is a hint, not a verdict (see slotobs docs).
	axisHint := "inconclusive"
	switch {
	case s.AgeCV > 0 && s.BytesCV > 0 && s.AgeCV*2 < s.BytesCV:
		axisHint = "age"
	case s.AgeCV > 0 && s.BytesCV > 0 && s.BytesCV*2 < s.AgeCV:
		axisHint = "down_bytes"
	}

	slog.Info("slot death distribution (snapshot)",
		"samples", s.Count,
		"total_deaths", pool.slotDeaths.Total(),
		"age_min_ms", s.AgeMin, // сырой: включает шум, для чтения человеком
		"age_p10_ms", s.AgeP10,
		"age_p50_ms", s.AgeP50,
		"age_p90_ms", s.AgeP90,
		"down_p10_kb", s.BytesP10/1024,
		"down_p50_kb", s.BytesP50/1024,
		"down_p90_kb", s.BytesP90/1024,
		"cv_age", fmt.Sprintf("%.4f", s.AgeCV),
		"cv_down_bytes", fmt.Sprintf("%.4f", s.BytesCV),
		"tighter_axis", axisHint,
		"by_close_kind", s.ByCloseKind,
	)

	// Вывод порога (P0 шаг 2). Отдельной строкой, потому что это ВЫВОД с
	// допущениями, а не описание данных: их надо читать раздельно. Инференс
	// отсеивает шум (age=0, closed_local, io_timeout), поэтому его `samples`
	// меньше, чем в сводке выше — по этой разнице видно, сколько отброшено.
	//
	// НИЧЕГО не применяет: ротацией по-прежнему управляют maxSlotAge /
	// stickyMaxDrainAge. Автоприменение — шаг 3, и оно требует гистерезиса,
	// иначе порог будет дёргаться на каждой смене сети.
	// Порог «слишком молодой слот» — тот же ageCutMinAge, по которому клиент
	// классифицирует age-cut. Передаём его, а не заводим копию в slotobs: две
	// правды об одном пороге разъедутся при первой же правке.
	v := pool.slotDeaths.InferWithMinAge(pool.ageCutFloor().Milliseconds())

	// P0 шаг 3: скармливаем вердикт адаптеру. Он сам решает, менять ли порог —
	// требует подтверждений, только сжимает, держит пол и гистерезис.
	changed := pool.ageAdapter.Observe(v)
	adaptedAge, configuredAge, adaptChanges, adaptReason := pool.ageAdapter.Stats()

	// worst_case_teardown берётся из pool.worstCaseTeardown() — единственного
	// источника истины. До 2026-08-07 здесь стояло `adaptedAge + stickyMaxDrainAge`,
	// и эта строка ВРАЛА: она не знала про stagger (до +48s) и про тик watchdog
	// (+5s), а из двух teardown-пределов брала не тот. При stagger cap=45s
	// реальный worst-case был 129s против напечатанных 84s — полтора раза.
	// Именно это расхождение скрыло, что 15 ячеек из 16 ротируются позже
	// медианы смертей.
	wcBase, wcStagger, wcSweep, wcDeferred, wcTear, wcTotal := pool.worstCaseTeardown()

	// Запас до самой ранней смерти. Отрицательный = худшая ячейка гарантированно
	// не доживает до своей ротации, её рвёт посредник.
	//
	// Берём v.AgeMinMs (ОЧИЩЕННАЯ выборка), а не s.AgeMin (сырая): 2026-08-07
	// сырой минимум оказался 2 мс — это `close 1000 (normal)` при старте слота,
	// а не рез. Сравнение бюджета с таким «минимумом» давало −2m24s дефицита и
	// обесценивало WARN. Минимум обязан быть из тех же данных, что и порог.
	var wcMargin time.Duration
	if v.AgeMinMs > 0 {
		wcMargin = time.Duration(v.AgeMinMs)*time.Millisecond - wcTotal
	}

	slog.Info("slot death inference",
		"axis", v.Axis.String(),
		"threshold_age", v.Threshold.Age,
		"threshold_bytes", v.Threshold.Bytes,
		"samples_used", v.Samples,
		"rejected_zero_age", v.Rejected.ZeroAge,
		"rejected_local_close", v.Rejected.LocalClose,
		"rejected_timeout", v.Rejected.Timeout,
		"rejected_too_young", v.Rejected.TooYoung,
		// rejected_planned в норме 0. Ненулевое = плановая ротация попала в ринг
		// резов (перепутаны Record/RecordPlanned), и это надо ВИДЕТЬ: иначе
		// наблюдения тихо исчезают из samples_used, а разницу со `samples` в
		// сводке объяснят чем угодно. Поле заведено ради этого сигнала —
		// не печатать его значило бы завести молчащий гейт (ревью 2026-08-12).
		"rejected_planned", v.Rejected.Planned,
		"applied_max_slot_age", adaptedAge,
		"configured_max_slot_age", configuredAge,
		"adapt_changes", adaptChanges,
		"sticky_max_drain", pool.stickyMaxDrainAge,
		"drain_hard_cap", pool.drainHardCap,
		"stagger_span", wcStagger,
		"effective_max_age_max", wcBase+wcStagger,
		// ⚠ Имя переименовано 2026-08-14 из `sweep_tick`. Слагаемое не равно
		// одному тику: тик расходуется ДВАЖДЫ (обнаружение + повторная попытка
		// после отсрочки гейта, см. worstCaseTeardown). Оставить прежнее имя
		// значило бы завести ровно тот дефект, который проект собирает пачками —
		// поле, чьё имя врёт о механизме. Сам тик печатается рядом, чтобы
		// величину можно было разложить, не читая код.
		"sweep_budget", wcSweep,
		"sweep_tick", rotationWatchdogTick,
		"defer_backoff", wcDeferred,
		"teardown_cap", wcTear,
		"worst_case_teardown", wcTotal,
		"age_min_clean_ms", v.AgeMinMs,
		"margin_to_age_min", wcMargin,
		"reason", v.Reason,
	)

	// Отрицательный запас — уровень INFO, не WARN (понижено 2026-08-10 по
	// замеру двух полевых прогонов).
	//
	// Строка утверждает ПРОГНОЗ: «худшая ячейка не доживёт до плановой
	// ротации». Прогноз верен арифметически, но описывает верхнюю оценку,
	// которая почти не достигается. Восстановленные из логов полные времена
	// жизни TCP (n=793 и n=560, два прогона по часу):
	//
	//	p50 79.7 / 84.1s   p90 104.6 / 104.7s   p99 114.7 / 114.7s
	//	max 143.2 / 124.6s — граница 141.5s пробита 1 раз из 1353 (0.07%)
	//
	// Смена слотов: 95–96% плановый дренаж, 4–5% рез посредником; цена реза —
	// fast age-cut reconnect ~0.8s, meltdowns_1m=0, decrypt_fails=0 весь
	// прогон. При этом WARN звучал 237 и 523 раза за час. Предупреждение,
	// которое срабатывает на три порядка чаще предсказанного отказа, читатель
	// перестаёт читать — а это тот же H-15, только через шум, а не через
	// молчание.
	//
	// Слагаемые остаются в строке: они и есть содержательная часть — по ним
	// видно, что накладные (stagger+sweep+defer+tear = 75.5s) сами по себе
	// сопоставимы с окном реза 84–118s, то есть дефицит структурный, а не
	// следствие плохой настройки.
	// ⚠ Дросселирование 2026-08-13: гейт тот же, печать — только при СМЕНЕ
	// состояния или сдвиге дефицита больше epsilon. В замере 2026-08-13 эта
	// строка дала 1782 повтора за 2ч40м при неизменном структурном дефиците
	// 59.91s — предупреждение, горящее всегда, читатель перестаёт читать.
	// Подробное обоснование выбора именно троттлинга — у budgetLogThrottle.
	deficitActive := shouldWarnRotationBudget(v.AgeMinMs, wcMargin)
	if budgetDeficitThrottle.shouldLog(deficitActive, -wcMargin, rotationBudgetLogEpsilon) {
		if deficitActive {
			slog.Info("rotation budget below observed cut window (upper-bound estimate, not an observed failure)",
				"worst_case_teardown", wcTotal,
				"age_min_clean", time.Duration(v.AgeMinMs)*time.Millisecond,
				"age_min_raw", time.Duration(s.AgeMin)*time.Millisecond,
				"deficit", -wcMargin,
				"base", wcBase,
				"stagger_span", wcStagger,
				// Как и в сводке выше: величина = тик + подтиковое
				// размазывание фазы, поэтому имя не `sweep_tick`.
				"sweep_budget", wcSweep,
				"defer_backoff", wcDeferred,
				"teardown_cap", wcTear,
				// Явный маркер, что строка дросселирована: иначе читатель,
				// увидев ОДНУ строку вместо потока, решит, что событие было
				// однократным. Молчание должно быть объяснимым.
				"throttled", "logged on change only",
			)
		} else {
			// Возврат в норму печатаем обязательно: без этого исчезновение
			// дефицита осталось бы невидимым, и последняя строка в логе
			// навсегда осталась бы тревожной.
			slog.Info("rotation budget deficit cleared",
				"worst_case_teardown", wcTotal,
				"margin_to_age_min", wcMargin,
			)
		}
	}

	// А вот ФАКТ — уровень WARN: наблюдённая жизнь слота дошла до бюджета,
	// то есть верхняя оценка перестала быть верхней.
	//
	// Сравниваем с AgeP90, а не с максимумом: максимума в Summary нет, а p90
	// устойчив к единичному выбросу — один длинный слот не поднимает панику,
	// а систематический сдвиг хвоста поднимает. Замер 2026-08-10 показывает,
	// какой это порог по факту: p90 = 104.6 и 104.7s против бюджета 141.5s,
	// то есть в норме условие НЕ выполняется и строка молчит. Сработает она,
	// когда хвост реально подъедет к бюджету — а это и есть тот случай, когда
	// сумму слагаемых нужно пересматривать.
	//
	// Выборка censored (Record зовётся только на ошибке чтения, плановые
	// ротации не попадают), поэтому p90 здесь — по СМЕРТЯМ, а не по всем
	// слотам; это смещает оценку вниз, то есть в сторону молчания. Строка
	// сознательно консервативна: ложная тревога здесь дороже пропуска, ради
	// этого и понижали соседний прогноз до INFO.
	// ⚠ Дросселирование 2026-08-13: 176 повторов за 2ч40м. См. budgetLogThrottle.
	//
	// ⚠ И ОГОВОРКА О САМОЙ ВЕЛИЧИНЕ (замер 2026-08-13). observed_age_p90
	// приколот к нашему же MAX_SLOT_AGE: при пороге 150s он дал 150.8s, то
	// есть повторил кап, а не описал цензора. Сравнивать worst_case с
	// величиной, ограниченной сверху нашим собственным капом, — сомнительно:
	// при достаточно высоком пороге p90 подойдёт к бюджету механически, без
	// какого-либо изменения поведения сети.
	//
	// Почему гейт всё же ОСТАВЛЕН как есть, а не «починен» подстановкой другой
	// величины: он ловит ровно то, что заявляет — «верхняя оценка перестала
	// быть верхней». Если наблюдённые времена жизни дошли до расчётного
	// worst-case, сумма слагаемых требует пересмотра НЕЗАВИСИМО от того, кто
	// поставил потолок — цензор или мы сами. Подмена p90 на величину «из
	// резов» сузила бы гейт до цензурированной выборки (Record зовётся только
	// на ошибке чтения) и вернула бы тот же survivorship bias, из-за которого
	// уже дважды неверно оценили окно.
	//
	// Правка тут была бы правкой ТАЙМИНГОВОЙ СЕМАНТИКИ по рассуждению, без
	// замера, — ровно то, что запрещает CLAUDE.md rule 8. Вместо этого
	// ограничение сделано ВИДИМЫМ в самой строке (поле observed_p90_capped_by),
	// чтобы читатель не принял совпадение p90 с капом за сигнал о сети.
	// Развязать по-честному можно только сравнением с временами жизни ПЛАНОВЫХ
	// ротаций (slotobs.RecordPlanned), у которых знаменатель не цензурирован, —
	// это отдельная работа со своим замером.
	if s.AgeP90 > 0 && wcTotal > 0 {
		observed := time.Duration(s.AgeP90) * time.Millisecond
		reached := observed >= wcTotal
		if budgetReachedThrottle.shouldLog(reached, observed-wcTotal, rotationBudgetLogEpsilon) && reached {
			slog.Warn("rotation budget reached by observed slot lifetimes — upper bound is no longer an upper bound",
				"observed_age_p90", observed,
				"worst_case_teardown", wcTotal,
				"excess", observed-wcTotal,
				"samples", s.Count,
				// Потолок наблюдаемого p90 — наш собственный порог ротации.
				// Если observed_age_p90 примерно равен ему, строка говорит о
				// НАШЕЙ политике, а не о поведении сети (замер 2026-08-13:
				// при пороге 150s p90=150.8s).
				"observed_p90_capped_by", adaptedAge,
				"throttled", "logged on change only",
			)
		}
	}

	// Изменение порога — отдельной строкой на уровне WARN: это смена поведения
	// транспорта, её нельзя терять в потоке INFO при разборе инцидента.
	if changed {
		// worst_case_teardown берётся из уже посчитанного wcTotal — того же
		// единственного источника истины, что и строка выше. До 2026-08-10 здесь
		// стояло `adaptedAge + pool.stickyMaxDrainAge`: ровно наивная формула,
		// которую признали ложью и убрали 60 строками выше, но в этой строке она
		// пережила правку. В поле обе строки печатались в ОДНУ секунду и
		// противоречили друг другу — 1m32s против 2m30.5s, расхождение 58.5s.
		// При разборе инцидента читатель верит той, что попалась первой.
		slog.Warn("rotation threshold adapted",
			"applied", adaptedAge,
			"configured", configuredAge,
			"changes_total", adaptChanges,
			"worst_case_teardown", wcTotal,
			"reason", adaptReason,
		)
	}
}

// minSlotDeathSamplesToLog is the floor below which the distribution stays
// unlogged. 12 is well short of a statistically comfortable sample but enough
// that a CV comparison is not pure noise; the log line carries `samples` so the
// reader can judge for themselves.
// logSlotDeathHazard печатает hazard-кривую — риск реза среди ДОЖИВШИХ до
// каждой полосы возраста.
//
// Почему это отдельная строка, а не поле в inference: hazard отвечает на другой
// вопрос. Перцентили смертей говорят «где умирают», и ответ смещён нашей же
// политикой ротации (survivorship bias). Именно на этом сгорел разбор
// 2026-08-12: p50 по 7 резам дал 85с против 97.6с по 222, и это прочли как
// «окно сжалось», хотя в том прогоне ни одно соединение не жило дольше 104.5с —
// посредник физически не мог показать рез на 110с. Hazard делит на число
// дошедших и потому от политики зависит слабее.
//
// Выводится в лог, а не остаётся вычислимой величиной: до ревью 2026-08-12
// slotobs.Hazard не вызывалась нигде в проде, при том что SKILL.md уже подал
// hazard-кривую как «правильную величину» и на этом основании отменил прежнюю
// оценку окна. Величина, которую никто не читает, — не наблюдаемость.
//
// Полосы строятся вокруг ageCutFloor: ниже него рез по нашей же модели не
// считается age-cut, поэтому смотреть там нечего.
func logSlotDeathHazard(pool *WSPoolTransport) {
	if pool == nil || pool.slotDeaths == nil {
		return
	}
	// Молчим, пока нет ни одного наблюдения хоть в одном ринге: пустая кривая
	// из одних нулей читается как «риска нет», а это не то же, что «нет данных».
	if pool.slotDeaths.Len() == 0 && pool.slotDeaths.LenPlanned() == 0 {
		return
	}

	// Дроссель: кривая меняется только при новых наблюдениях, а зовут нас каждые
	// 5s. Без этого перенос вызова выше гейта дал бы 720 строк/час — тот шум,
	// который лечили в 9563dad. Ключ — пара пожизненных счётчиков: любое новое
	// наблюдение в любом ринге меняет кривую, отсутствие новых не меняет ничего.
	// Резы — по сырому счётчику: их единицы за прогон, и каждый меняет кривую
	// содержательно. Плановые — бакетом по 100: их сотни, и печатать на каждую
	// значило бы вернуть шум с другой стороны.
	hkey := hazardLogKey{
		cuts:          pool.slotDeaths.Total(),
		plannedBucket: pool.slotDeaths.TotalPlanned() / 100,
	}
	if pool.lastHazardLog.Swap(hkey) == hkey {
		return
	}

	floorMs := pool.ageCutFloor().Milliseconds()
	if floorMs <= 0 {
		floorMs = 30_000
	}

	attrs := []any{
		"band_width_ms", hazardBandWidthMs,
		"floor_ms", floorMs,
	}
	ringSaturated := false
	for i := 0; i < hazardBandCount; i++ {
		from := floorMs + int64(i)*hazardBandWidthMs
		h := pool.slotDeaths.Hazard(from, from+hazardBandWidthMs)
		// Пустые полосы не печатаем: нули без знаменателя — это шум, который
		// читается как «риск нулевой».
		if h.Reached == 0 {
			continue
		}
		// Печатаем ОБЕ величины и экспозицию.
		//
		// rate_exp (1/с) — не смещена ЦЕНЗУРИРОВАНИЕМ: резы делятся на фактически
		// прожитое в полосе время. rate_act — прежняя actuarial-форма, оставлена
		// только для сравнимости со старыми логами; в нашей конфигурации она
		// ЗАНИЖАЕТ вдвое, потому что цензурирование сидит у нижней кромки полосы
		// (порог ротации 70s+stagger → плановые умирают на 74-80s). Замер
		// 2026-08-14 для полосы 80-85s: rate_act 3.37% против p_pass 6.94%.
		//
		// p_pass — вероятность реза при проходе полосы ЦЕЛИКОМ (1-exp(-rate*width)).
		// Именно её сравнивают с «hazard N%» из разборов. ⚠ Не путать с Cut/Reached:
		// та величина — доля на ВХОД в полосу, и при экспозиции 0.2s даёт 2.1%
		// там, где p_pass даёт 6.94%. Подмена этих единиц уже приводила к неверному
		// выводу (разбор 2026-08-14).
		//
		// ⚠ Поле reached читать буквально нельзя: это «записей осталось в ринге»,
		// а не «соединений дошло». При ring_saturated=true ринги набирались окнами
		// разной длины, и смещена ЛЮБАЯ доля, включая rate_exp — у него обрезается
		// знаменатель. В PROBE 2026-08-13 это дало завышение ×2.06. С 2026-08-14
		// ринг плановых вмещает PlannedCapacity=4096 (~13ч), поэтому в обычном
		// прогоне флаг должен быть false; true = прогон длиннее ринга.
		//
		// exposure_s == 0 при cut > 0 означает рез ровно на входе в полосу:
		// rate_exp тогда 0, и это «нет данных», а не «нет риска» (см. Hazard).
		bandWidthSec := float64(hazardBandWidthMs) / 1000
		rateExp := h.RateByExposure()
		attrs = append(attrs,
			fmt.Sprintf("band_%d_%d", from/1000, (from+hazardBandWidthMs)/1000),
			fmt.Sprintf("reached=%d cut=%d censored_in=%d exposure_s=%.1f "+
				"rate_exp=%.5f p_pass=%.4f rate_act=%.4f",
				h.Reached, h.Cut, h.CensoredIn,
				float64(h.ExposureMs)/1000, rateExp,
				1-math.Exp(-rateExp*bandWidthSec), h.Rate()),
		)
		if h.RingSaturated {
			ringSaturated = true
		}
	}
	// Насыщение печатаем ОДИН раз на строку, а не полем в каждой полосе: оно
	// свойство рингов, а не полосы. Молча пропустить нельзя — читатель принял бы
	// смещённые доли за наблюдение (урок PROBE 2026-08-13).
	attrs = append(attrs, "ring_saturated", ringSaturated)
	if ringSaturated {
		attrs = append(attrs,
			"ring_warning", "ring full: numerator and denominator span different windows, ratios biased",
			"cuts_lifetime", pool.slotDeaths.Total(),
			"planned_lifetime", pool.slotDeaths.TotalPlanned(),
		)
	}
	slog.Info("slot death hazard (risk among survivors)", attrs...)
}

// hazardLogKey — состояние, при неизменности которого hazard-кривую повторять не
// нужно. Резы по сырому счётчику (их единицы), плановые бакетом по 100 (их сотни).
type hazardLogKey struct {
	cuts          uint64
	plannedBucket uint64
}

const (
	// hazardBandWidthMs — ширина полосы hazard-кривой. 5s: в поле риск удваивался
	// примерно на таком шаге, более узкие полосы дают единичные знаменатели.
	hazardBandWidthMs = 5_000
	// hazardBandCount — сколько полос строить от ageCutFloor вверх. 16×5s = 80s
	// сверху floor'а покрывает наблюдённый диапазон жизни слота с запасом.
	hazardBandCount = 16
)

const minSlotDeathSamplesToLog = 12

// insufficientSamplesKey — состояние, при неизменности которого строку о
// нехватке наблюдений повторять не нужно (см. место использования).
//
// Comparable-структура, а не строка: сравнение по значению даёт atomic.Pointer
// семантику «изменилось ли состояние» без форматирования на каждом тике.
type insufficientSamplesKey struct {
	samples int
	applied time.Duration
	// plannedBucket — TotalPlanned/100. Без него строка молчала бы, пока идут
	// только плановые ротации, то есть скрывала бы рост знаменателя. Бакет, а не
	// сырое число, чтобы не печатать на каждую плановую ротацию.
	plannedBucket uint64
}

// Состояние дросселирования живёт НА ПУЛЕ (WSPoolTransport.lastInsufficientLog),
// а не в пакетной переменной.
//
// Сначала было сделано пакетной переменной с рассуждением «при пересоздании пула
// сброс не нужен, у нового рекордера счётчик нулевой». Рассуждение неверное:
// нулевое состояние нового пула может СОВПАСТЬ с последним напечатанным для
// старого, и тогда первая строка после реконнекта пропадёт — то есть ровно в
// момент, когда наблюдаемость нужнее всего.
//
// Обнаружено тестом: TestSlotDeathGate_InsufficientLineIsThrottled проходил в
// изоляции и падал в наборе, потому что ключ протекал между тестами через
// пакетную переменную. Тот самый класс, о котором предупреждает skill
// testing-rules — «зелёный при -count=1, красный в наборе — это почти всегда
// общее состояние, а не флейк железа». Здесь общее состояние было и в проде.
