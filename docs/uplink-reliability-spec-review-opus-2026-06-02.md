# Critical spec review — Uplink reliability (tail-resend on slot death)

**Reviewer:** senior eng (opus), adversarial pre-implementation review
**Date:** 2026-06-02
**Spec under review:** `docs/superpowers/specs/2026-06-02-uplink-reliability-design.md`
**Recon:** `docs/uplink-reliability-design-recon-2026-06-02.md`
**Trace:** `docs/bug9-uplink-resend-trace-2026-06-02.md`
**Code read at review time:** `core/chunk.go`, `core/session.go`, `server/relay_registry.go`,
`server/websocket.go` (uplink recv 805-861, ack recv 1300-1344), `proxy/socks5/tcp.go` (uplink
goroutine 845-928, downlink loop 930-1044), `client/migrate_send.go` (barrier 188-282),
`client/migrate_watchdog.go` (migrateStream/rebindStreamToSlot 224-361),
`client/ws_pool.go` (demux 3220-3293, resumeStreamOnDeath 3690-3727), `client/split_transport.go`
(StreamSession 120-126), `client/client.go` (SendStreamAckThrottled 1107-1131).

---

## VERDICT: **NEEDS-REVISION**

The spec mirrors the downlink mechanism at the right level and the wire-format reuse is sound.
But it is **wrong on its single most load-bearing premise** — it asserts the symptom is uplink
*loss* and prescribes a tail-resend that, as designed, would write **reordered / interleaved**
uplink bytes straight into the origin socket with no reassembler, **corrupting** the byte stream
it is meant to protect. There are 3 BLOCKERs that will break the feature or production. The
spec must be revised (especially Risks 1, 5, 6) before a plan is written.

A second, strategic concern: the trace doc (`bug9-uplink-resend-trace`) explicitly concludes
**"клиент НЕ переотправляет uplink — чанк ПОТЕРЯН, а не продублирован"** is *unproven by
instrument*, and its TL;DR names **application-level retry on a NEW streamID** (§5-д) as the
*most likely* explanation for the 1 MB uplink. The spec acknowledges this ("Риск принят явно")
but then builds a large client+server+wire feature on the weaker of the two hypotheses without
the cheap DEBUG measurement the trace already specified. See HIGH-1.

---

## BLOCKERs (break the feature or production)

### BLOCKER-1 — No uplink reassembler on the server: resend will CORRUPT the origin byte stream

This is the spec's fatal architectural gap and it directly answers the task's Risk 5.

**Downlink is safe because the client has a reassembler** (`proxy/socks5/tcp.go`
`downlinkReassemblyLoop` + `reassembler.push`, dedup/reorder by `seq < expectedSeq`). Reordered
or duplicated downlink frames are buffered and re-sequenced *before* `conn.Write` to the app.

**Uplink has NO such stage.** The server writes uplink **directly** into the origin TCP socket:
- local fast path: `streams[streamID].Write(payload)` (`websocket.go:826`)
- migrated path: `entry.tc.Write(payload)` (`websocket.go:856`)

The spec's only ordering defense is a high-water dedup: "`upSeq <= lastUpSeq → drop`"
(spec §"server uplink-приём"). A high-water counter **cannot reorder** — it can only drop a
*prefix*. If frame N+1 arrives before frame N, the dedup test `N+1 <= lastUpSeq(=N-1)` is **false**,
so N+1 is written to origin **immediately and out of order**, then N arrives and is also written.
Result: `...N+1, N...` in the origin socket = a corrupted request body. For TLS-over-tunnel
(every real stream) this is an instant `decrypt_failure` / broken request — the exact failure
class Bug #8 fought on downlink.

**Can N+1 actually precede N?** The recon (§"Concurrency note") and `websocket.go:845-854`
argue NO, because `WaitStreamMigrateBarrier` serializes uplink onto one slot at a time so "the
client never writes uplink on slot A and slot B concurrently." **That argument does not cover the
resend.** The resend (spec §3c) re-sends the unacked tail onto the NEW slot *after* the barrier
clears. But frames already in flight on the dying slot A may still be sitting in A's nginx/CF
buffer or the server's WS read queue and get delivered to the server **after** the resend frames
on slot B were already written to origin. Two independent TCP/WS paths (dead-but-draining A,
live B) have **no ordering guarantee** between them. The barrier only gates the *client's*
write ordering; it says nothing about server-side *arrival* ordering across two sockets. So
A-tail-frame `k` can land at the server *after* B-resend-frame `k+3` — high-water dedup writes
`k+3` then **drops** `k` (k <= lastUpSeq now), permanently losing it. Either way: corruption or
loss.

The existing test `TestE2E_UplinkAfterMigration_NoByteLoss` does **not** catch this — it tests a
graceful MIGRATE where slot A is still alive (recon §5), i.e. no two-paths-in-flight race.

**Required revision:** uplink under migration needs **server-side resequencing**, symmetric to
the client's downlink reassembler — buffer out-of-order upSeq frames keyed per relayEntry, write
to `entry.tc` strictly in upSeq order, drop `upSeq < expectedUpSeq`. A bare high-water dedup is
*insufficient and unsafe*. This is the single biggest design change the spec is missing.

### BLOCKER-2 — Client uplink seq is per-SESSION, not per-stream; resend re-encrypts under a NEW session

This is the task's Risk 1, and the code confirms the hole is real and worse than the spec implies.

The spec says "монотонный upSeq" but never says where the counter lives. The recon (§3a) says to
add "the next per-stream upSeq". But the **application-level dedup key the spec proposes** (`upSeq`
in the seq-tagged data payload, mirroring downlink's `downSeq`) must be **per-stream and
slot-independent**, exactly like the server's `downSeqCounter` which "**NEVER reset on
reassociate**" (`relay_registry.go:121`). The spec does not state this invariant for the client
side, and the surrounding code makes the wrong choice the *default*:

- Today uplink uses `uplinkSession.NextSeqNum()` (`tcp.go:916`) = the **per-slot session**
  `sendSeq` (`core/session.go:161`). The crypto session is **per-slot, not per-stream nor
  per-client** (confirmed: `bug9-stream-migration-design.md` §4 "крипто-сессия per-slot";
  `StreamSession` → `SessionForStream` → `slots[idx].session`). After migration the uplink
  goroutine re-resolves `uplinkSession` to the **new slot's** session (`tcp.go:912-913`), whose
  `sendSeq` is an **independent counter starting from its own handshake** — it has no relationship
  to the old slot's seq.

- So if the implementer naively "tags upSeq with `uplinkSession.NextSeqNum()`" (the obvious local
  read), the resent tail re-encrypted under the new slot's session would carry **new-slot session
  seqs**, which (a) do not match the upSeqs already recorded in `unackedUpTail`, and (b) are not
  monotonic across the migration boundary → server high-water dedup desyncs immediately.

**Required revision:** the spec must explicitly mandate a **dedicated per-stream `upSeqCounter`**
(client-side, on the per-stream state, NOT `session.sendSeq`), monotonic across migration, mirror
of server `downSeqCounter`. The transport-layer `chunk.SeqNum` (session anti-replay seq) stays
separate and per-slot. The recon hints at this ("the client assigns the seq for uplink") but the
spec body does not pin the invariant, and `NextSeqNum()` is a trap sitting right there in the code
the implementer will copy. Pin it or the dedup is built on sand.

### BLOCKER-3 — UplinkAck loss → permanent uplink stall (no ack retransmit / no resume-time resync)

This is the task's Risk 3 and it is a genuine liveness bug as specified.

The spec puts the client into hard backpressure: "при полном `unackedUpTail` блокировать
`conn.Read`" (§2). The buffer only frees on `FlagUplinkAck` (§3 demux → `evictUpTo`). But the
UplinkAck rides the **same WS slot that TSPU is cutting** (it is enqueued on the active binding's
writer, recon §1a-в). Under the field condition that motivates this whole feature — a slot cut
every 10-30s — the ack is exactly as likely to die with the slot as the data was.

If the final UplinkAck before a cut is lost:
- server `lastUpSeq` is advanced (it wrote to origin), but the client never hears it;
- client's `unackedUpTail` keeps those frames forever;
- on the next fill, `conn.Read` blocks (backpressure) and **never unblocks** → the app's TCP
  send window collapses → the stream hangs. **This reproduces the original symptom** (Claude Code
  "думал и не ответил") via a *different* mechanism the fix itself introduces.

**How downlink avoids this (the spec should have copied this and didn't):**
1. The downlink ack (`FlagStreamAck`) is **resent on every reassembler flush**, throttled
   (`SendStreamAckThrottled`, `tcp.go:1016`) — it is *idempotent and repeated*, not one-shot, so a
   lost ack is recovered by the next flush ("a dropped ack is recovered by the next flush",
   `client.go:1119`).
2. On `MIGRATE_OK` the server returns `resumeDownSeq` (`BuildMigrateOK`, `core/chunk.go:435`) so
   the client *resynchronizes* the high-water at resume.

The uplink design has **neither**: a single throttled ack with no flush-driven repeat (the server
only writes-then-acks; there is no periodic "I'm at upSeq=X" heartbeat), and the recon explicitly
**defers** carrying `lastUpSeq` in `MIGRATE_OK` ("Recommend deferring this; rely on server dedup
for v1", recon §3c). Server dedup makes *resend* idempotent but does **nothing** to recover a lost
*ack* — the client tail never shrinks. The two are not interchangeable.

**Required revision:** EITHER (a) on every successful `MIGRATE_OK`/`RESUME_OK`, have the server
return its current `lastUpSeq` so the client trims `unackedUpTail` at resume (the recon's deferred
optimization is in fact **required for liveness**, not an optimization); AND/OR (b) make the server
emit UplinkAck periodically / on a resync trigger, not just inline once. Without one of these the
backpressure-block is a deadlock waiting for the first lost ack.

---

## HIGH

### HIGH-1 — Root cause is unproven and the trace names a more likely culprit the fix doesn't address

The trace TL;DR (`bug9-uplink-resend-trace` §"TL;DR", §4, §5-д) concludes the 1 MB uplink is
**most plausibly application/tun2socks retry on a NEW streamID** (new CONNECT → new stream → app
re-uploads the request body), which the server accepts twice because it doesn't dedup across
streams. That is a *different* defect than "in-flight uplink lost on slot death," and **this spec
does not fix it** (a per-stream `lastUpSeq` does nothing across two different streamIDs). The spec
admits the risk verbally but then commits a client+server+wire feature + server redeploy to the
weaker hypothesis. The trace already wrote the exact 5 cheap DEBUG points (§5 a-д) to *distinguish*
the two in one field run. Spending those ~30 min of instrumentation BEFORE building this feature is
the architecturally correct move (per project memory: "не клепать", measure first). Recommend:
gate the plan on the §5-д retry-detector + §5-а uplink-read log confirming real loss, not app
retry.

### HIGH-2 — `boundedBuffer` lives in `package server`; spec's "переиспользуем тип из server" violates isolation

Task Risk 6, confirmed. `boundedBuffer` is defined in `server/relay_registry.go:41`. The client
cannot import `server` (it would invert the dependency and is forbidden by the ShadowLink isolation
rule). The spec hedges ("вынесем в общее место или дублируем — решить в плане") but this is not a
plan detail, it's an architecture decision that affects where the shared FIFO type lives. The
**correct home is `core/`** (a new `core/boundedbuffer.go` or similar), imported by both `server`
and `client` — mirroring how `core/chunk.go` already holds the shared wire helpers both sides use.
Note: the server `boundedBuffer` also has `Push`-returns-false-on-full semantics tightly coupled to
the server credit gate ("the credit gate guarantees in-flight ≤ window so this push always fits",
`relay_registry.go:696`). The **client uplink has NO such credit gate** (recon §4c: flow control is
downlink-only), so the client's bounded buffer must enforce its own cap independently and the
"always fits" invariant does **not** carry over. Spec must call this out — copying the type without
copying the gating context is a bug.

### HIGH-3 — Backpressure on `conn.Read` is safe from demux deadlock, but the spec doesn't prove it

Task Risk 4. I verified the reading paths and they are **not** in a shared-lock deadlock:
the uplink goroutine (`tcp.go:847`) and the downlink demux that delivers UplinkAck
(`ws_pool.go:slotReaderWithClient`) are **separate goroutines**, and `evictUpTo` would run under a
per-stream lock the uplink goroutine does not hold while parked. So Risk 4 is **not** a blocker as
the code stands. HOWEVER the spec says to keep the new `unackedUpTail` map "под `c.streamMu` как
`streamFlow`" (recon §3 / §4c). If the uplink goroutine blocks (cond.Wait) **while holding
`c.streamMu`**, and the demux's `resolveUplinkAck` needs `c.streamMu` to find the buffer to evict
→ classic deadlock. The downlink side avoids this because the reassembler/ack live on per-stream
state accessed without parking under the global map lock. **Required:** spec must mandate that the
uplink backpressure wait uses a **per-stream cond/lock**, and that `c.streamMu` is released before
parking (look up the buffer, then Wait on the buffer's own cond — never Wait under `streamMu`).
This is a real footgun given the recon's "fold under c.streamMu" suggestion.

### HIGH-4 — Dedup must run on BOTH server uplink sinks (local fast-path AND registry-fallback), or pre-migration bytes escape it

The recon (§1a) flags this and the spec's §"server uplink-приём" only describes the migrated path.
The server has two uplink writers to the **same** origin conn: `s.Write(payload)` on the slot the
stream was born on (`websocket.go:826`) and `entry.tc.Write(payload)` after migration
(`websocket.go:856`) — and the comment at `:840-843` confirms `s.TargetConn == entry.tc` are the
same `net.Conn`. If dedup/resequencing is applied only on the registry path, then frames that
arrive on the **original** slot (pre-migration, the common case) bypass the high-water entirely;
after a migration the resent tail (which includes frames originally sent pre-migration) then hits
the dedup with a `lastUpSeq` of **0** (never advanced on the local path) and **everything is
re-written to origin** → duplication. **Required:** the spec must mandate resolving the relayEntry
and advancing `lastUpSeq` / resequencing on **both** sinks uniformly (recon's "ALWAYS resolve entry
for migrate sessions and write via entry.tc"), or the dedup is a no-op for the exact streams that
later migrate.

### HIGH-5 — Ack-vs-resume race is benign ONLY if BLOCKER-1 is fixed; as written it can drop bytes

Task Risk 2. The "resend tail before the ack for those bytes arrives → duplicates" case is
**handled correctly** by an *order-preserving* dedup (server already saw them, drops on
`upSeq <= lastUpSeq`) — IF and only if the server resequences (BLOCKER-1). With the bare
high-water dedup the spec proposes, the same race can instead **drop** a genuine frame whenever
arrival order across the two slots inverts (see BLOCKER-1 worked example). So Risk 2 is not
independently a blocker, but it collapses into BLOCKER-1: fix the resequencer and the ack/resume
race is idempotent; leave it as high-water-only and the race is lossy.

---

## MEDIUM

### MED-1 — `FlagUplinkAck = 0x0E` collision check is correct, but the throttle/timer ownership is unspecified
`0x0E` is genuinely free (last is `FlagStreamAck=0x0D`, `core/chunk.go:26`; grep clean). Good. But
the spec says ack is "throttled, как downlink ack" without saying who runs the throttle on the
**server** side. Downlink ack is throttled on the *client* (`SendStreamAckThrottled`). The server
has no equivalent throttle helper today. This is new server plumbing the spec hand-waves; name it
in the plan (a per-entry last-ack-ns + interval), and ensure a forced ack on resume (so the client
can trim) — which ties back to BLOCKER-3.

### MED-2 — Backward-compat claim is plausible but the gating predicate is under-specified
Spec §"Объём/деплой" claims old-client→new-server degrades to current behavior. Likely true: an old
client sends flat `NewStreamDataChunk` (no upSeq) and never sends `FlagStreamAck`-style uplink
proof, so the new server must **only** apply upSeq parse/dedup/resequence when the frame is actually
seq-tagged AND the session negotiated migration (`migrateEnabled`), exactly as the downlink side
gates `ParseStreamDataSeq` behind `migrateEnabled` (`ws_pool.go:3272`). The spec must state the
gating predicate explicitly: **a non-seq-tagged FlagData on a migrate session = legacy uplink,
write straight through (no dedup)**, else a new server would try to parse 10-byte headers out of
short legacy uplink frames and corrupt them. New-client→old-server: old server ignores
`FlagUplinkAck`? No — old server hits `default → UnknownFlag` (`websocket.go:1330`), harmless, but
the client then NEVER gets an ack → BLOCKER-3 deadlock against an old server. So the client MUST
gate the whole uplink-tail machinery behind a negotiated capability, not just `migrateEnabled`,
or a new client against an un-redeployed server self-deadlocks. The staged "server first" deploy
mitigates but the capability gate should be explicit.

### MED-3 — Buffer cap sizing has no flow-control backstop on uplink
Recon §4a/§4c is right that there is no uplink credit gate, so the client `unackedUpTail` cap is the
*only* memory bound and a full buffer is the *only* backpressure. The spec says "byte-cap зеркалит
downlink" (one flow window) but the downlink window is sized for the *downlink* credit system that
doesn't exist here. Pick the cap from the actual in-flight-between-send-and-ack budget under TSPU
RTT, and document it; "mirror downlink" is not a derivation.

### MED-4 — `uploads`/metrics semantics will shift; spec lists no counters
The trace established `uploads++` counts real `conn.Read`s. Once resend exists, the spec needs the
recon's counters (`uplink_resend_total`, `uplink_ack_evict_total`, `uplink_dedup_dropped_total`,
and a NEW `uplink_resequence_buffered_total` if BLOCKER-1 is addressed) to make the canary
falsifiable — otherwise you cannot tell resend-working from app-retry-masking (HIGH-1). Spec §Тесты
covers unit tests but omits the field-observability counters.

---

## NIT

- **NIT-1** Spec §1 "208 uploads / 1 054 952 bytes" → ~5KB avg per read; consistent with TLS records,
  not with tiny duplicated frames — a (weak) data point *for* the app-retry hypothesis (HIGH-1).
- **NIT-2** `BuildUplinkAckFrame`/`ParseUplinkAckFrame` are byte-identical to the StreamAck pair
  (`core/chunk.go:384/393`). Recon notes you *could* reuse them. Prefer the named pair (spec's
  choice) for direction clarity — agreed, keep as spec says.
- **NIT-3** Spec calls the env flag `SHADOWLINK_UPLINK_RELIABILITY` "(default on при migration)".
  Given BLOCKER-3/MED-2, ship it **default-off** for the first canary and flip after a field run
  confirms no ack-loss deadlock — same caution as every prior Bug #6/#8/#9 staged rollout.
- **NIT-4** `NewStreamDataChunkUpSeq` vs reusing `NewStreamDataChunkSeq`: reuse is fine (recon
  option a) since the wire shape is identical; just add a doc-comment that the seq field is
  *client-assigned per-stream upSeq* on the uplink direction to prevent the BLOCKER-2 confusion.

---

## Summary of required revisions before a plan is written

1. **Add a server-side uplink reassembler** (per-relayEntry, reorder + drop-prefix), not a bare
   high-water dedup (BLOCKER-1, HIGH-5).
2. **Pin a dedicated per-stream client `upSeqCounter`** monotonic across migration, explicitly NOT
   `session.NextSeqNum()` (BLOCKER-2).
3. **Add ack recovery**: server returns `lastUpSeq` in MIGRATE_OK/RESUME_OK and/or repeats
   UplinkAck, so a lost ack can't wedge the backpressure block (BLOCKER-3, MED-1).
4. **Move `boundedBuffer` to `core/`** (HIGH-2).
5. **Apply dedup/resequence on both server uplink sinks** uniformly (HIGH-4).
6. **Mandate per-stream lock for backpressure wait; never Wait under `c.streamMu`** (HIGH-3).
7. **Explicit capability gate + default-off first canary** so new-client/old-server doesn't
   self-deadlock (MED-2, NIT-3).
8. **Measure first** (trace §5-а/§5-д) to confirm real loss vs app-retry before committing the
   build (HIGH-1).

Counts: **3 BLOCKER / 5 HIGH / 4 MEDIUM / 4 NIT.**
