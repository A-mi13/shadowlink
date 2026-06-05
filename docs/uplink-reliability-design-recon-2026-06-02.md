# Uplink Reliability — Design Recon (mirror downlink tail-resend onto uplink)

Date: 2026-06-02. Scope: spec-only reconnaissance, NO code changes. Goal: give an
exact integration map so uplink bytes survive WS-slot kill during stream migration,
the same way downlink already does via `relayEntry.unackedTail` + `FlagStreamAck` +
client reassembler dedup.

All file:line references are against the tree at recon time.

---

## TL;DR for the parent agent

- **Free Flag byte for UplinkAck:** YES — `0x0E` is unused. The last defined flag is
  `FlagStreamAck = 0x0D` (`core/chunk.go:26`). Next free is `0x0E`. Grep for
  `0x0E`/`UplinkAck`/`upSeq` across the whole module = zero matches — nothing to
  collide with. (Suggest `FlagUplinkAck byte = 0x0E`.)
- **Seq-tagged chunk helper to mirror:** PARTIAL. There is a *downlink* seq helper
  (`NewStreamDataChunkSeq` + `ParseStreamDataSeq`, `core/chunk.go:215/229`) and an
  ack-frame helper (`BuildStreamAckFrame`/`ParseStreamAckFrame`, `core/chunk.go:384/393`).
  There is NO uplink equivalent — uplink is sent today with the flat
  `NewStreamDataChunk` (no seq). You will add a symmetric `NewStreamDataChunkUpSeq`
  (or reuse the downlink one — the wire shape `[streamID(2)][seq(8)][data]` is
  identical; only the *direction* and the dedup-owner differ) and a
  `BuildUplinkAckFrame`/`ParseUplinkAckFrame` mirror of the StreamAck helpers.

### Key integration points (client + server)

| # | Side | file:line | What |
|---|------|-----------|------|
| 1 | core | `core/chunk.go:26` (+ add at `:27`) | Add `FlagUplinkAck byte = 0x0E`; add `NewStreamDataChunkUpSeq`/`ParseStreamDataUpSeq` (mirror `:215/:229`) + `BuildUplinkAckFrame`/`ParseUplinkAckFrame` (mirror `:384/:393`). |
| 2 | client | `proxy/socks5/tcp.go:916-926` | Uplink goroutine: today builds flat `NewStreamDataChunk` and fires `client.StreamWrite`. This is where to (a) tag upSeq, (b) push into a per-stream `unackedUpTail` BEFORE write, (c) flush/resend on resume. |
| 3 | server | `server/websocket.go:820-861` | `case core.FlagData:` — production uplink reception. Local `streams[sid].Write` fast path + the registry-fallback `entry.tc.Write` (migrated path, `:855-860`). This is where to parse upSeq, dedup against `relayEntry.lastUpSeq`, and arm the UplinkAck. |
| 4 | server | `server/handler.go:877-944` | POST-path `handleDataChunk` `FlagData` — the OTHER uplink sink (`targetConn.Write(data)` at `:922`, legacy `legacyConn.Write` at `:944`). Must apply the same upSeq dedup OR be explicitly out-of-scope (see §1). |
| 5 | server | `server/relay_registry.go:100-182` | `relayEntry` struct — add `lastUpSeq atomic.Uint64` (mirror `downSeqCounter:121`) and the UplinkAck-send plumbing. The egress conn `e.tc` is the single uplink write target post-migration (`:111`). |
| 6 | client | `client/ws_pool.go:3230-3233` | Downlink demux: `FlagMigrate/FlagResume` reply branch. Add a sibling `case core.FlagUplinkAck:` that calls a new `resolveUplinkAck` → evicts the client's `unackedUpTail` up to ackedUpSeq. |
| 7 | client | `client/migrate_watchdog.go:276` (`rebindStreamToSlot`) & `client/ws_pool.go:3690` (`resumeStreamOnDeath`) | The two points where a stream's slot binding flips. Resend of the unacked uplink tail onto the NEW slot must be triggered from here (after a successful `migrateResultOK`). |
| 8 | server | `server/websocket.go:1054` + `:1199-1219` (FIN) | Where the `relayEntry` is created/bound and torn down — `lastUpSeq` initialises to 0 here; UplinkAck buffers freed on FIN alongside the existing downlink teardown. |

---

## 1. Server uplink reception (where to add upSeq dedup / lastUpSeq / uplink-ack)

There are TWO uplink sinks. The production CF/WS path is `server/websocket.go`; the
legacy direct-POST path is `server/handler.go`.

### 1a. Production path — `server/websocket.go` reader loop, `case core.FlagData:` (`:820-861`)

```
:821  streamID, payload := core.ParseStreamID(chunk.Payload)   // flat [streamID(2)][data]
:822  s := streams[streamID]
:825  if s != nil && len(payload) > 0 { s.Write(payload) }      // local fast path (stream lives on THIS slot)
:827  else if s == nil && ... migrateEnabled && migrateClientID != "" {
:855      if entry, ok := h.relayRegistry.find(migrateClientID, streamID); ok && entry.tc != nil {
:856          entry.tc.Write(payload)                           // registry-fallback (stream migrated here)
```

- **streamID + payload extraction**: `core.ParseStreamID(chunk.Payload)` at `:821`. To
  carry an upSeq you switch the wire to `[streamID(2)][upSeq(8)][data]` and parse with
  a new `ParseStreamDataUpSeq` (the `migrateEnabled` branches only). Legacy
  (`migrateEnabled==false`) stays on `ParseStreamID` byte-for-byte — same disambiguation
  the downlink side already does (`ws_pool.go:3272-3290`).
- **(а) upSeq dedup**: the dedup owner is the `relayEntry` (it is the per-stream object
  that survives migration). Add `relayEntry.lastUpSeq atomic.Uint64`. On the registry
  path (`:855`) AND ideally on the local path (`:825`, resolve the entry too), drop
  `upSeq <= lastUpSeq`, else `lastUpSeq.Store(upSeq)` then write. NOTE: the local fast
  path `s.Write` does NOT currently resolve the registry entry — to dedup uniformly you
  must `relayRegistry.find` on both branches, or move uplink entirely onto the registry
  (`entry.tc.Write`) for migration sessions and treat `s` as just the pre-migration
  owner. Cleaner mirror of downlink: ALWAYS resolve `entry` for migrate sessions and
  write via `entry.tc`, since `s.TargetConn == entry.tc` are the same `net.Conn`
  (`websocket.go` comment at `:840-843` confirms this identity).
- **(б) record lastUpSeq on relayEntry**: `relayEntry` at `server/relay_registry.go:100`.
  Add field next to `downSeqCounter` (`:121`). It is uplink's mirror of the downlink
  ordering counter, but uplink's counter is *client-assigned* (the server only tracks
  the high-water mark for dedup), whereas downlink's is *server-assigned*. So it is a
  high-water `lastUpSeq`, not a `downSeqCounter`-style allocator.
- **(в) send UplinkAck to client**: mirror how the server sends downlink frames —
  `enqueueDownFrame` (`relay_registry.go:822`) encrypts under `b.session` and enqueues on
  `b.writer`. For UplinkAck you build a `FlagUplinkAck` chunk
  (`BuildUplinkAckFrame(streamID, lastUpSeq)`) and enqueue it on the active binding's
  writer. Throttle it exactly like the client throttles StreamAck (don't ack per-frame).
  Reuse `binding` (`relay_registry.go:32`) so it rides whichever slot is currently bound.

### 1b. Legacy POST path — `server/handler.go::handleDataChunk` (`:877-951`)

- Multiplexed: `streamID, data := core.ParseStreamID(chunk.Payload)` (`:893`) →
  `targetConn.Write(data)` (`:922`).
- Legacy single-conn: `legacyConn.Write(chunk.Payload)` (`:944`).
- This path is NOT registry-backed and does NOT migrate (it is the non-WS POST datapath,
  largely retired per CLAUDE.md "T1.4 V1 closure"). **Recommendation: declare 1b
  OUT-OF-SCOPE for uplink reliability** — migration only exists on the WS pool transport
  (`migrateEnabled` is a WS-session property). The POST path has no slot kill / migration,
  so there is nothing for an uplink tail to survive. Keep it on the flat
  `NewStreamDataChunk` shape; the new `ParseStreamDataUpSeq` is gated behind
  `migrateEnabled` so the POST path never sees an upSeq frame.

---

## 2. Wire format (core/) — what exists, what to add

`core/chunk.go`:

- Flag constants `:13-27`. Defined through `FlagStreamAck = 0x0D`. **`0x0E` is FREE.**
  Add `FlagUplinkAck byte = 0x0E`.
- `NewStreamDataChunk` (`:194`) — flat `[streamID(2)][data]`, `FlagData`. Today's uplink.
- `NewStreamDataChunkSeq` (`:215`) + `ParseStreamDataSeq` (`:229`) — `[streamID(2)][downSeq(8)][data]`,
  still `FlagData`. **DOWNLINK** seq helper. The wire shape is direction-agnostic —
  uplink can reuse the SAME `[streamID][seq][data]` layout. Either:
  (a) reuse `NewStreamDataChunkSeq`/`ParseStreamDataSeq` directly for uplink (the bytes
      are identical; the only asymmetry is the client assigns the seq for uplink, the
      server assigns it for downlink — both still `FlagData`), or
  (b) add thin aliases `NewStreamDataChunkUpSeq`/`ParseStreamDataUpSeq` for naming clarity.
  Option (a) is the smallest diff and keeps the parser/`<10`-guard identical
  (`ws_pool.go` NEW-2 guard). Recommend (a) with a doc-comment noting the dual use.
- `BuildStreamAckFrame`/`ParseStreamAckFrame` (`:384/:393`) — `[streamID(2)][ackedSeq(8)]`,
  for `FlagStreamAck` (downlink ack, client→server). **Mirror these** as
  `BuildUplinkAckFrame`/`ParseUplinkAckFrame` (identical 10-byte layout) for
  `FlagUplinkAck` (uplink ack, server→client). The shape is literally the same; you may
  even reuse `BuildStreamAckFrame`/`ParseStreamAckFrame` and only differ in the Flag —
  but a named pair documents direction.

So: **one new flag (`0x0E`), zero new wire shapes** (both the data and ack layouts
already exist for downlink and are reusable for uplink).

---

## 3. Client side — buffer-until-ack + receive uplink-ack + resend on resume

### 3a. Uplink goroutine — buffer sent chunks until acked (`proxy/socks5/tcp.go:847-928`)

The goroutine (`:847`):
- `:859` `conn.Read(buf)` → `:910-915` migrate barrier (`WaitStreamMigrateBarrier`,
  re-resolves `uplinkSession`) → `:916` `core.NewStreamDataChunk(...)` → `:917`
  `uplinkSession.EncryptChunk` → `:923` `client.StreamWrite(wst, streamID, enc)`.
- **Insert buffering at `:916-923`**: assign the next per-stream upSeq, build the
  seq-tagged chunk, and push `{upSeq, rawBytes}` into a per-stream `unackedUpTail`
  (bounded buffer) BEFORE `StreamWrite`. The raw app bytes (`buf[:n]` copied) must be
  retained — not the encrypted chunk — because a resend onto a NEW slot must re-encrypt
  under the new slot's session (the encryption is per-session, see how downlink
  `enqueueDownFrame` re-encrypts per binding, `relay_registry.go:822-829`).
- The buffer should live on the per-stream client state, NOT on the WSPoolTransport —
  mirror where downlink's per-stream `streamFlowState` lives (`Client.streamFlow` map,
  `stream_flow.go:233-243`, keyed by streamID under `c.streamMu`). Add a parallel
  `Client.streamUpTail map[uint16]*uplinkTail` (or fold into `streamEntry`). The
  server-side bounded buffer to copy is `boundedBuffer` (`relay_registry.go:41-91`):
  `Push` (cap by bytes), `evictUpTo(ackedSeq)`, `tailFrames()`. Reuse that exact type or
  a client copy of it.

### 3b. Receiving the uplink-ack (same demux as the migrate reply / StreamAck)

- The client downlink demux is `client/ws_pool.go` `slotReaderWithClient` around
  `:3220-3293`. The `FlagMigrate/FlagResume` reply is intercepted at `:3230-3233`
  (`resolveMigrateReplyPayload`) BEFORE the streamID parse. **Add a sibling
  `case`/`if chunk.Flags == core.FlagUplinkAck` at the same spot (just after `:3233`)**
  that parses `ParseUplinkAckFrame` and calls a new
  `p.resolveUplinkAck(streamID, ackedUpSeq)` → looks up the per-stream `unackedUpTail`
  and `evictUpTo(ackedUpSeq)`. This is the exact mirror of how the SERVER consumes the
  client's `FlagStreamAck` (`server/websocket.go:1315-1328` → `entry.onStreamAck`).
- Note: `FlagStreamAck` on the client is SENT (downlink ack); `FlagUplinkAck` on the
  client is RECEIVED (uplink ack). The server is symmetric: it RECEIVES `FlagStreamAck`
  (`websocket.go:1315`) and would SEND `FlagUplinkAck` from the uplink reception path
  (§1a в).

### 3c. Resend the uplink tail on resume / migrate

- The two binding-flip points:
  - Preemptive: `migrateStream` → on `migrateResultOK` calls
    `rebindStreamToSlot(streamID, targetIdx)` (`migrate_watchdog.go:276`).
  - Reactive (slot death): `resumeStreamOnDeath` → on OK re-points the entry
    (`ws_pool.go:3690-3711+`).
- **Resend hook**: after a confirmed `migrateResultOK` in BOTH paths, walk the stream's
  `unackedUpTail.tailFrames()`, re-encrypt each under the NEW slot's session
  (`StreamSession(wst, cl, streamID)` after rebind — same call the uplink goroutine uses
  at `tcp.go:912`), and `StreamWrite` them onto the new slot. The server-side
  `lastUpSeq` dedup (§1a а) makes the resend idempotent: any frame slot A already
  delivered (upSeq <= lastUpSeq) is dropped server-side, exactly as downlink resend is
  deduped client-side by `reassembler.push` `seq < expectedSeq` (`reassembler.go:30`).
- The `migrateResult` already carries `resumeDownSeq` (`migrate_send.go:273`) — the
  server's MIGRATE_OK could be extended to ALSO carry the server's current `lastUpSeq`
  so the client can pre-trim its uplink tail before resending (an optimization; not
  required for correctness because server-side dedup covers it). Wire room exists:
  `BuildMigrateOK` (`core/chunk.go:435`) is `[0x01][streamID(2)][resumeDownSeq(8)]` —
  adding a second 8-byte field is a versioned reply-shape change (touch `ParseMigrateReply`
  `:456`). Recommend deferring this; rely on server dedup for v1.

### Concurrency note (uplink barrier already protects ordering)
`WaitStreamMigrateBarrier` (`migrate_send.go:193-241`, called at `tcp.go:910`) already
guarantees uplink is serialized onto ONE slot at a time during a migration — the client
never writes uplink on slot A and slot B concurrently. This is what makes a simple
high-water `lastUpSeq` dedup sufficient (no interleave). The resend in §3c happens AFTER
the barrier clears, onto the resolved new slot.

---

## 4. Symmetry of risk — cap, backpressure, Bug #8 interaction

### 4a. Uplink tail cap
- Downlink `unackedTail` is a `boundedBuffer` capped at `int(flowWindow)` — one flow
  window (`server/websocket.go:1039` `newBoundedBuffer(int(flowWindow))`; rationale at
  `relay_registry.go:37-44` "≤ 1 flow-window, §4.2"). The credit gate guarantees
  in-flight ≤ window so the push "always fits" (`relay_registry.go:696-698`).
- **Uplink mirror: cap the client `unackedUpTail` at one flow window too** (the
  negotiated `c.flowWindow`, `stream_flow.go:54`). BUT note the asymmetry: downlink flow
  control (Bug #8) gates the SERVER's send rate against the CLIENT's window. There is NO
  symmetric credit gating the CLIENT's uplink rate against a SERVER window today (flow
  control is downlink-only — see §4c). So the uplink tail is NOT automatically bounded by
  an existing credit gate; the cap must be enforced by the buffer itself, and a full
  buffer must apply backpressure by NOT reading the app socket (stop calling
  `conn.Read` at `tcp.go:859`) until an UplinkAck frees space — mirroring the server's
  `routeDownFrame` blocking-on-full-buffer backpressure (`relay_registry.go:705-712`).

### 4b. Backpressure if client outruns server acks
- Server downlink uses `bufCond` to block the relay loop on a full `downBuffer`
  (`relay_registry.go:705-712`, woken by `onStreamAck`/`reassociate`). Client uplink
  should do the same shape: when `unackedUpTail.Push` returns false, the uplink goroutine
  blocks (cond.Wait or a small poll) until `resolveUplinkAck` evicts and signals. This
  stalls `conn.Read` → the app's TCP send window collapses → natural end-to-end
  backpressure, zero bytes dropped. This is the SAME design that fixed Bug #8 on the
  downlink (no `default`-drop). Do NOT use a non-blocking drop — that reintroduces the
  Bug #8 class of corruption on uplink.

### 4c. Bug #8 flow-control credit — does it conflict?
- Bug #8 credit is DOWNLINK-ONLY: `streamCredit` lives server-side
  (`server/stream_credit.go`, gated in `relayLoop`/the WS download writer,
  `relay_registry.go:580-589`), replenished by the client's `WINDOW_UPDATE`
  (`stream_flow.go:187-204` send; `server/websocket.go:1264-1301` receive). It throttles
  how fast the SERVER pushes downlink to the client.
- The client uplink path has NO credit gate — `OnStreamConsumed`/`creditSenderTick`
  (`stream_flow.go`) only emit WINDOW_UPDATEs for downlink bytes the app consumed. So the
  uplink-tail machinery is ORTHOGONAL to Bug #8: it adds a per-stream uplink reorder/ack
  buffer + backpressure that did not exist. **No conflict**, but they share the same
  control-channel send path (`TryStreamWriteControl`, `stream_flow.go:203/227`) and the
  same per-stream `streamMu`-guarded maps — keep the new `unackedUpTail` map under
  `c.streamMu` like `streamFlow`/`streamChans` to avoid a new lock.
- One interaction to watch: the client uplink-tail cap (one flow window) and the server's
  ingest. The server writes uplink straight to `entry.tc` with a BLOCKING write
  (`websocket.go:856`, comment at `:851-854` says blocking tc.Write applies natural WS
  backpressure). So the server already backpressures the WS reader; the client tail only
  needs to bound memory until the ack, not to rate-limit (the blocking tc.Write does
  that). Pick the cap to comfortably cover the in-flight bytes between send and ack
  (≈ one window or a fixed few hundred KiB), and throttle the UplinkAck like StreamAck.

---

## 5. Existing downlink tail-resend tests to mirror

- `server/migrate_e2e_test.go`:
  - `TestE2E_UplinkAfterMigration_NoByteLoss` (`:638-709`) — ALREADY tests uplink
    survives migration via the registry-fallback (`entry.tc.Write`), but ONLY for a
    graceful preemptive MIGRATE where slot A is still alive (no in-flight loss). It does
    NOT test slot-A-DEATH mid-uplink (the case the tail-resend fixes). EXTEND this: kill
    slot A while uplink bytes are in flight (un-acked) and assert the origin still
    receives all bytes after RESUME → that is the uplink mirror of the downlink
    tail-resend test. Helpers to reuse: `sendUplink` (`:610`), `readOriginExactly`
    (`:620`), `e2eReassembler`, `dialSlot`, `connect`, `sendMigrate`.
  - The downlink no-byte-loss test it mirrors is around `:560-602` (sha256 over the full
    concatenation across the migration boundary — `:600`).
- `server/relay_registry_test.go` — unit tests for `boundedBuffer`
  (`Push`/`evictUpTo`/`tailFrames`/`drainAll`) and `resendTail`/`reassociate`. If you
  add a client-side `uplinkTail` (copy of `boundedBuffer`), mirror these unit tests in
  `client/`.
- `client/migrate_resume_test.go`, `client/migrate_send_test.go`,
  `client/migration_e2e_test.go` — the client migrate/resume harness (`newMigrateTestPool`,
  `migrateSendHook`, `WaitStreamMigrateBarrier` exercises). The uplink-tail resend-on-OK
  hook should get a client unit test here: inject `migrateSendHook` returning
  `migrateResultOK`, assert the unacked uplink tail was re-`StreamWrite`n onto the target
  slot.
- `core/migrate_frame_test.go`, `core/chunk_test.go` — round-trip tests for the
  build/parse helpers. Add round-trip tests for `BuildUplinkAckFrame`/`ParseUplinkAckFrame`
  and (if added) `NewStreamDataChunkUpSeq`/`ParseStreamDataUpSeq` mirroring the existing
  `BuildStreamAckFrame`/`ParseStreamDataSeq` tests.
- `server/migrate_metrics_test.go` / `client/migrate_stats_test.go` — pattern for adding
  the uplink-resend counters (`uplink_resend_total`, `uplink_ack_evict_total`,
  `uplink_dedup_dropped_total`) symmetric to the downlink `migrate_tail_resent` /
  `resume_ok` counters tracked in MEMORY.

---

## Appendix — the downlink mechanism being mirrored (one-paragraph recap)

Server: each migratable stream owns a `relayEntry` (`relay_registry.go:100`) keyed
(clientID, globalStreamID), independent of any WS slot. Downlink frames get a
server-assigned monotonic `downSeq` (`downSeqCounter`, never reset across migration) and
are kept in `unackedTail` (`boundedBuffer`, one flow window) until the client acks via
`FlagStreamAck` → `onStreamAck`→`evictUpTo` (`:529-544`). On slot-A death the binding
moves (`reassociate`, `:732`) and the unacked tail is resent on the new slot
(`resendTail`/`reassociate(aDead=true)`). Client dedups by `reassembler.push`
(`reassembler.go:30`, `seq < expectedSeq` dropped) and emits the ack from
`downlinkReassemblyLoop`'s `onFlush` (`tcp.go:1011-1017`). Uplink today has NONE of this
(`tcp.go:916` flat chunk, no buffer; `websocket.go:856` direct `entry.tc.Write`, no seq,
no dedup, no ack) — this recon maps the symmetric build-out.
