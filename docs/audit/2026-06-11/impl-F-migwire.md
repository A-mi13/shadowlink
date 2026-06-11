# Impl block F — migration wire-format correctness (H-C2, H-C3)

Date: 2026-06-11
Scope: `client/ws_pool.go`, `client/stats.go`, new `client/migrate_wireformat_test.go`.
Source: audit `docs/audit/2026-06-11/agent2-concurrency-pool.md` findings H2 (HIGH) and H3 (HIGH).
Tree baseline: block E (`881e7a3`, p.slots centralization via slotAt/snapshotSlots) already committed; read live code.

---

## H-C2 — silent frame-drop on a migration slot (HIGH) — RESOLVED

**Before:** In `slotReaderWithClient`'s migration demux, a decrypted FlagData frame that matched
neither `isStreamControlMsg` nor `core.ParseStreamDataSeq` (perr != nil; len<10 / malformed) was
silently dropped — no `continue`, no log, no counter. Same class as Bug#8 default-drop: a dropped
already-decrypted downlink frame punches a hole in the proxied TCP byte-stream → app-side TLS
decrypt failure / broken download, and invisible on the dashboard.

**Fix:** Extracted the FlagData routing into a new method
`(*WSPoolTransport).routeDownlinkFlagData(cl, slot, streamID, chunk)`. On the migration path, when a
frame is unparseable it now:
1. bumps `Stats.MigrationFrameUnparseable` (new counter — see below),
2. logs at WARN (`migration FlagData frame unparseable — tearing stream`, stream + payload_len),
3. **deterministically tears the stream** via `handleStreamClose(cl, streamID)` — closes both
   `streamChans` and `streamFramesChans`, so the SOCKS5/memConn reader gets EOF and the app retries
   instead of receiving a silently-corrupted byte stream.

This is the exact Bug#8-class remediation the audit recommended: count + deterministic teardown,
never a silent drop.

**New counter:** `Stats.MigrationFrameUnparseable atomic.Uint64` (client/stats.go), exported in the
Prometheus text output as `shadowlink_migration_frame_unparseable_total` (with HELP/TYPE). Modeled
on the existing `StaleFrameDroppedTotal` / `DownlinkReplayDroppedTotal` counters. Expected ~0 in a
healthy canary; sustained non-zero = a wire-format contract gap (unrecognized server control frame
or a decode-shape desync).

---

## H-C3 — seq-decode desync on pool-wide migrateEnabled (HIGH) — RESOLVED

**Before:** Slot readers selected the downlink decode shape from the pool-wide
`p.migrateEnabled.Load()` (write-once-true, flipped when ANY slot negotiates migrate). If slot A
served FlagData on the legacy-flat path while slot B's handshake flipped the pool flag → A's reader
switched to seq-tagged decode (`ParseStreamDataSeq` over `[streamID][downSeq(8)][data]`) for its
next frame, even though A's server session may still emit flat frames (server latches seq format
per-session at its own negotiation point, not atomically with the client's pool-wide flip). The
8-byte downSeq is then mis-parsed out of real payload → H-C2 drop / mis-route.

**Fix — per-slot decode latch:**
- Added `migrateNegotiated atomic.Bool` to `poolSlot` (client/ws_pool.go, next to the per-slot
  `flowControlEnabled`). **Source of the latch:** set in `connectSlot` from this slot's OWN FLOWCTL
  ack — `slot.migrateNegotiated.Store(wst.flowMigrateEnabled)` — alongside the existing pool-wide
  `p.migrateEnabled.Store(true)`. `wst.flowMigrateEnabled` (WSTransport) is read synchronously from
  the server's per-session FLOWCTL V2 ack in `UpgradeToWS` (ws_transport.go:564). A recycled cell
  gets a fresh `*poolSlot` so the latch is set fresh per (re)connect (no stale carry-over).
- `routeDownlinkFlagData` now keys the decode shape on `slot.migrateNegotiated.Load()` (the session
  that PRODUCED the frame), NOT the pool-global bit. The reader already holds `slot` (via `slotAt`
  after block E), so the slot pointer is passed straight in.

**migrateEnabled scope reduced to SOCKS registration only:** `p.migrateEnabled` is now used ONLY by
the SOCKS5 front-end via `MigrationEnabled()` (proxy/socks5/tcp.go:716-717) — it must register seq
channels as soon as ANY slot CAN produce seq frames. Its doc-comment was updated to record that it
no longer drives the per-frame decode shape and that the old "once on, all slots are seq-tagged"
invariant was false.

`FlagUDP` stays inline in the reader (routed via `RouteToStream` in both modes — datagram, no
ordering contract), unchanged.

---

## Tests (TDD: RED → GREEN)

New file `client/migrate_wireformat_test.go`, driving `routeDownlinkFlagData` directly (the reader's
ReadMessage loop needs a live conn; the routing decision is the unit under test):

- `TestRouteDownlinkFlagData_UnparseableSeqFrame_TearsStreamAndCounts` (H-C2) — a 5-byte
  non-control FlagData on a migration-negotiated slot → `MigrationFrameUnparseable` += 1 AND both
  stream channels closed/removed (no silent drop).
- `TestRouteDownlinkFlagData_ValidSeqFrame_RoutesSeq` (H-C2 negative) — a valid
  `NewStreamDataChunkSeq` frame routes to the seq channel, counter unchanged, stream not torn.
- `TestRouteDownlinkFlagData_FlatSlot_StaysFlat_AfterPoolFlip` (H-C3) — slot 1 flips the pool-wide
  bit; slot 0 (migrateNegotiated=false) still flat-decodes its frame to the legacy channel, counter
  unchanged, stream not torn, nothing leaks onto the seq channel.

All three RED before impl (undefined field/counter/method), GREEN after.

---

## Verification

- `go build ./...` — OK
- `go vet ./client/...` — OK (clean)
- `go test ./client/... ./core/...` — PASS (client 51.7s, core cached). Full ~50s client suite stays
  green; no existing migration test (migrate_e2e / migrate_resume / migrate_send / emergency) broke.
- `-race`: NOT run (no gcc on Windows). The change adds one `atomic.Bool` per slot written once in
  connectSlot (under reserveMu, alongside the existing flow fields) and read lock-free in the reader
  — identical access discipline to `migrateEnabled`/`flowControlEnabled`. **Run on Linux/CI:**
  `go test -race -count=3 ./client/`.

---

## Risks

1. **Per-slot latch correctness depends on `wst.flowMigrateEnabled` being authoritative per session.**
   It is set synchronously from the server FLOWCTL ack in UpgradeToWS before the slot goes live, so
   the latch is correct at reader start. Low risk; covered by the H-C3 test.
2. **No live-reader end-to-end test** — the unit tests exercise `routeDownlinkFlagData` directly, not
   through `slotReaderWithClient`'s ReadMessage loop (which needs a real conn). The extraction is a
   pure refactor of the inline block + the per-slot key, so behavior on the wire is unchanged for the
   common case; confirm with a canary watching `shadowlink_migration_frame_unparseable_total` ≈ 0.
3. **`-race` deferred to Linux/CI** (Windows has no gcc). New field follows existing atomic discipline,
   so the risk is low, but the rotation/cascade path is where H-C3's window lived — race suite should
   confirm no new slice/field race was introduced.
