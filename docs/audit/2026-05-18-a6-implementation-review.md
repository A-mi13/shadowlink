# A6 (per-session chunk_size sampling) — Implementation Review

**Reviewer:** code-reviewer subagent
**Date:** 2026-05-18
**Verdict:** **SHIP-AS-CANARY** (no blocking defects; one operational concern + one minor robustness suggestion)

---

## 1. Verdict and rationale

The implementation is **correct, wire-compatible, and adequately tested**. The
key engineering judgment — that `core.Session` does NOT need a new field
because the server data path never reads per-session chunk_size — is
**confirmed** by exhaustive grep:

- Only two readers of `h.config.ChunkSize` exist server-side:
  - `server/handler.go:556` (handshake — the sampled site, fixed).
  - `server/handler.go:741` (`handleNewFormatPost` body limit, intentionally
    global per design note).
- `core.Session` has no `ChunkSize` field, and `HandleClientHelloWithVersion`
  consumes its `chunkSize` parameter exclusively to write
  `ServerHello.ChunkSize` (line 124). It is **not** persisted on the session.
- Client-side `c.chunkSize` (client.go:487) is read only for the slog at
  client.go:521 — confirmed by `c\.chunkSize` grep: 4 hits total
  (assignment, zero-fallback, fallback constant, log).
- `client/ws_pool.go::connectSlot` likewise stores `shData.ChunkSize` into
  `core.ServerHello` but the value never propagates beyond
  `CompleteHandshake`'s discard (it derives session keys from `EphPub`/
  `EncryptedSessionToken`/`ProtoVersion`, not from `cs`).

Therefore A6 is **purely a wire-format change in the JSON `"cs"` field of
ServerHello**, sampled per session, with no protocol-state consequences
client or server side. The "no Session field" path is the right call.

## 2. Top issues

### W1 — Per-session global body-limit asymmetry (WARNING)

`handleNewFormatPost` uses **global** `h.config.ChunkSize + 8192` as the body
read cap (handler.go:741). When the sampler returns 6144 for a session, the
server **still accepts uploads up to** `12288+8192 = 20480` from that
client. This is *functionally* fine (no spec violation, no buffer
overflow), but it means the wire-observable behavior diverges from the
advertised `cs`:

- Server tells client X (e.g. 6144).
- Client may upload Y > X bytes per chunk.
- Server accepts Y silently.

If a sophisticated observer correlates ServerHello `cs` to the upload-size
upper bound, they will notice that some clients (those whose `cs` was
sampled low) still upload at the global cap. **Mitigation is optional** —
the attack model for A6 is unimodal-distribution detection, not adversarial
flow correlation. Current code does not amplify the original signature,
and tightening the limit per-session would require the Session-field
change you correctly avoided. Document this in the audit closeout and
defer the per-session tightening to a separate task.

### W2 — `[]byte` zero from `sampleChunkSize(0)` propagates as wire `"cs":0` (WARNING)

`sampleChunkSize(0) → 0` and `sampleChunkSize(<0) → 0`. If a future
operator misconfigures `chunk_size: 0` in YAML, the server will emit
`{"cs":0,...}` in the ServerHello JSON. Client side
(`client/client.go:488`) **does** have a fallback (`if c.chunkSize == 0 {
c.chunkSize = 12288 }`), but the pool slot path at `ws_pool.go:1190` does
**not** — it stores 0 into `core.ServerHello.ChunkSize` without guard.
Since `core.ServerHello.ChunkSize` is read by no other code (only logged
on the non-pool path), this is *currently* harmless but is a latent trap
if any future feature uses `session.serverHelloChunkSize` for budgeting.

Recommend a defensive `slog.Warn` in `Handler.handleHandshakeNew` if
`h.config.ChunkSize <= 0`, or a startup-time `LoadFromFlags`/`LoadFromYAML`
sanity check that rejects non-positive `chunk_size` configs.

### S1 — Distribution-test flakiness floor (SUGGESTION)

`TestSampleChunkSize_DistributionUniform` accepts each bucket in
[190, 310] for 1000 trials. Under uniform 4-way, σ ≈ 13.7, so 250±60 is
~4.4σ — false-positive rate is ~10⁻⁵ per test, **20× over four buckets**
≈ 4×10⁻⁵ per run. Acceptable for unit tests but could flake under CI
load. Two options:
1. Bump trials to 5000 (tightens relative bound).
2. Use seeded `rand.New(rand.NewPCG(seed1, seed2))` for the distribution
   test so determinism is guaranteed.

`math/rand/v2` package-level `IntN` cannot be seeded; if you want option
2 you need to refactor `sampleChunkSize` to take an `*rand.Rand` (or test
seam via a swappable function variable). Not blocking — current odds of
flake are very low.

### S2 — `maxIdx` loop is correct but could be expressed clearer (SUGGESTION, style)

```go
maxIdx := 0
for i, v := range chunkSizeSampleSet {
    if int(v) <= configChunkSize {
        maxIdx = i
    }
}
return chunkSizeSampleSet[rand.IntN(maxIdx+1)]
```

Logic relies on **ascending order** of the set (which `TestChunkSizeSampleSet_AscendingOrder`
guards). Correct, but slightly subtle. A clearer equivalent:

```go
n := 0
for _, v := range chunkSizeSampleSet {
    if int(v) > configChunkSize {
        break
    }
    n++
}
return chunkSizeSampleSet[rand.IntN(n)]
```

`n` is the count of allowed values; reads "drop the first too-big value".
Not blocking. The current form has the corner case that if NO value ≤ cap
exists, it returns `chunkSizeSampleSet[0]` (wrong) — but the prior
`configChunkSize < int(chunkSizeSampleSet[0])` guard prevents reaching the
loop in that case. Two interacting guards make the file slightly harder
to reason about than necessary.

## 3. Edge cases verified

| Cap value | Expected sample set | Current code result | OK? |
|-----------|---------------------|---------------------|-----|
| 0 | (disabled) | 0 | yes |
| -1 | (disabled) | 0 | yes |
| 4096 (below 6144) | {4096} (cap verbatim) | 4096 | yes |
| 6144 (exact match smallest) | {6144} | maxIdx=0, returns 6144 | yes |
| 6145 | {6144} | maxIdx=0, returns 6144 | yes |
| 8192 (exact intermediate) | {6144, 8192} | maxIdx=1, IntN(2)∈{0,1} → {6144,8192} | yes |
| 9000 (test case) | {6144, 8192} | maxIdx=1 → {6144,8192} | yes |
| 10240 (exact intermediate) | {6144, 8192, 10240} | maxIdx=2 → {6144,8192,10240} | yes |
| 11000 | {6144, 8192, 10240} | maxIdx=2 | yes |
| 12288 (default) | all 4 | maxIdx=3 → all 4 | yes |
| 99999 (oversize cap) | all 4 | maxIdx=3 → all 4 | yes |

All edges pass. The two-guard structure handles below-smallest correctly.

## 4. What this change does NOT break

Verified by source inspection:

1. **Existing client deserialization** (`client/client.go`, `client/ws_pool.go`):
   uses `uint16 "cs"`, accepts any 0..65535, has zero-fallback to 12288.
   Sampled values 6144/8192/10240/12288 all fit comfortably.
2. **Body limit** (`handleNewFormatPost`): unchanged at
   `h.config.ChunkSize + 8192` — global. Sampled value is always ≤ global,
   so no regression on the body-accept path. (See W1 for the wire-shape
   side observation.)
3. **Replay protection** (`replayCache.Accept`): keyed on `encClientID`
   ciphertext, NOT chunk_size. Unaffected.
4. **Rate limiters / token buckets**: read no chunk_size. Unaffected.
5. **Mimicry session / decoy timing**: independent surfaces. Unaffected.
6. **Cryptographic key derivation** (`DeriveSessionKeys`): inputs are
   shared secret + ephPubs + clientID + protoVersion. chunk_size is not
   in the key schedule. Unaffected.
7. **Tests that pin `12288`**:
   - `core/handshake_test.go` (5 sites) — pass `12288` directly to
     `HandleClientHello`, do not go through `sampleChunkSize`. Pass.
   - `client/ws_pool_test.go:270` — hand-crafted JSON `"cs":12288`,
     decoded standalone. Pass.
   - `server/handler_test.go`, `server/server_test.go`,
     `client/transport_test.go` — receive whatever the server emits and
     forward to ServerHello. **These tests will see varying values
     after this change.** Verified all such call sites use the received
     `shData.ChunkSize` (do not assert == 12288). Pass.
   - `server/fileconfig_test.go:171` — tests *config loader* default,
     not handshake output. Pass.
8. **Tunnel / WS data path**: client uploads chunks of whatever size it
   chooses; server body limit is global. No regression.
9. **A1-A4 (storm brake, byte budget, stagger jitter, max streams)**:
   independent surfaces, confirmed via spec read. Unaffected.

## 5. Compilation / sample correctness

- `math/rand/v2` is correctly imported and the package-level `rand.IntN`
  is goroutine-safe (per Go 1.22+ docs, the global v2 RNG uses a
  per-thread state). Called once per handshake, not a hot path.
- `uint16(configChunkSize)` cast at line 76 is safe because the
  precondition is `0 < configChunkSize < 6144` — fits in uint16.
- `rand.IntN(maxIdx+1)` is always ≥ 1 argument (panic-safe) because the
  function returns early when `configChunkSize < chunkSizeSampleSet[0]`,
  so reaching the loop guarantees at least one match (`maxIdx ≥ 0`,
  `maxIdx+1 ≥ 1`).
- `chunkSizeSampleSet` is a `[4]uint16` value — not a slice — so iteration
  is bounds-safe by construction. No mutation possible.

## 6. Deployment recommendation

**Canary first.** Rationale:

- The change alters wire output for **every** session on pl1 immediately.
- Recovery from "we accidentally broke something on the data path" would
  require a server-side revert and redeploy (no env flag).
- The risk is low (analysis shows no real coupling), but the population
  using pl1 is also small, so canary cost is near zero.

**Rollback path:** revert `server/handler.go:556` to
`uint16(h.config.ChunkSize)`. The `sampleChunkSize` helper is dead-code-safe
to leave in place during canary. No client coordination needed for
rollback.

**Observability during canary:**

- Add a debug-level log line in `handleHandshakeNew` immediately after
  `sampledChunkSize := sampleChunkSize(...)` recording the value. This is
  not currently present and would help confirm distribution shape in
  production via log aggregation.
- Optional: add a counter
  `shadowlink_handshake_chunksize_sampled_total{value="6144|8192|10240|12288"}`
  to `server/metrics.go` for histogram visibility. Defer if metrics
  surface should not grow during canary.

**Phase 5 calibration hook:** the placeholder set {6144, 8192, 10240, 12288}
is uniform spacing chosen for unimodal-defeat, not real-Mixpanel-shape
fidelity. Same caveat applies as in C6 padding constants — refit against
captured Mixpanel fixture during S5 schema lock.

## 7. Misc

- File-level documentation in `chunk_size_sampler.go` is **excellent** —
  range bounds, why-uniform, why-per-session, wire-format-compatibility
  all called out with rationale. Pattern to emulate for future sampler
  additions.
- Test coverage is appropriate scope: contract / distribution / cap /
  edges / invariant. No over-testing.

## 8. Action items (none blocking)

1. (optional, defer) Consider per-session body-limit tightening (W1) as
   a separate audit item if observable correlation becomes a concern.
2. (optional) Add startup validation rejecting `chunk_size <= 0` (W2).
3. (optional) Add debug-log + metric for sampled value during canary.
4. (optional) Distribution-test tightening or seeding (S1).
5. (optional) Sampler loop expressed via "drop too-big values" style (S2).
