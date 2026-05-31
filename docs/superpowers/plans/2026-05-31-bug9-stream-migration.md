# Bug #9 — Stream Migration Implementation Plan (TDD)

**REQUIRED SUB-SKILL: `superpowers:subagent-driven-development`** — execute each task as an independent subagent dispatch with per-task spec + quality review, exactly as Bug#8 (18 tasks) and Bug#6 (9 tasks) were run. Each task is a self-contained commit on branch `new-version`.

**Source of truth:** `docs/superpowers/specs/2026-05-31-bug9-stream-migration-design.md` (REVISED-v3, 2 opus review rounds, READY). Section references below (§3.1, §4.1, §5.2, …) point at that spec.

**Reviews that shaped this:** `docs/bug9-spec-review-opus.md` (F1–F13), `docs/bug9-spec-review-opus-v2.md` (NEW-1..NEW-5).

---

## Goal

Egress-TCP (server→site) **never breaks** when a client WS slot is cut by a middlebox/TSPU by age (~90-120s), as long as migration or grace-resume succeeds. Two mechanisms:

- **A. Preemptive migration** (~80%, age-based cut): client migrates each active stream off an aging slot A onto a young slot B *before* A is cut. Server re-points the egress-TCP relay from slot A's crypto session to slot B's, transparently.
- **B. Grace-fallback** (sudden cut before threshold): server keeps the orphaned relay alive for `gracePeriod` (8s); client sends RESUME on a live slot; server reassociates.

Correctness pillar: **per-stream monotonic downlink sequence number on the wire** + **client-side reassembler** that delivers bytes to `conn.Write` strictly in seq order, so in-flight bytes arriving split across two sockets (A in-flight + B) are never reordered → no TCP-stream corruption for fast downloads, no silent hang for long quiet streams.

On any failure (no slots, grace expired, bad proof, reassembler overflow, FD-budget) the stream degrades to **breaking exactly as today** — never worse.

## Architecture

Built bottom-up in 9 layers; each layer is fully tested before the next builds on it.

```
Layer 1  CORE WIRE        core/chunk.go         FlagMigrate/Resume/StreamAck + NewStreamDataChunkSeq
Layer 2  CRYPTO PROOF     core/migrate.go       MigrateNonce + HKDF perClientKey + HMAC proof
Layer 3  CAPABILITY NEG   core/flowctl.go +     MIGRATE capability bit in keepalive marker
                          client/ws_transport.go  migrateAckTimeout fail-safe
Layer 4  SERVER REGISTRY  server/relay_registry.go  relayRegistry + relayEntry + binding atomic + state CAS
Layer 5  SERVER HANDLERS  server/websocket.go   relay-loop refactor + MIGRATE/RESUME handlers + grace + DoS/FD
Layer 6  CLIENT REASSEMBLER proxy/socks5/tcp.go reassembler in downlink-goroutine (NEW-1 gap-timeout)
Layer 7  CLIENT MIGRATION client/ws_pool.go     age-watchdog + MIGRATE/RESUME send + uplink barrier + drain coord
Layer 8  METRICS + ENV    client/stats.go +     migrate_ok/fail, orphaned gauge, env flags
                          server/metrics.go
Layer 9  INTEGRATION      *_test.go             acceptance: no-loss migration, grace-resume, anti-DPI, perf
```

### Key shared type names (consistent across all tasks — see Self-review §type-consistency)

| Name | Defined in | Used by |
|---|---|---|
| `FlagMigrate=0x0B`, `FlagResume=0x0C`, `FlagStreamAck=0x0D` | `core/chunk.go` (Task 1) | Tasks 3,5,7 |
| `NewStreamDataChunkSeq` / `ParseStreamDataSeq` | `core/chunk.go` (Task 1) | Tasks 5,6 |
| `BuildMigrateFrame` / `ParseMigrateFrame` / `BuildStreamAckFrame` / `ParseStreamAckFrame` | `core/chunk.go` (Task 1) | Tasks 5,7 |
| `Session.MigrateNonce [16]byte` | `core/session.go` (Task 2) | Tasks 4,5 |
| `DeriveServerPerClientKey` / `ComputeStreamProof` / `VerifyStreamProof` | `core/migrate.go` (Task 2) | Tasks 5,7 |
| `BuildMigrateMarker` / `ParseMigrateMarker` (capability bit) | `core/flowctl.go` (Task 3) | Tasks 5,7 |
| `binding{session,writer}` (atomic.Pointer) | `server/relay_registry.go` (Task 4) | Task 5 |
| `relayEntry` (with `downSeqCounter`, `unackedTail`, `downBuffer`, `credit`, `state`, `bound`) | `server/relay_registry.go` (Task 4) | Task 5 |
| `relayRegistry` | `server/relay_registry.go` (Task 4) | Task 5 |
| `streamFrame{seq uint64, data []byte}` | `client/client.go` (Task 6) | Tasks 6,7 |

## Tech Stack

- Go 1.25, module `github.com/nixavpn/shadowlink` (own go.mod under `shadowlink/`).
- Crypto: stdlib `crypto/hmac`, `crypto/sha256`, `crypto/rand`; `golang.org/x/crypto/hkdf` (already in go.mod `v0.49.0` — confirmed by review v2).
- Existing patterns reused: `core.Chunk` encrypted-payload control frames (FLOWCTL/WINDOW_UPDATE), `sendEpoch` `atomic.Pointer` consistent-pair idiom (`core/session.go:27,79,312`), `streamCredit` Bug#8 bucket, `WSAsyncWriter`.
- Tests: `go test ./<pkg>/ -run TestName -v`. **Windows dev host has no gcc → run plain `go test` (no `-race`).** Each `-race`/`-count=3` run is flagged as a **Linux/CI step for the user** (per CLAUDE.md Race Detector section).
- Commits: branch `new-version` (same branch Bug#6/#8 used), one commit per task.

---

# LAYER 1 — CORE WIRE FORMAT

Pure `core/` package work — frame build/parse, no networking. Tested in isolation by round-trip.

---

## Task 1 — `FlagMigrate/Resume/StreamAck` flags + control-frame build/parse

Adds the three new control flags and the build/parse functions for MIGRATE/RESUME frames (`[globalStreamID(2)][proof(32)]`) and the StreamAck frame (`[globalStreamID(2)][ackedDownSeq(8)]`). Pattern mirrors `NewWindowUpdateChunk`/`ParseWindowUpdate` (`core/chunk.go:244-260`). No crypto here — proof is an opaque 32-byte blob this task only frames/unframes.

**Files:**
- Modify: `core/chunk.go`
- Create: `core/migrate_frame_test.go`

**Steps:**

1. Write failing test `core/migrate_frame_test.go`:
   ```go
   package core

   import (
   	"bytes"
   	"testing"
   )

   func TestBuildParseMigrateFrame_RoundTrip(t *testing.T) {
   	var proof [32]byte
   	for i := range proof {
   		proof[i] = byte(i + 1)
   	}
   	p := BuildMigrateFrame(0xBEEF, proof)
   	if len(p) != 34 {
   		t.Fatalf("migrate frame len = %d, want 34", len(p))
   	}
   	gotID, gotProof, err := ParseMigrateFrame(p)
   	if err != nil {
   		t.Fatalf("ParseMigrateFrame: %v", err)
   	}
   	if gotID != 0xBEEF {
   		t.Errorf("streamID = %#x, want 0xBEEF", gotID)
   	}
   	if !bytes.Equal(gotProof[:], proof[:]) {
   		t.Errorf("proof mismatch")
   	}
   }

   func TestParseMigrateFrame_TooShort(t *testing.T) {
   	if _, _, err := ParseMigrateFrame(make([]byte, 33)); err == nil {
   		t.Fatal("expected error on 33-byte frame")
   	}
   }

   func TestBuildParseStreamAckFrame_RoundTrip(t *testing.T) {
   	p := BuildStreamAckFrame(0x1234, 0xDEADBEEFCAFE)
   	if len(p) != 10 {
   		t.Fatalf("ack frame len = %d, want 10", len(p))
   	}
   	id, seq, err := ParseStreamAckFrame(p)
   	if err != nil {
   		t.Fatalf("ParseStreamAckFrame: %v", err)
   	}
   	if id != 0x1234 || seq != 0xDEADBEEFCAFE {
   		t.Errorf("got id=%#x seq=%#x", id, seq)
   	}
   }

   func TestParseStreamAckFrame_TooShort(t *testing.T) {
   	if _, _, err := ParseStreamAckFrame(make([]byte, 9)); err == nil {
   		t.Fatal("expected error on 9-byte frame")
   	}
   }

   func TestNewControlFlagValues(t *testing.T) {
   	if FlagMigrate != 0x0B || FlagResume != 0x0C || FlagStreamAck != 0x0D {
   		t.Fatalf("flag values drifted: migrate=%#x resume=%#x ack=%#x",
   			FlagMigrate, FlagResume, FlagStreamAck)
   	}
   }
   ```

2. Run: `go test ./core/ -run 'TestBuildParseMigrateFrame|TestParseMigrateFrame|TestBuildParseStreamAck|TestParseStreamAckFrame|TestNewControlFlagValues' -v` → FAIL (undefined: FlagMigrate, BuildMigrateFrame, …).

3. Minimal impl in `core/chunk.go`. After the `FlagWindowUpdate byte = 0x0A` line (`core/chunk.go:23`):
   ```go
   	FlagMigrate   byte = 0x0B // payload = [globalStreamID(2 BE)] + [proof(32)] — preemptive migration (§3.2)
   	FlagResume    byte = 0x0C // payload = [globalStreamID(2 BE)] + [proof(32)] — reactive resume from grace
   	FlagStreamAck byte = 0x0D // payload = [globalStreamID(2 BE)] + [ackedDownSeq(8 BE)] — reassembler barrier (§3.3)
   ```
   At the end of `core/chunk.go`:
   ```go
   // BuildMigrateFrame builds the payload for a FlagMigrate / FlagResume control
   // chunk: [globalStreamID(2 BE)] + [proof(32)]. proof is an opaque HMAC token
   // (see core/migrate.go); this function does not interpret it. §3.3.
   func BuildMigrateFrame(streamID uint16, proof [32]byte) []byte {
   	p := make([]byte, 2+32)
   	binary.BigEndian.PutUint16(p[0:2], streamID)
   	copy(p[2:], proof[:])
   	return p
   }

   // ParseMigrateFrame extracts streamID and proof from a FlagMigrate/FlagResume
   // payload. Errors (never panics) on payload shorter than 34 bytes.
   func ParseMigrateFrame(payload []byte) (streamID uint16, proof [32]byte, err error) {
   	if len(payload) < 34 {
   		return 0, proof, fmt.Errorf("migrate frame too short: %d < 34", len(payload))
   	}
   	streamID = binary.BigEndian.Uint16(payload[0:2])
   	copy(proof[:], payload[2:34])
   	return streamID, proof, nil
   }

   // BuildStreamAckFrame builds the payload for a FlagStreamAck chunk:
   // [globalStreamID(2 BE)] + [ackedDownSeq(8 BE)]. §3.3.
   func BuildStreamAckFrame(streamID uint16, ackedDownSeq uint64) []byte {
   	p := make([]byte, 2+8)
   	binary.BigEndian.PutUint16(p[0:2], streamID)
   	binary.BigEndian.PutUint64(p[2:10], ackedDownSeq)
   	return p
   }

   // ParseStreamAckFrame extracts streamID and ackedDownSeq from a FlagStreamAck
   // payload. Errors (never panics) on payload shorter than 10 bytes.
   func ParseStreamAckFrame(payload []byte) (streamID uint16, ackedDownSeq uint64, err error) {
   	if len(payload) < 10 {
   		return 0, 0, fmt.Errorf("stream ack frame too short: %d < 10", len(payload))
   	}
   	streamID = binary.BigEndian.Uint16(payload[0:2])
   	ackedDownSeq = binary.BigEndian.Uint64(payload[2:10])
   	return streamID, ackedDownSeq, nil
   }
   ```

4. Run: `go test ./core/ -run 'TestBuildParseMigrateFrame|TestParseMigrateFrame|TestBuildParseStreamAck|TestParseStreamAckFrame|TestNewControlFlagValues' -v` → PASS. Also `go build ./...`.

5. Commit: `git add core/chunk.go core/migrate_frame_test.go && git commit -m "feat(bug9): core wire — FlagMigrate/Resume/StreamAck flags + frame build/parse"`

---

## Task 2 — Per-stream downlink seq data-chunk format (`NewStreamDataChunkSeq` / `ParseStreamDataSeq`)

The base for the reassembler (F1, §3.1). New data-chunk payload format `[StreamID(2 BE)][downSeq(8 BE)][data]`, gated per-session by capability (Task 3). Legacy `NewStreamDataChunk` (`core/chunk.go:191`) stays untouched (capability=off path). Reserves `downSeq=0` for control (NEW-2): the seq constructor takes the seq explicitly so callers (server relay-loop) control it; control chunks use the legacy constructor (no seq), so they are distinguished on the wire by length (`<10` after streamID, see Task 6 guard) — but to keep parse unambiguous in seq-mode, the seq parser is only used when capability is on.

**Files:**
- Modify: `core/chunk.go`
- Modify: `core/migrate_frame_test.go`

**Steps:**

1. Write failing test (append to `core/migrate_frame_test.go`):
   ```go
   func TestNewStreamDataChunkSeq_RoundTrip(t *testing.T) {
   	data := []byte("hello-world-payload")
   	c := NewStreamDataChunkSeq(7, 99, 0xABCD, 42, data)
   	if c.Flags != FlagData {
   		t.Fatalf("flags = %#x, want FlagData", c.Flags)
   	}
   	// payload = streamID(2) + downSeq(8) + data
   	if len(c.Payload) != 2+8+len(data) {
   		t.Fatalf("payload len = %d, want %d", len(c.Payload), 2+8+len(data))
   	}
   	gotID, gotSeq, gotData, err := ParseStreamDataSeq(c.Payload)
   	if err != nil {
   		t.Fatalf("ParseStreamDataSeq: %v", err)
   	}
   	if gotID != 0xABCD || gotSeq != 42 {
   		t.Errorf("got id=%#x seq=%d", gotID, gotSeq)
   	}
   	if string(gotData) != string(data) {
   		t.Errorf("data mismatch: %q", gotData)
   	}
   	PutBuffer(c.Payload) // pooled backing, like NewStreamDataChunk
   }

   func TestParseStreamDataSeq_TooShort(t *testing.T) {
   	// 9 bytes < 10 (2 streamID + 8 seq) → error, NOT a misparse.
   	if _, _, _, err := ParseStreamDataSeq(make([]byte, 9)); err == nil {
   		t.Fatal("expected error on 9-byte seq payload")
   	}
   }

   func TestParseStreamDataSeq_EmptyData(t *testing.T) {
   	// exactly 10 bytes = streamID + seq, zero data — valid (control-sized data chunk).
   	c := NewStreamDataChunkSeq(1, 1, 5, 1, nil)
   	id, seq, data, err := ParseStreamDataSeq(c.Payload)
   	if err != nil || id != 5 || seq != 1 || len(data) != 0 {
   		t.Fatalf("got id=%d seq=%d data=%v err=%v", id, seq, data, err)
   	}
   	PutBuffer(c.Payload)
   }
   ```

2. Run: `go test ./core/ -run 'TestNewStreamDataChunkSeq|TestParseStreamDataSeq' -v` → FAIL (undefined).

3. Minimal impl in `core/chunk.go`, next to `NewStreamDataChunk`:
   ```go
   // NewStreamDataChunkSeq creates a data chunk carrying a per-stream monotonic
   // downlink sequence number (Bug #9 §3.1, F1). Payload format:
   //   [StreamID(2 BE)] + [downSeq(8 BE)] + [data]
   //
   // downSeq is assigned by the SERVER relay-loop (relayEntry.downSeqCounter,
   // §5.1) and survives slot migration — it is the ordering key the client-side
   // reassembler uses (§5.4). downSeq==0 is RESERVED for control chunks
   // (CONNECT_OK/FAIL) which use the legacy NewStreamDataChunk; the first real
   // data chunk is downSeq==1 (NEW-2).
   //
   // Like NewStreamDataChunk the returned Payload uses a pooled backing array;
   // callers MUST release it via core.PutBuffer(chunk.Payload) after encrypting.
   func NewStreamDataChunkSeq(sessID, seq uint32, streamID uint16, downSeq uint64, payload []byte) *Chunk {
   	pSize := 2 + 8 + len(payload)
   	pBuf := GetBuffer(pSize)
   	p := pBuf[:pSize]
   	binary.BigEndian.PutUint16(p[0:2], streamID)
   	binary.BigEndian.PutUint64(p[2:10], downSeq)
   	copy(p[10:], payload)
   	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagData, Payload: p}
   }

   // ParseStreamDataSeq extracts streamID, downSeq and data from a seq-format
   // data payload (§3.1). Errors (never panics) on payload shorter than 10 bytes
   // — the client guard MUST reject such frames rather than misparse them as the
   // legacy [StreamID(2)]+[data] format (NEW-2, see ws_pool guard <10).
   func ParseStreamDataSeq(payload []byte) (streamID uint16, downSeq uint64, data []byte, err error) {
   	if len(payload) < 10 {
   		return 0, 0, nil, fmt.Errorf("seq data payload too short: %d < 10", len(payload))
   	}
   	streamID = binary.BigEndian.Uint16(payload[0:2])
   	downSeq = binary.BigEndian.Uint64(payload[2:10])
   	return streamID, downSeq, payload[10:], nil
   }
   ```

4. Run: `go test ./core/ -run 'TestNewStreamDataChunkSeq|TestParseStreamDataSeq' -v` → PASS. `go test ./core/ -v` (full pkg) to confirm no regression. `go build ./...`.

5. Commit: `git add core/chunk.go core/migrate_frame_test.go && git commit -m "feat(bug9): core wire — NewStreamDataChunkSeq per-stream downlink seq format (F1, NEW-2)"`

---

# LAYER 2 — CRYPTO PROOF-OF-OWNERSHIP

Stateless HMAC proof (F2/F12, §4.1). Server holds only `serverMasterKey`; derives a per-client key via HKDF; the per-stream secret is `HMAC(perClientKey, clientID‖globalStreamID‖session_nonce)`. The 16-byte `session_nonce` from `crypto/rand` is the per-device binding discriminator (a second device of the same clientID cannot read nonce A → cannot forge proof). Pure `core/` package — no networking.

---

## Task 3 — `Session.MigrateNonce` (crypto/rand 16 bytes)

Adds the per-session nonce field and its initialization (§4.1, F2). It must be `crypto/rand`, NOT derived from `session.ID` (which is sequential `uint32` — `core/session.go:33`).

**Files:**
- Modify: `core/session.go`
- Create: `core/migrate_nonce_test.go`

**Steps:**

1. Write failing test `core/migrate_nonce_test.go`:
   ```go
   package core

   import (
   	"bytes"
   	"testing"
   )

   func TestNewSession_MigrateNonce_NonZero(t *testing.T) {
   	s := NewSession(1, make([]byte, 32), make([]byte, 32))
   	var zero [16]byte
   	if bytes.Equal(s.MigrateNonce[:], zero[:]) {
   		t.Fatal("MigrateNonce is all-zero — must be seeded from crypto/rand")
   	}
   }

   func TestNewSession_MigrateNonce_DistinctPerSession(t *testing.T) {
   	a := NewSession(1, make([]byte, 32), make([]byte, 32))
   	b := NewSession(2, make([]byte, 32), make([]byte, 32))
   	if bytes.Equal(a.MigrateNonce[:], b.MigrateNonce[:]) {
   		t.Fatal("two sessions share a MigrateNonce — must be independent random")
   	}
   }

   func TestNewSession_MigrateNonce_NotDerivedFromID(t *testing.T) {
   	// Sequential IDs must NOT produce predictable/correlated nonces.
   	s := NewSession(0x01020304, make([]byte, 32), make([]byte, 32))
   	// First 4 bytes must not equal the big-endian session ID (anti "nonce=ID" regression).
   	if s.MigrateNonce[0] == 0x01 && s.MigrateNonce[1] == 0x02 &&
   		s.MigrateNonce[2] == 0x03 && s.MigrateNonce[3] == 0x04 {
   		t.Fatal("MigrateNonce appears derived from session.ID")
   	}
   }
   ```

2. Run: `go test ./core/ -run 'TestNewSession_MigrateNonce' -v` → FAIL (Session has no field MigrateNonce).

3. Minimal impl. In `core/session.go`, add field to `Session` struct (after `MimicrySession *MimicrySession`, ~`:96`):
   ```go
   	// MigrateNonce is a 16-byte crypto/rand nonce stamped at session creation.
   	// It is the per-device binding discriminator for Bug #9 stream-migration
   	// proof-of-ownership (§4.1, F2): the stream secret is
   	// HMAC(serverPerClientKey, clientID‖globalStreamID‖MigrateNonce). A second
   	// device of the same clientID cannot read this nonce (it travels only inside
   	// the encrypted CONNECT reply of the originating session), so it cannot
   	// forge a proof for a stream it does not own. MUST be crypto/rand — NEVER
   	// derived from session.ID (sequential, guessable). Read-only after creation.
   	MigrateNonce [16]byte
   ```
   In `NewSession` (`core/session.go:114`), seed it before returning:
   ```go
   func NewSession(id uint32, sendKey, recvKey []byte) *Session {
   	now := time.Now()
   	s := &Session{
   		ID:           id,
   		SendKey:      sendKey,
   		RecvKey:      recvKey,
   		lastActivity: now,
   		CreatedAt:    now,
   		lastRekey:    now,
   	}
   	// Bug #9 §4.1: per-session migration nonce from crypto/rand. Ignore the
   	// error path the same way the rest of core does for rand.Read on a 16-byte
   	// buffer — a failing system CSPRNG is fatal elsewhere; here a zero nonce
   	// would only make migration proofs unverifiable (fail-closed to no
   	// migration), never insecure.
   	_, _ = rand.Read(s.MigrateNonce[:])
   	return s
   }
   ```
   (`rand` = `crypto/rand`, already imported in `core/session.go:6`.)

4. Run: `go test ./core/ -run 'TestNewSession_MigrateNonce' -v` → PASS. `go test ./core/ -v` full pkg → confirm no regression (other NewSession callers unaffected). `go build ./...`.

5. Commit: `git add core/session.go core/migrate_nonce_test.go && git commit -m "feat(bug9): core — Session.MigrateNonce (crypto/rand 16B per-device binding, F2)"`

---

## Task 4 — HKDF per-client key + HMAC stream proof (`core/migrate.go`)

The actual proof primitives (§4.1, F2/F12). `DeriveServerPerClientKey` (HKDF-SHA256), `ComputeStreamProof` (HMAC-SHA256), `VerifyStreamProof` (constant-time `hmac.Equal`). Tests cover valid/invalid/foreign-clientID/foreign-nonce (replay & second-device).

**Files:**
- Create: `core/migrate.go`
- Create: `core/migrate_proof_test.go`

**Steps:**

1. Write failing test `core/migrate_proof_test.go`:
   ```go
   package core

   import "testing"

   func TestDeriveServerPerClientKey_Deterministic(t *testing.T) {
   	master := make([]byte, 32)
   	for i := range master {
   		master[i] = byte(i)
   	}
   	k1 := DeriveServerPerClientKey(master, "client-A")
   	k2 := DeriveServerPerClientKey(master, "client-A")
   	if len(k1) != 32 {
   		t.Fatalf("perClientKey len = %d, want 32", len(k1))
   	}
   	if string(k1) != string(k2) {
   		t.Fatal("HKDF not deterministic for same clientID")
   	}
   	kB := DeriveServerPerClientKey(master, "client-B")
   	if string(k1) == string(kB) {
   		t.Fatal("different clientIDs must yield different keys")
   	}
   }

   func TestStreamProof_ValidVerifies(t *testing.T) {
   	master := make([]byte, 32)
   	key := DeriveServerPerClientKey(master, "client-A")
   	var nonce [16]byte
   	nonce[0] = 0x42
   	proof := ComputeStreamProof(key, "client-A", 0xABCD, nonce)
   	if !VerifyStreamProof(proof, key, "client-A", 0xABCD, nonce) {
   		t.Fatal("valid proof did not verify")
   	}
   }

   func TestStreamProof_WrongStreamIDFails(t *testing.T) {
   	master := make([]byte, 32)
   	key := DeriveServerPerClientKey(master, "client-A")
   	var nonce [16]byte
   	proof := ComputeStreamProof(key, "client-A", 0xABCD, nonce)
   	if VerifyStreamProof(proof, key, "client-A", 0x0001, nonce) {
   		t.Fatal("proof verified for the wrong streamID")
   	}
   }

   func TestStreamProof_ForeignClientFails(t *testing.T) {
   	master := make([]byte, 32)
   	keyA := DeriveServerPerClientKey(master, "client-A")
   	keyB := DeriveServerPerClientKey(master, "client-B")
   	var nonce [16]byte
   	proof := ComputeStreamProof(keyA, "client-A", 0xABCD, nonce)
   	// Attacker is client-B: different perClientKey → cannot verify.
   	if VerifyStreamProof(proof, keyB, "client-B", 0xABCD, nonce) {
   		t.Fatal("foreign clientID forged a proof")
   	}
   }

   func TestStreamProof_ForeignNonceFails(t *testing.T) {
   	// Same clientID, second device: different session_nonce → cannot verify
   	// (F2 per-device binding + replay defence).
   	master := make([]byte, 32)
   	key := DeriveServerPerClientKey(master, "client-A")
   	var nonceA, nonceB [16]byte
   	nonceA[0] = 0x01
   	nonceB[0] = 0x02
   	proof := ComputeStreamProof(key, "client-A", 0xABCD, nonceA)
   	if VerifyStreamProof(proof, key, "client-A", 0xABCD, nonceB) {
   		t.Fatal("proof verified under a different session_nonce (second-device/replay)")
   	}
   }
   ```

2. Run: `go test ./core/ -run 'TestDeriveServerPerClientKey|TestStreamProof' -v` → FAIL (no such package symbols).

3. Minimal impl `core/migrate.go`:
   ```go
   package core

   import (
   	"crypto/hmac"
   	"crypto/sha256"
   	"encoding/binary"
   	"io"

   	"golang.org/x/crypto/hkdf"
   )

   // migrateHKDFSalt domain-separates the migration KDF from any other use of the
   // server master key. §4.1.
   var migrateHKDFSalt = []byte("shadowlink-migrate-v1")

   // DeriveServerPerClientKey derives a 32-byte per-client key from the server
   // master key via HKDF-SHA256 (salt fixed, info = clientID). Deterministic and
   // stateless — the server recomputes it on the fly, storing no per-client
   // secret (§4.1, F2).
   func DeriveServerPerClientKey(serverMasterKey []byte, clientID string) []byte {
   	r := hkdf.New(sha256.New, serverMasterKey, migrateHKDFSalt, []byte(clientID))
   	out := make([]byte, 32)
   	if _, err := io.ReadFull(r, out); err != nil {
   		// HKDF-Expand over SHA-256 for 32 bytes cannot fail in practice; return
   		// zeros so a downstream VerifyStreamProof fails closed rather than panic.
   		return make([]byte, 32)
   	}
   	return out
   }

   // ComputeStreamProof = HMAC-SHA256(perClientKey, clientID ‖ globalStreamID(2 BE)
   // ‖ session_nonce(16)). This is the 32-byte proofToken the client presents in
   // MIGRATE/RESUME (§3.3, §4.1).
   func ComputeStreamProof(perClientKey []byte, clientID string, globalStreamID uint16, nonce [16]byte) [32]byte {
   	mac := hmac.New(sha256.New, perClientKey)
   	mac.Write([]byte(clientID))
   	var idBuf [2]byte
   	binary.BigEndian.PutUint16(idBuf[:], globalStreamID)
   	mac.Write(idBuf[:])
   	mac.Write(nonce[:])
   	var out [32]byte
   	copy(out[:], mac.Sum(nil))
   	return out
   }

   // VerifyStreamProof recomputes the proof and compares in constant time
   // (crypto/hmac.Equal — F12; NEVER bytes.Equal).
   func VerifyStreamProof(received [32]byte, perClientKey []byte, clientID string, globalStreamID uint16, nonce [16]byte) bool {
   	expected := ComputeStreamProof(perClientKey, clientID, globalStreamID, nonce)
   	return hmac.Equal(received[:], expected[:])
   }
   ```

4. Run: `go test ./core/ -run 'TestDeriveServerPerClientKey|TestStreamProof' -v` → PASS. `go build ./...`.
   **User/CI step (Linux, gcc):** `go test -race -count=3 ./core/` once Layers 1-2 land.

5. Commit: `git add core/migrate.go core/migrate_proof_test.go && git commit -m "feat(bug9): core — HKDF perClientKey + HMAC stream proof (F2, F12)"`

---

# LAYER 3 — CAPABILITY NEGOTIATION

Extends the existing FLOWCTL keepalive marker (`core/flowctl.go`) with a MIGRATE capability bit, and wires the client/server handshake to learn each other's support (§3.5). Plus the `migrateAckTimeout` fail-safe constant + hysteresis (F3). Off → legacy seq-less wire path, behaviour exactly as today.

---

## Task 5 — MIGRATE capability bit in the FLOWCTL marker

Extends `BuildFlowCtlMarker`/`ParseFlowCtlMarker` (`core/flowctl.go`) to carry a 1-byte capability flags field after the window, backwards-compatible: an 11-byte (old) marker parses with `migrate=false`; a 12-byte marker carries the bit. This reuses the Bug#8 mechanism (§3.5) instead of inventing a new keepalive.

**Files:**
- Modify: `core/flowctl.go`
- Create: `core/flowctl_migrate_test.go`

**Steps:**

1. Write failing test `core/flowctl_migrate_test.go`:
   ```go
   package core

   import "testing"

   func TestFlowCtlMarker_MigrateBit_RoundTrip(t *testing.T) {
   	p := BuildFlowCtlMarkerV2(1<<20, true)
   	win, migrate, ok := ParseFlowCtlMarkerV2(p)
   	if !ok {
   		t.Fatal("V2 marker did not parse")
   	}
   	if win != 1<<20 {
   		t.Errorf("window = %d, want %d", win, 1<<20)
   	}
   	if !migrate {
   		t.Error("migrate bit lost")
   	}
   }

   func TestFlowCtlMarker_MigrateBitOff(t *testing.T) {
   	p := BuildFlowCtlMarkerV2(4096, false)
   	_, migrate, ok := ParseFlowCtlMarkerV2(p)
   	if !ok || migrate {
   		t.Fatalf("ok=%v migrate=%v, want ok=true migrate=false", ok, migrate)
   	}
   }

   func TestFlowCtlMarker_LegacyParsesAsNoMigrate(t *testing.T) {
   	// An old 11-byte marker (no capability byte) must parse: window OK, migrate=false.
   	old := BuildFlowCtlMarker(2048)
   	win, migrate, ok := ParseFlowCtlMarkerV2(old)
   	if !ok || win != 2048 || migrate {
   		t.Fatalf("legacy compat broke: ok=%v win=%d migrate=%v", ok, win, migrate)
   	}
   }

   func TestFlowCtlMarker_OldParserIgnoresExtraByte(t *testing.T) {
   	// The old ParseFlowCtlMarker must still read window from a V2 (12-byte) marker
   	// (forward compat for an old peer reading a new marker).
   	p := BuildFlowCtlMarkerV2(777, true)
   	win, ok := ParseFlowCtlMarker(p)
   	if !ok || win != 777 {
   		t.Fatalf("old parser on V2 marker: ok=%v win=%d", ok, win)
   	}
   }
   ```

2. Run: `go test ./core/ -run 'TestFlowCtlMarker_Migrate|TestFlowCtlMarker_Legacy|TestFlowCtlMarker_Old' -v` → FAIL.

3. Minimal impl in `core/flowctl.go`. Add the capability-bit constants and V2 build/parse; keep `ParseFlowCtlMarker` working on both lengths:
   ```go
   const flowCtlMarkerLenV2 = 7 + 4 + 1 // magic(7) + window(4) + capFlags(1)

   // Capability flag bits in the optional 12th byte of the FLOWCTL marker.
   const flowCapMigrate byte = 0x01 // peer supports Bug #9 stream migration (§3.5)

   // BuildFlowCtlMarkerV2 builds the 12-byte capability+window advertisement:
   //   ["FLOWCTL"(7)] + [window(4 BE)] + [capFlags(1)]
   // The extra byte is invisible to an old peer's ParseFlowCtlMarker (it reads
   // only the first 11 bytes). §3.5.
   func BuildFlowCtlMarkerV2(window uint32, migrate bool) []byte {
   	p := make([]byte, flowCtlMarkerLenV2)
   	copy(p[:7], flowCtlMagic)
   	binary.BigEndian.PutUint32(p[7:11], window)
   	if migrate {
   		p[11] |= flowCapMigrate
   	}
   	return p
   }

   // ParseFlowCtlMarkerV2 reports window + migrate-capability. A legacy 11-byte
   // marker parses with migrate=false (backwards compat). ok=false for any
   // non-marker payload.
   func ParseFlowCtlMarkerV2(payload []byte) (window uint32, migrate bool, ok bool) {
   	if len(payload) < flowCtlMarkerLen { // 11 — magic + window minimum
   		return 0, false, false
   	}
   	for i := 0; i < 7; i++ {
   		if payload[i] != flowCtlMagic[i] {
   			return 0, false, false
   		}
   	}
   	window = binary.BigEndian.Uint32(payload[7:11])
   	if len(payload) >= flowCtlMarkerLenV2 {
   		migrate = payload[11]&flowCapMigrate != 0
   	}
   	return window, migrate, true
   }
   ```
   `ParseFlowCtlMarker` is unchanged — it already reads only `payload[7:11]` and tolerates a longer slice (its `len < flowCtlMarkerLen` guard passes for 12 bytes).

4. Run: `go test ./core/ -run 'TestFlowCtlMarker' -v` → PASS. `go test ./core/ -v` → confirm existing FLOWCTL tests still pass. `go build ./...`.

5. Commit: `git add core/flowctl.go core/flowctl_migrate_test.go && git commit -m "feat(bug9): core — MIGRATE capability bit in FLOWCTL marker (§3.5, compat-safe)"`

---

## Task 6 — Client/server capability wiring + `migrateAckTimeout` + hysteresis state

Wires the negotiation end-to-end: client advertises the migrate bit in its first-keepalive marker; server parses it in `authenticateFirstFrame` and returns whether migration is enabled for the session; client reads it back. Adds the `migrateAckTimeout` constant and the per-stream pending-ack registry + ≥3-timeout hysteresis flag (F3). This task only adds the plumbing/state and a `migrationEnabled` gate — the actual MIGRATE send is Task 12. Gated by env `SHADOWLINK_STREAM_MIGRATION` (default on, parsed here).

**Files:**
- Modify: `client/ws_transport.go` (advertise + read-back; constant)
- Modify: `server/websocket.go` (`authenticateFirstFrame` parses migrate bit, plumbs `migrateEnabled` to `runWebSocketSession`)
- Modify: `server/handler.go` (no behavior change yet — confirm `flowMaxWindow` field reachable; add `migrationEnabled config gate`)
- Create: `client/migrate_capability_test.go`
- Create: `server/migrate_capability_test.go`

**Steps:**

1. Write failing client test `client/migrate_capability_test.go`:
   ```go
   package client

   import (
   	"os"
   	"testing"
   )

   func TestStreamMigrationEnabledFromEnv(t *testing.T) {
   	t.Setenv("SHADOWLINK_STREAM_MIGRATION", "")
   	if !streamMigrationEnabledFromEnv() {
   		t.Error("default (unset) should be ON")
   	}
   	for _, off := range []string{"0", "false", "no", "off", "OFF"} {
   		os.Setenv("SHADOWLINK_STREAM_MIGRATION", off)
   		if streamMigrationEnabledFromEnv() {
   			t.Errorf("%q should disable migration", off)
   		}
   	}
   	t.Setenv("SHADOWLINK_STREAM_MIGRATION", "1")
   	if !streamMigrationEnabledFromEnv() {
   		t.Error("=1 should be ON")
   	}
   }

   func TestMigrateAckTimeout_Value(t *testing.T) {
   	if migrateAckTimeout <= 0 {
   		t.Fatal("migrateAckTimeout must be positive")
   	}
   }
   ```

2. Write failing server test `server/migrate_capability_test.go`:
   ```go
   package server

   import "testing"

   func TestNegotiateMigration(t *testing.T) {
   	// server supports migration AND client advertised → enabled
   	if !negotiateMigration(true, true) {
   		t.Error("both support → enabled")
   	}
   	if negotiateMigration(false, true) {
   		t.Error("server off → disabled")
   	}
   	if negotiateMigration(true, false) {
   		t.Error("client off → disabled")
   	}
   }
   ```

3. Run both → FAIL (undefined `streamMigrationEnabledFromEnv`, `migrateAckTimeout`, `negotiateMigration`).

4. Minimal impl:
   - In `client/ws_transport.go`, add near `negotiationAckTimeout` (`:612`):
     ```go
     // migrateAckTimeout bounds how long the client waits for a MIGRATE_OK /
     // RESUME_OK before degrading the stream to a hard break (F3 fail-safe,
     // §3.5). Same order as the first-frame negotiation window so an old server
     // that silently ignores FlagMigrate never hangs a stream.
     const migrateAckTimeout = 1500 * time.Millisecond

     // streamMigrationEnabledFromEnv resolves SHADOWLINK_STREAM_MIGRATION.
     // Default ON; 0/false/no/off (case-insensitive) disables. Main kill-switch (§7).
     func streamMigrationEnabledFromEnv() bool {
     	v := strings.ToLower(strings.TrimSpace(os.Getenv("SHADOWLINK_STREAM_MIGRATION")))
     	switch v {
     	case "0", "false", "no", "off":
     		return false
     	default:
     		return true
     	}
     }
     ```
     (`os`, `strings`, `time` already imported in this file.)
   - Where the client builds its first-keepalive FLOWCTL marker (`client/ws_transport.go:725` `keepalive.Payload = core.BuildFlowCtlMarker(flowWindow)`), switch to V2 carrying the migrate bit:
     ```go
     keepalive.Payload = core.BuildFlowCtlMarkerV2(flowWindow, streamMigrationEnabledFromEnv()) // inside AES-GCM
     ```
   - Where the client reads the server's FLOWCTL-ack (`client/ws_transport.go:539` `parseFlowAckPayload`), also capture the migrate bit. Add a field `flowMigrateEnabled bool` to the transport struct and set it from `ParseFlowCtlMarkerV2`:
     ```go
     if win, migrate, okFlow := core.ParseFlowCtlMarkerV2(ackChunk.Payload); okFlow {
     	t.flowControlEnabled = true
     	t.flowWindow = win
     	t.flowMigrateEnabled = migrate
     }
     ```
     (Locate the existing `parseFlowAckPayload` helper at `:737`; replace its body to call `ParseFlowCtlMarkerV2` returning `(win, migrate, ok)` OR add a sibling `parseFlowAckPayloadV2`. Keep `parseFlowAckPayload` for any other caller; the read-back site uses the V2 form.)
   - In `server/websocket.go` `authenticateFirstFrame` (`:196`), after parsing the FLOWCTL marker, parse the migrate bit and echo it in the ack:
     ```go
     var migrateAdvertised bool
     if cw, mig, okFlow := core.ParseFlowCtlMarkerV2(chunk.Payload); okFlow {
     	migrateAdvertised = mig
     	effectiveWindow = negotiateFlowWindow(cw, uint32(h.flowMaxWindow))
     	// ... existing ack send, but build the ack marker as V2:
     	//   Payload: core.BuildFlowCtlMarkerV2(effectiveWindow, negotiateMigration(h.migrationEnabled, migrateAdvertised))
     }
     ```
     Change `authenticateFirstFrame` return signature to `(*core.Session, uint32, bool)` (third = migrateEnabled) and thread it through `handleWebSocket` (`:467`) into `runWebSocketSession`, adding a `migrateEnabled bool` param. (Where migration is off, the relay loop in Task 9 stays on the legacy `NewStreamDataChunk` path.)
   - Add `negotiateMigration` helper in `server/stream_credit.go` (next to `negotiateFlowWindow`):
     ```go
     // negotiateMigration reports whether Bug #9 stream migration is enabled for a
     // session: both the server config and the client's advertised capability must
     // agree (§3.5).
     func negotiateMigration(serverEnabled, clientAdvertised bool) bool {
     	return serverEnabled && clientAdvertised
     }
     ```
   - Add `migrationEnabled bool` to `Handler` (server/handler.go) initialized from config (default true); add `config.StreamMigrationEnabled`. Wire the env on the **server** side in `cmd/shadowlink-server/main.go` (Task 17 finalizes env table, but the bool field + default must exist now so `negotiateMigration(h.migrationEnabled, …)` compiles). Default `true`.

5. Run: `go test ./client/ -run 'TestStreamMigrationEnabledFromEnv|TestMigrateAckTimeout' -v` and `go test ./server/ -run 'TestNegotiateMigration' -v` → PASS. `go build ./...`. `go test ./server/ -run TestAuthenticateFirstFrame -v` (existing) → confirm no regression in the auth path.

6. Commit: `git add client/ws_transport.go server/websocket.go server/stream_credit.go server/handler.go cmd/shadowlink-server/main.go client/migrate_capability_test.go server/migrate_capability_test.go && git commit -m "feat(bug9): capability negotiation wiring + migrateAckTimeout + SHADOWLINK_STREAM_MIGRATION gate (§3.5, F3)"`

---

# LAYER 4 — SERVER RELAY REGISTRY

The new `server/relay_registry.go`: a server-level registry of relays keyed `(clientID, globalStreamID)` that lives independently of any one WS session. This layer builds the data structures + state machine + buffers in isolation (no relay-loop refactor yet — that's Layer 5). All unit-testable without networking.

---

## Task 7 — `binding` atomic pair + `boundedBuffer` + `relayEntry` skeleton

The NEW-5 single-atomic-pointer pair `binding{session,writer}`, the bounded FIFO buffer used by both `downBuffer` and `unackedTail`, and the `relayEntry` struct with its fields (no behavior beyond construct/get/set). Models the `sendEpoch` idiom (`core/session.go:27`).

**Files:**
- Create: `server/relay_registry.go`
- Create: `server/relay_registry_test.go`

**Steps:**

1. Write failing test `server/relay_registry_test.go`:
   ```go
   package server

   import (
   	"sync"
   	"testing"

   	"github.com/nixavpn/shadowlink/core"
   )

   func TestBinding_AtomicConsistentPair(t *testing.T) {
   	var e relayEntry
   	sA := core.NewSession(1, make([]byte, 32), make([]byte, 32))
   	sB := core.NewSession(2, make([]byte, 32), make([]byte, 32))
   	wA := core.NewWSAsyncWriter(nil, 8)
   	wB := core.NewWSAsyncWriter(nil, 8)
   	e.bound.Store(&binding{session: sA, writer: wA})

   	// Concurrent readers must always see a matching pair (never sA+wB).
   	var wg sync.WaitGroup
   	stop := make(chan struct{})
   	for i := 0; i < 4; i++ {
   		wg.Add(1)
   		go func() {
   			defer wg.Done()
   			for {
   				select {
   				case <-stop:
   					return
   				default:
   				}
   				b := e.bound.Load()
   				if b == nil {
   					continue
   				}
   				if (b.session == sA) != (b.writer == wA) {
   					t.Errorf("torn pair: session/writer mismatch")
   					return
   				}
   			}
   		}()
   	}
   	for i := 0; i < 1000; i++ {
   		if i%2 == 0 {
   			e.bound.Store(&binding{session: sA, writer: wA})
   		} else {
   			e.bound.Store(&binding{session: sB, writer: wB})
   		}
   	}
   	close(stop)
   	wg.Wait()
   }

   func TestBoundedBuffer_PushPopOrder(t *testing.T) {
   	b := newBoundedBuffer(1024)
   	b.Push(pendingDownFrame{seq: 1, data: []byte("a")})
   	b.Push(pendingDownFrame{seq: 2, data: []byte("bb")})
   	if b.byteLen() != 3 {
   		t.Fatalf("byteLen = %d, want 3", b.byteLen())
   	}
   	frames := b.drainAll()
   	if len(frames) != 2 || frames[0].seq != 1 || frames[1].seq != 2 {
   		t.Fatalf("drain order wrong: %+v", frames)
   	}
   	if b.byteLen() != 0 {
   		t.Fatalf("byteLen after drain = %d, want 0", b.byteLen())
   	}
   }

   func TestBoundedBuffer_FullRejects(t *testing.T) {
   	b := newBoundedBuffer(4)
   	if !b.Push(pendingDownFrame{seq: 1, data: []byte("abcd")}) {
   		t.Fatal("first push of exactly-cap should succeed")
   	}
   	if b.Push(pendingDownFrame{seq: 2, data: []byte("x")}) {
   		t.Fatal("push past cap must be rejected (backpressure)")
   	}
   }

   func TestBoundedBuffer_AckEvictsUpToSeq(t *testing.T) {
   	b := newBoundedBuffer(1024)
   	b.Push(pendingDownFrame{seq: 1, data: []byte("a")})
   	b.Push(pendingDownFrame{seq: 2, data: []byte("b")})
   	b.Push(pendingDownFrame{seq: 3, data: []byte("c")})
   	b.evictUpTo(2) // drop seq<=2
   	frames := b.drainAll()
   	if len(frames) != 1 || frames[0].seq != 3 {
   		t.Fatalf("after evictUpTo(2): %+v", frames)
   	}
   }
   ```

2. Run: `go test ./server/ -run 'TestBinding_AtomicConsistentPair|TestBoundedBuffer' -v` → FAIL.

3. Minimal impl `server/relay_registry.go`:
   ```go
   package server

   import (
   	"sync"
   	"sync/atomic"

   	"github.com/nixavpn/shadowlink/core"
   )

   // pendingDownFrame is one downlink chunk captured under its assigned downSeq.
   // Buffered either while there is no active binding (downBuffer) or as the
   // not-yet-acked tail after a preemptive migration (unackedTail). §5.1/§5.3.
   type pendingDownFrame struct {
   	seq  uint64
   	data []byte
   }

   // binding packs the crypto session and async writer of the CURRENTLY active
   // slot into one unit so the relay-loop reads a consistent pair under a single
   // atomic.Load (NEW-5). Mirrors core.sendEpoch{gcm, nonce} under one
   // atomic.Pointer (core/session.go:27,79,312).
   type binding struct {
   	session *core.Session
   	writer  *core.WSAsyncWriter
   }

   // boundedBuffer is a FIFO of pendingDownFrame capped by total payload bytes
   // (≤ 1 flow-window, §4.2). Push returns false when full (caller applies
   // backpressure by not reading the egress-TCP). Not safe for concurrent use —
   // callers hold relayEntry.perEntryMu.
   type boundedBuffer struct {
   	frames  []pendingDownFrame
   	bytes   int
   	maxByte int
   }

   func newBoundedBuffer(maxByte int) *boundedBuffer {
   	return &boundedBuffer{maxByte: maxByte}
   }

   func (b *boundedBuffer) Push(f pendingDownFrame) bool {
   	if b.bytes+len(f.data) > b.maxByte {
   		return false
   	}
   	b.frames = append(b.frames, f)
   	b.bytes += len(f.data)
   	return true
   }

   func (b *boundedBuffer) byteLen() int { return b.bytes }

   // drainAll returns all buffered frames in FIFO order and empties the buffer.
   func (b *boundedBuffer) drainAll() []pendingDownFrame {
   	out := b.frames
   	b.frames = nil
   	b.bytes = 0
   	return out
   }

   // evictUpTo drops all frames with seq <= ackedSeq (FlagStreamAck barrier, §5.4).
   func (b *boundedBuffer) evictUpTo(ackedSeq uint64) {
   	kept := b.frames[:0]
   	bytes := 0
   	for _, f := range b.frames {
   		if f.seq <= ackedSeq {
   			continue
   		}
   		kept = append(kept, f)
   		bytes += len(f.data)
   	}
   	b.frames = kept
   	b.bytes = bytes
   }

   // tailFrames returns a copy of all buffered frames in seq order (for resend on
   // slot-A death before ack, §5.3) without emptying the buffer.
   func (b *boundedBuffer) tailFrames() []pendingDownFrame {
   	out := make([]pendingDownFrame, len(b.frames))
   	copy(out, b.frames)
   	return out
   }

   // relay state machine (§5.1, F8). All transitions via state.CompareAndSwap.
   const (
   	stActive  int32 = 0
   	stOrphaned int32 = 1
   	stClosing int32 = 2
   )

   // relayEntry owns one egress-TCP relay that survives WS-slot migration. Keyed
   // (clientID, globalStreamID) in relayRegistry (§5.1).
   type relayEntry struct {
   	// Identity / proof
   	originClientID     string
   	globalStreamID     uint16
   	originSessionNonce [16]byte

   	// Egress — survives slot changes.
   	tc interface{ Close() error } // net.Conn; minimal iface keeps the struct testable

   	// Dynamic binding to the active slot's crypto session+writer (NEW-5).
   	bound atomic.Pointer[binding]

   	// State machine (F8).
   	state      atomic.Int32 // stActive | stOrphaned | stClosing
   	orphanedAt atomic.Int64 // unix nanos

   	// Ordering (F1) — counter NEVER reset on reassociate (NEW-3, §3.1).
   	downSeqCounter atomic.Uint64
   	downBuffer     *boundedBuffer // buffered while no binding / during grace
   	unackedTail    *boundedBuffer // sent-on-A-but-unacked tail (NEW-1)

   	// FD accounting (F5).
   	holdsFD bool

   	perEntryMu sync.Mutex
   }
   ```
   (The `tc` field is declared as a minimal interface here so this skeleton task compiles & tests without a real `net.Conn`; Task 9 uses `net.Conn` directly — refine the field to `net.Conn` then. Keep `credit *streamCredit` OUT until Task 8 to keep this commit small.)

4. Run: `go test ./server/ -run 'TestBinding_AtomicConsistentPair|TestBoundedBuffer' -v` → PASS. `go build ./...`.
   **User/CI step (Linux):** `go test -race -count=3 ./server/ -run TestBinding_AtomicConsistentPair` (the torn-pair test is the whole point of `-race`).

5. Commit: `git add server/relay_registry.go server/relay_registry_test.go && git commit -m "feat(bug9): server — binding atomic pair + boundedBuffer + relayEntry skeleton (NEW-5, NEW-1, F8)"`

---

## Task 8 — `relayRegistry` map ops + single-winner state machine + credit field

The registry map (`map[clientID]map[globalStreamID]*relayEntry` under RWMutex), add/find/remove keyed `(clientID, globalStreamID)` (F11), the CAS state transitions (F8), and adds `credit *streamCredit` to `relayEntry` (F9 — credit lives here, not in the per-WS map).

**Files:**
- Modify: `server/relay_registry.go`
- Modify: `server/relay_registry_test.go`

**Steps:**

1. Write failing tests (append to `server/relay_registry_test.go`):
   ```go
   func TestRelayRegistry_AddFindRemove(t *testing.T) {
   	r := newRelayRegistry()
   	e := &relayEntry{originClientID: "c1", globalStreamID: 42}
   	r.add("c1", 42, e)
   	got, ok := r.find("c1", 42)
   	if !ok || got != e {
   		t.Fatal("find did not return the added entry")
   	}
   	// Same streamID under a DIFFERENT clientID must not collide (F11).
   	if _, ok := r.find("c2", 42); ok {
   		t.Fatal("cross-client collision on streamID")
   	}
   	r.remove("c1", 42)
   	if _, ok := r.find("c1", 42); ok {
   		t.Fatal("entry not removed")
   	}
   }

   func TestRelayState_SingleWinner_ResumeBeatsTimer(t *testing.T) {
   	var e relayEntry
   	e.state.Store(stOrphaned)
   	resumeWon := e.state.CompareAndSwap(stOrphaned, stActive)
   	timerWon := e.state.CompareAndSwap(stOrphaned, stClosing)
   	if !resumeWon || timerWon {
   		t.Fatalf("resume should win: resumeWon=%v timerWon=%v", resumeWon, timerWon)
   	}
   	if e.state.Load() != stActive {
   		t.Fatal("state not active after resume won")
   	}
   }

   func TestRelayState_SingleWinner_TimerBeatsResume(t *testing.T) {
   	var e relayEntry
   	e.state.Store(stOrphaned)
   	timerWon := e.state.CompareAndSwap(stOrphaned, stClosing)
   	resumeWon := e.state.CompareAndSwap(stOrphaned, stActive)
   	if !timerWon || resumeWon {
   		t.Fatalf("timer should win: timerWon=%v resumeWon=%v", timerWon, resumeWon)
   	}
   }

   func TestRelayRegistry_PerClientCount(t *testing.T) {
   	r := newRelayRegistry()
   	r.add("c1", 1, &relayEntry{})
   	r.add("c1", 2, &relayEntry{})
   	r.add("c2", 1, &relayEntry{})
   	if n := r.countForClient("c1"); n != 2 {
   		t.Fatalf("countForClient(c1) = %d, want 2", n)
   	}
   	if n := r.totalCount(); n != 3 {
   		t.Fatalf("totalCount = %d, want 3", n)
   	}
   }
   ```

2. Run: `go test ./server/ -run 'TestRelayRegistry|TestRelayState_SingleWinner' -v` → FAIL.

3. Minimal impl in `server/relay_registry.go`. Add `credit *streamCredit` to `relayEntry` (after `holdsFD bool`):
   ```go
   	credit *streamCredit // Bug#8 bucket — lives here, survives migration (F9, §5.9)
   ```
   Add the registry type:
   ```go
   // relayRegistry holds relays keyed (clientID, globalStreamID), living
   // independently of any single WS session (§5.1). RWMutex guards the maps;
   // per-entry mutation uses relayEntry.perEntryMu / atomics.
   type relayRegistry struct {
   	mu      sync.RWMutex
   	byClient map[string]map[uint16]*relayEntry
   }

   func newRelayRegistry() *relayRegistry {
   	return &relayRegistry{byClient: make(map[string]map[uint16]*relayEntry)}
   }

   func (r *relayRegistry) add(clientID string, streamID uint16, e *relayEntry) {
   	r.mu.Lock()
   	defer r.mu.Unlock()
   	m := r.byClient[clientID]
   	if m == nil {
   		m = make(map[uint16]*relayEntry)
   		r.byClient[clientID] = m
   	}
   	m[streamID] = e
   }

   func (r *relayRegistry) find(clientID string, streamID uint16) (*relayEntry, bool) {
   	r.mu.RLock()
   	defer r.mu.RUnlock()
   	if m := r.byClient[clientID]; m != nil {
   		e, ok := m[streamID]
   		return e, ok
   	}
   	return nil, false
   }

   func (r *relayRegistry) remove(clientID string, streamID uint16) {
   	r.mu.Lock()
   	defer r.mu.Unlock()
   	if m := r.byClient[clientID]; m != nil {
   		delete(m, streamID)
   		if len(m) == 0 {
   			delete(r.byClient, clientID)
   		}
   	}
   }

   func (r *relayRegistry) countForClient(clientID string) int {
   	r.mu.RLock()
   	defer r.mu.RUnlock()
   	return len(r.byClient[clientID])
   }

   func (r *relayRegistry) totalCount() int {
   	r.mu.RLock()
   	defer r.mu.RUnlock()
   	n := 0
   	for _, m := range r.byClient {
   		n += len(m)
   	}
   	return n
   }
   ```

4. Run: `go test ./server/ -run 'TestRelayRegistry|TestRelayState_SingleWinner|TestBinding|TestBoundedBuffer' -v` → PASS. `go build ./...`.

5. Commit: `git add server/relay_registry.go server/relay_registry_test.go && git commit -m "feat(bug9): server — relayRegistry map ops + single-winner CAS state + credit field (F8, F9, F11)"`

---

## Task 9 — `unackedTail` resend logic + `downSeqCounter` monotonic invariant (NEW-1, NEW-3)

The resend-tail logic on `relayEntry`: a method that, given the entry is bound to B and slot A died with unacked frames, re-enqueues those frames on B in seq order; and the ack-eviction method. Plus a regression test proving `downSeqCounter` is never reset on reassociate (NEW-3). Still no networking — drives the methods directly.

**Files:**
- Modify: `server/relay_registry.go`
- Modify: `server/relay_registry_test.go`

**Steps:**

1. Write failing tests (append):
   ```go
   func TestRelayEntry_AckEvictsTail(t *testing.T) {
   	e := &relayEntry{unackedTail: newBoundedBuffer(1 << 20)}
   	e.unackedTail.Push(pendingDownFrame{seq: 1, data: []byte("a")})
   	e.unackedTail.Push(pendingDownFrame{seq: 2, data: []byte("b")})
   	e.unackedTail.Push(pendingDownFrame{seq: 3, data: []byte("c")})
   	e.onStreamAck(2) // ack up to seq 2
   	if e.unackedTail.byteLen() != 1 {
   		t.Fatalf("unackedTail bytes = %d, want 1 (only seq3)", e.unackedTail.byteLen())
   	}
   }

   func TestRelayEntry_ResendTailReturnsUnackedInOrder(t *testing.T) {
   	e := &relayEntry{unackedTail: newBoundedBuffer(1 << 20)}
   	e.unackedTail.Push(pendingDownFrame{seq: 5, data: []byte("e")})
   	e.unackedTail.Push(pendingDownFrame{seq: 6, data: []byte("f")})
   	frames := e.resendTail()
   	if len(frames) != 2 || frames[0].seq != 5 || frames[1].seq != 6 {
   		t.Fatalf("resendTail order: %+v", frames)
   	}
   	// resendTail must NOT clear the tail (still awaiting ack on B).
   	if e.unackedTail.byteLen() == 0 {
   		t.Fatal("resendTail must not empty the buffer")
   	}
   }

   func TestRelayEntry_DownSeqNeverResetOnReassociate(t *testing.T) {
   	e := &relayEntry{}
   	// Simulate slot A producing seq 1..4.
   	for i := 0; i < 4; i++ {
   		e.downSeqCounter.Add(1)
   	}
   	before := e.downSeqCounter.Load()
   	// reassociate = only the binding changes (NEW-3): counter untouched.
   	sB := core.NewSession(2, make([]byte, 32), make([]byte, 32))
   	e.bound.Store(&binding{session: sB, writer: core.NewWSAsyncWriter(nil, 8)})
   	if e.downSeqCounter.Load() != before {
   		t.Fatal("downSeqCounter changed on reassociate — NEW-3 invariant broken")
   	}
   	// Next data chunk on B continues monotonically.
   	if next := e.downSeqCounter.Add(1); next != before+1 {
   		t.Fatalf("post-reassociate next seq = %d, want %d", next, before+1)
   	}
   }
   ```

2. Run: `go test ./server/ -run 'TestRelayEntry_' -v` → FAIL (no `onStreamAck`, `resendTail`).

3. Minimal impl in `server/relay_registry.go`:
   ```go
   // onStreamAck releases the not-yet-acked tail up to ackedSeq (FlagStreamAck
   // barrier, §5.4). Called under perEntryMu by the FlagStreamAck handler.
   func (e *relayEntry) onStreamAck(ackedSeq uint64) {
   	e.perEntryMu.Lock()
   	if e.unackedTail != nil {
   		e.unackedTail.evictUpTo(ackedSeq)
   	}
   	if e.downBuffer != nil {
   		e.downBuffer.evictUpTo(ackedSeq)
   	}
   	e.perEntryMu.Unlock()
   }

   // resendTail returns the unacked tail (seq order) so the relay-loop can
   // re-enqueue it on the NEW binding when slot A died before acking (NEW-1,
   // §5.3). Does NOT clear the buffer — the frames stay pending until B acks
   // them. Caller resends under the same perEntryMu it holds.
   func (e *relayEntry) resendTail() []pendingDownFrame {
   	e.perEntryMu.Lock()
   	defer e.perEntryMu.Unlock()
   	if e.unackedTail == nil {
   		return nil
   	}
   	return e.unackedTail.tailFrames()
   }
   ```

4. Run: `go test ./server/ -run 'TestRelayEntry_|TestRelayRegistry|TestBinding|TestBoundedBuffer' -v` → PASS. `go build ./...`.

5. Commit: `git add server/relay_registry.go server/relay_registry_test.go && git commit -m "feat(bug9): server — unackedTail ack-evict + resend-on-A-death + downSeq monotonic invariant (NEW-1, NEW-3)"`

---

# LAYER 5 — SERVER RELAY-LOOP REFACTOR + MIGRATE/RESUME HANDLERS

The big surgery (F4): pull the per-stream relay goroutine out of `runWebSocketSession`'s CONNECT closure so it reads `entry.bound.Load()` dynamically every iteration and is no longer torn down by `<-done`. Then add the FlagMigrate/FlagResume/FlagStreamAck handlers, grace timer, and DoS/FD budget.

---

## Task 10 — Relay-loop reads `bound` dynamically + decoupled from `done` (F4)

Replace the CONNECT relay closure (`server/websocket.go:786-851`) with a relay loop attached to a `*relayEntry`: on every iteration it `entry.bound.Load()`s the consistent (session, writer) pair, assigns `downSeq = entry.downSeqCounter.Add(1)`, emits `NewStreamDataChunkSeq` when migration is enabled (legacy `NewStreamDataChunk` otherwise), pushes the frame into `unackedTail`, and buffers into `downBuffer` when there is no binding. The `<-done` watchdog (`:766-784`) NO LONGER closes `tc` for migration-capable sessions. On CONNECT the server registers the entry under `(clientID, globalStreamID)` (F11) using the streamID from the CONNECT payload.

**Files:**
- Modify: `server/websocket.go`
- Modify: `server/relay_registry.go` (the `relayLoop` method)
- Create: `server/relay_loop_test.go`

**Steps:**

1. Write failing test `server/relay_loop_test.go` (drives relayLoop with an in-memory `net.Pipe` egress + a fake writer capturing enqueued frames; verifies a `bound.Store` mid-flight makes subsequent chunks decrypt under session B):
   ```go
   package server

   import (
   	"net"
   	"testing"
   	"time"

   	"github.com/nixavpn/shadowlink/core"
   )

   // captureWriter records every Enqueue so the test can decrypt frames.
   // (Implemented as a thin wrapper the relay loop accepts via binding.writer;
   //  if WSAsyncWriter cannot be faked directly, add a small writerSink iface
   //  on binding for test injection — keep production path on *core.WSAsyncWriter.)

   func TestRelayLoop_SwitchBindingReencryptsUnderNewSession(t *testing.T) {
   	// egress pipe: test writes "DATA-B" after the binding switch.
   	srvSide, egress := net.Pipe()
   	defer srvSide.Close()
   	defer egress.Close()

   	sessA := core.NewSession(1, mustKey(0xA), mustKey(0xA))
   	sessB := core.NewSession(2, mustKey(0xB), mustKey(0xB))
   	// ... initialize cached GCM via SessionManager.Create-equivalent helper ...

   	e := &relayEntry{
   		globalStreamID: 7,
   		tc:             egress,
   		downBuffer:     newBoundedBuffer(1 << 20),
   		unackedTail:    newBoundedBuffer(1 << 20),
   		credit:         newStreamCredit(1 << 20),
   	}
   	e.state.Store(stActive)
   	sinkB := newTestWriterSink()
   	e.bound.Store(&binding{session: sessB, writer: sinkB.asWriter()})

   	go e.relayLoop(true /*migrateEnabled*/, make(chan struct{}))

   	srvSide.Write([]byte("DATA-B"))
   	frame := sinkB.waitFrame(t, time.Second)
   	chunk, err := sessB.DecryptChunkSafe(frame)
   	if err != nil {
   		t.Fatalf("frame did not decrypt under session B: %v", err)
   	}
   	_, seq, data, perr := core.ParseStreamDataSeq(chunk.Payload)
   	if perr != nil || seq != 1 || string(data) != "DATA-B" {
   		t.Fatalf("seq=%d data=%q err=%v", seq, data, perr)
   	}
   	_ = sessA
   }
   ```
   (Helper `mustKey`, `newTestWriterSink`, the `writerSink` test seam on `binding`, and a `SessionManager.Create`-style GCM init helper are part of this task's test scaffolding. Keep the production `binding.writer` typed `*core.WSAsyncWriter`; the seam is an interface the writer satisfies, used only by tests.)

2. Run: `go test ./server/ -run TestRelayLoop_SwitchBinding -v` → FAIL.

3. Minimal impl:
   - In `server/relay_registry.go`, add `relayLoop` modeled on the spec §5.2 pseudocode and the current loop at `server/websocket.go:807-851`:
     ```go
     // relayLoop reads egress-TCP and pushes downlink chunks to the CURRENTLY
     // bound slot, re-reading entry.bound every iteration (F4). Lives in the
     // registry, NOT tied to one WS-conn's done (§5.2). Exits on dest EOF/error,
     // grace close, or session-FIN.
     func (e *relayEntry) relayLoop(migrateEnabled bool, closeCh <-chan struct{}) {
     	buf := make([]byte, 32768)
     	for {
     		limit := len(buf)
     		if e.credit != nil {
     			got := e.credit.waitForCredit(closeCh)
     			if got <= 0 {
     				return
     			}
     			if int(got) < limit {
     				limit = int(got)
     			}
     		}
     		n, err := e.tc.Read(buf[:limit])
     		if n > 0 {
     			seq := e.downSeqCounter.Add(1) // first data → 1 (NEW-2)
     			frame := pendingDownFrame{seq: seq, data: append([]byte(nil), buf[:n]...)}
     			b := e.bound.Load()
     			if b == nil || b.session == nil || b.writer == nil {
     				// migration window (reassociate in flight) — buffer under seq.
     				e.perEntryMu.Lock()
     				ok := e.downBuffer.Push(frame)
     				e.perEntryMu.Unlock()
     				if !ok {
     					// backpressure: stop reading until buffer drains. Simplest
     					// correct form — sleep-poll; production uses a cond on
     					// downBuffer drain (Task 11 wires drain on reassociate).
     					time.Sleep(2 * time.Millisecond)
     				}
     				continue
     			}
     			// NEW-1: hold unacked tail copy under its seq.
     			e.perEntryMu.Lock()
     			e.unackedTail.Push(frame)
     			e.perEntryMu.Unlock()
     			e.enqueueDownFrame(b, migrateEnabled, frame)
     			e.credit.consume(n)
     		}
     		if err != nil {
     			return // dest closed → §5.5 handled by caller via tc error
     		}
     	}
     }

     // enqueueDownFrame encrypts one downlink frame under the bound session and
     // enqueues it on the bound writer. Uses seq-format when migration is on,
     // legacy format otherwise (capability gate, §3.1).
     func (e *relayEntry) enqueueDownFrame(b *binding, migrateEnabled bool, f pendingDownFrame) {
     	var chunk *core.Chunk
     	if migrateEnabled {
     		chunk = core.NewStreamDataChunkSeq(b.session.ID, b.session.NextSeqNum(), e.globalStreamID, f.seq, f.data)
     	} else {
     		chunk = core.NewStreamDataChunk(b.session.ID, b.session.NextSeqNum(), e.globalStreamID, f.data)
     	}
     	enc, err := b.session.EncryptChunk(chunk)
     	core.PutBuffer(chunk.Payload)
     	if err != nil {
     		return
     	}
     	_ = b.writer.Enqueue(websocketBinaryMessage, enc)
     }
     ```
     (`websocketBinaryMessage` = a package const aliasing `websocket.BinaryMessage` to avoid importing gorilla into relay_registry.go if undesirable; or import gorilla here — it is already a server dep. Pick the import; keep it simple.)
   - Change `relayEntry.tc` field type to `net.Conn` (drop the minimal interface from Task 7) now that it is exercised.
   - In `server/websocket.go` FlagConnect path: after `s.Activate(tc)` and CONNECT_OK send (`:756-764`), when `migrateEnabled` for the session, build a `relayEntry`, register it under `(clientID, streamID)` via the handler's `relayRegistry`, set `bound` to the current `{session, writer}`, move credit into `entry.credit`, and `go entry.relayLoop(true, sessionCloseCh)` INSTEAD of the inline `for{}` loop. For non-migration sessions keep the existing inline relay verbatim (zero behaviour change on the legacy path).
   - In the `<-done` watchdog closure (`:777-784`): gate the `tc.Close()` on `!migrateEnabled` — for migration sessions, do NOT close tc on done; instead the orphan transition (Task 11) handles it. Add a clear comment referencing §5.2.
   - Handler needs a `relayRegistry` field + `clientID` accessible at CONNECT. `clientID` comes from the authorized-clients context already on the session/tunnel; thread it into `runWebSocketSession`. If clientID is not currently carried to the WS session, capture it in `authenticateFirstFrame` (whitelist lookup) and pass it through.

4. Run: `go test ./server/ -run TestRelayLoop_SwitchBinding -v` → PASS. `go build ./...`. `go test ./server/ -run 'TestWS|TestRelay|TestRunWebSocket' -v` → confirm legacy WS relay path unaffected.
   **User/CI step (Linux):** `go test -race -count=3 ./server/ -run TestRelayLoop`.

5. Commit: `git add server/websocket.go server/relay_registry.go server/relay_loop_test.go && git commit -m "feat(bug9): server — relay-loop reads bound dynamically, decoupled from done; register on CONNECT (F4, F11)"`

---

## Task 11 — FlagMigrate / FlagResume / FlagStreamAck handlers + grace timer + reassociate

The inbound handlers in the WS reader-loop `switch` (`server/websocket.go:854-931`, alongside `FlagFin`/`FlagWindowUpdate`). MIGRATE/RESUME verify proof, CAS the state, `bound.Store` the new pair, drain `downBuffer`, resend `unackedTail` if slot A is known-dead, and reply OK/FAIL. Slot death transitions live entries to `stOrphaned` and arms a grace timer that `CAS(stOrphaned→stClosing)` and closes `tc`. FlagStreamAck calls `entry.onStreamAck`.

**Files:**
- Modify: `server/websocket.go`
- Modify: `server/relay_registry.go` (reassociate + grace helpers)
- Create: `server/migrate_handlers_test.go`

**Steps:**

1. Write failing tests `server/migrate_handlers_test.go`:
   ```go
   func TestReassociate_MigrateOK_SwitchesBindingAndDrainsBuffer(t *testing.T) {
   	// entry bound to A, downBuffer has 2 frames (seq 1,2) buffered during the
   	// no-binding window; reassociate to B drains them on B in seq order, then
   	// state stays Active. Proof valid.
   }
   func TestReassociate_BadProof_Fails(t *testing.T) {
   	// VerifyStreamProof false → MIGRATE_FAIL(bad_proof), binding unchanged.
   }
   func TestResume_FromOrphaned_CASActive(t *testing.T) {
   	// entry orphaned within grace, valid proof → CAS stOrphaned→stActive, OK.
   }
   func TestResume_GraceExpired_Fails(t *testing.T) {
   	// timer already CAS'd stOrphaned→stClosing → RESUME_FAIL(grace_expired).
   }
   func TestGraceTimer_ClosesTCOnExpiry(t *testing.T) {
   	// orphaned entry, grace timer fires → tc closed, entry removed, state stClosing.
   }
   func TestStreamAck_EvictsTail(t *testing.T) {
   	// FlagStreamAck(ackedSeq=N) on entry → unackedTail evicted up to N.
   }
   ```
   (Bodies drive the registry helpers + a stubbed verify; full text written in the task execution. Each asserts the spec'd outcome.)

2. Run: `go test ./server/ -run 'TestReassociate|TestResume|TestGraceTimer|TestStreamAck' -v` → FAIL.

3. Minimal impl:
   - In `server/relay_registry.go` add the reassociate + grace primitives:
     ```go
     // reassociate switches the entry to a new (session, writer), drains any
     // buffered downlink onto the new binding in seq order, and (if slot A died
     // with an unacked tail) resends that tail. downSeqCounter is NEVER touched
     // (NEW-3). Returns the resumeDownSeq (highest seq assigned before switch).
     func (e *relayEntry) reassociate(sess *core.Session, w *core.WSAsyncWriter, migrateEnabled bool, aDead bool) uint64 {
     	resumeDownSeq := e.downSeqCounter.Load()
     	b := &binding{session: sess, writer: w}
     	e.bound.Store(b) // one atomic Store of the consistent pair (NEW-5)

     	e.perEntryMu.Lock()
     	buffered := e.downBuffer.drainAll()
     	var resend []pendingDownFrame
     	if aDead {
     		resend = e.unackedTail.tailFrames()
     	}
     	e.perEntryMu.Unlock()

     	// Drain buffered-during-no-binding first, then resend tail (dedup is on
     	// the client by f.seq<expectedSeq, §5.4 — idempotent).
     	for _, f := range buffered {
     		e.enqueueDownFrame(b, migrateEnabled, f)
     	}
     	for _, f := range resend {
     		e.enqueueDownFrame(b, migrateEnabled, f)
     	}
     	return resumeDownSeq
     }

     // toOrphaned transitions an active entry to orphaned and stamps the clock.
     // Returns false if the entry was not active (already orphaned/closing).
     func (e *relayEntry) toOrphaned(now int64) bool {
     	if e.state.CompareAndSwap(stActive, stOrphaned) {
     		e.orphanedAt.Store(now)
     		return true
     	}
     	return false
     }
     ```
   - Add a grace-timer launcher (registry method) that sleeps `grace`, then `CAS(stOrphaned→stClosing)`; if it wins, `tc.Close()` + `registry.remove` + metric `migrate_grace_expired`. If it loses (RESUME already flipped to active) it does nothing.
   - In `server/websocket.go` reader-loop `switch` add cases (mirroring the FlagWindowUpdate case structure at `:915`):
     ```go
     case core.FlagMigrate, core.FlagResume:
     	sid, proof, perr := core.ParseMigrateFrame(chunk.Payload)
     	if perr != nil { continue }
     	entry, ok := h.relayReg.find(clientID, sid)
     	if !ok {
     		writeMsg(h.encMigrateFail(session, sid, "not_found")); continue
     	}
     	perClientKey := core.DeriveServerPerClientKey(h.serverMasterKey, clientID)
     	if !core.VerifyStreamProof(proof, perClientKey, clientID, sid, entry.originSessionNonce) {
     		writeMsg(h.encMigrateFail(session, sid, "bad_proof")); continue
     	}
     	if chunk.Flags == core.FlagResume {
     		if !entry.state.CompareAndSwap(stOrphaned, stActive) {
     			writeMsg(h.encMigrateFail(session, sid, "grace_expired")); continue
     		}
     	}
     	aDead := chunk.Flags == core.FlagResume
     	resumeSeq := entry.reassociate(session, writer, migrateEnabled, aDead)
     	writeMsg(h.encMigrateOK(session, sid, resumeSeq))
     	if chunk.Flags == core.FlagMigrate { h.metrics.MigrateOK.Add(1) } else { h.metrics.ResumeOK.Add(1) }

     case core.FlagStreamAck:
     	sid, ackedSeq, aerr := core.ParseStreamAckFrame(chunk.Payload)
     	if aerr != nil { continue }
     	if entry, ok := h.relayReg.find(clientID, sid); ok {
     		entry.onStreamAck(ackedSeq)
     	}
     ```
     `encMigrateOK`/`encMigrateFail` are small helpers building reply control chunks (reuse FlagMigrate/FlagResume reply convention from §3.4 — reply carries `[streamID(2)][resumeDownSeq(8)]` for OK or a 1-byte reason code for FAIL; define `BuildMigrateOK`/`BuildMigrateFail` in core if cleaner, otherwise inline). The client (Task 12-13) parses them.
   - On WS-conn death for a migration session (in the `runWebSocketSession` cleanup, `:946-953`): for each relayEntry currently `bound` to THIS session that is NOT already moved to another slot, call `entry.toOrphaned(now)` + launch grace timer + FD-budget accounting (Task 14 adds the budget gate). Do NOT close `tc`.

4. Run: `go test ./server/ -run 'TestReassociate|TestResume|TestGraceTimer|TestStreamAck' -v` → PASS. `go build ./...`.
   **User/CI step (Linux):** `go test -race -count=3 ./server/ -run 'TestReassociate|TestResume|TestGraceTimer'`.

5. Commit: `git add server/websocket.go server/relay_registry.go server/migrate_handlers_test.go && git commit -m "feat(bug9): server — MIGRATE/RESUME/StreamAck handlers + grace timer + reassociate (§5.3, §5.5, F8)"`

---

## Task 12 — DoS limits: per-client/total orphan caps + FD budget + idle-only eviction (F5, F6)

The orphan admission gate (§4.2): `maxOrphanedPerClient` (16), `maxOrphanedTotal` (1024), an `atomic.Int64 orphanedFDInUse` + `orphanFDBudget = min(maxOrphanedTotal, getrlimit_soft/4)` read at startup, and an eviction policy that only evicts **idle** orphaned entries (state==orphaned AND downlink quiet ≥ `evictIdleThreshold`=2s), never active-migrating ones. dest-closed during grace (F13) sets a `destClosed` flag.

**Files:**
- Modify: `server/relay_registry.go`
- Create: `server/relay_fdbudget.go` (getrlimit; build-tagged unix + a portable fallback)
- Create: `server/relay_dos_test.go`

**Steps:**

1. Write failing tests `server/relay_dos_test.go`:
   ```go
   func TestOrphanAdmit_RejectsWhenPerClientFull(t *testing.T) {
   	r := newRelayRegistry()
   	r.setLimits(2 /*perClient*/, 100 /*total*/, 100 /*fdBudget*/)
   	for i := 0; i < 2; i++ {
   		ok := r.admitOrphan("c1", &relayEntry{state: atomicInt32(stOrphaned)})
   		if !ok { t.Fatalf("admit %d should pass", i) }
   	}
   	// 3rd: per-client full, and the existing two are idle → one is evicted.
   	// If both are recent/active → admit returns false (reject new).
   }
   func TestOrphanAdmit_FDBudgetReject(t *testing.T) {
   	r := newRelayRegistry()
   	r.setLimits(100, 100, 0 /*fdBudget=0 → always reject*/)
   	if r.admitOrphan("c1", &relayEntry{}) {
   		t.Fatal("zero FD budget must reject orphan hold")
   	}
   }
   func TestEviction_SkipsActiveMigrating(t *testing.T) {
   	// active entry must NOT be chosen by evictIdleOrphan even under pressure.
   }
   func TestEviction_PicksIdleOrphanedLRU(t *testing.T) {
   	// oldest idle orphaned entry is evicted first.
   }
   ```

2. Run → FAIL.

3. Minimal impl:
   - `server/relay_fdbudget.go`:
     ```go
     //go:build unix

     package server

     import "golang.org/x/sys/unix"

     // readFDSoftLimit returns RLIMIT_NOFILE soft limit, or 0 on error.
     func readFDSoftLimit() uint64 {
     	var rl unix.Rlimit
     	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
     		return 0
     	}
     	return rl.Cur
     }
     ```
     Plus a `//go:build !unix` sibling returning 0 (Windows dev). Compute `orphanFDBudget = min(maxOrphanedTotal, soft/4)`; if soft==0, fall back to `maxOrphanedTotal`. Log the chosen budget at startup (F5).
   - In `server/relay_registry.go`: add `maxOrphanedPerClient`, `maxOrphanedTotal int`, `orphanFDBudget int`, `orphanedFDInUse atomic.Int64`, `evictIdleThreshold time.Duration` (2s) fields + `setLimits`. Add `destClosed atomic.Bool` + `lastDownlinkNs atomic.Int64` to `relayEntry` (F13 + eviction idleness). Implement `admitOrphan(clientID, *relayEntry) bool`:
     - if `orphanedFDInUse.Load() >= orphanFDBudget` → metric `orphan_fd_budget_rejected` ++, return false;
     - if `countForClient >= maxOrphanedPerClient` → `evictIdleOrphan(clientID)`; if still full → return false;
     - if `totalCount >= maxOrphanedTotal` → `evictIdleOrphan("")` (global LRU); if still full → return false;
     - else increment `orphanedFDInUse`, set `holdsFD`, return true.
   - `evictIdleOrphan(scope)`: scan, pick the oldest entry with `state==stOrphaned && now-lastDownlinkNs >= evictIdleThreshold`; CAS it to stClosing, close tc, remove, decrement FD, metric `orphaned_evicted_limit` ++; skip active/recent.
   - Wire `admitOrphan` into the orphan transition in Task 11's WS-conn death path: only hold the relay (keep tc open) if `admitOrphan` returns true; otherwise `tc.Close()` immediately (degradation, §5.5 step 1).
   - dest-closed (F13): when `relayLoop` exits on `tc.Read` EOF while `state==stOrphaned`, set `destClosed=true` and append a FIN marker into `downBuffer`; the next RESUME drains remainder + FIN.

4. Run: `go test ./server/ -run 'TestOrphanAdmit|TestEviction' -v` → PASS. `go build ./...` (build both unix + windows tags — verify `go vet ./server/`).

5. Commit: `git add server/relay_registry.go server/relay_fdbudget.go server/relay_dos_test.go && git commit -m "feat(bug9): server — orphan DoS caps + FD budget + idle-only eviction + dest-closed grace (F5, F6, F13)"`

---

# LAYER 6 — CLIENT REASSEMBLER

The central client mechanism (F1, §5.4): an out-of-order buffer in the per-stream downlink goroutine that delivers to `conn.Write` strictly by seq, dedups, overflows on size, and breaks on a gap-timeout (NEW-1). Built as a standalone unit first, then wired into `tcp.go`.

---

## Task 13 — Standalone reassembler unit (`proxy/socks5/reassembler.go`)

A pure, testable reassembler struct: `push(seq, data)` → returns the ordered slice ready for `conn.Write` (or signals overflow/gap-break). Holds `expectedSeq` (starts at 1, NEW-2), `pending map[uint64][]byte`, byte-bounded `reassemblyMaxBuffered`, and a gap-timer abstraction injected for testability.

**Files:**
- Create: `proxy/socks5/reassembler.go`
- Create: `proxy/socks5/reassembler_test.go`

**Steps:**

1. Write failing test `proxy/socks5/reassembler_test.go`:
   ```go
   package socks5

   import "testing"

   func TestReassembler_InOrder(t *testing.T) {
   	r := newReassembler(1 << 20)
   	out, st := r.push(1, []byte("a"))
   	if st != reasmOK || len(out) != 1 || string(out[0]) != "a" {
   		t.Fatalf("seq1: st=%v out=%v", st, out)
   	}
   	out, st = r.push(2, []byte("b"))
   	if st != reasmOK || string(out[0]) != "b" {
   		t.Fatalf("seq2: st=%v out=%v", st, out)
   	}
   }

   func TestReassembler_OutOfOrderBuffersThenFlushes(t *testing.T) {
   	r := newReassembler(1 << 20)
   	if out, st := r.push(3, []byte("c")); st != reasmOK || len(out) != 0 {
   		t.Fatalf("seq3 early: st=%v out=%v (want buffered, no flush)", st, out)
   	}
   	if out, _ := r.push(2, []byte("b")); len(out) != 0 {
   		t.Fatalf("seq2 still gapped at 1: out=%v", out)
   	}
   	out, st := r.push(1, []byte("a"))
   	if st != reasmOK || len(out) != 3 ||
   		string(out[0]) != "a" || string(out[1]) != "b" || string(out[2]) != "c" {
   		t.Fatalf("flush after gap closed: st=%v out=%v", st, out)
   	}
   }

   func TestReassembler_DedupsBelowExpected(t *testing.T) {
   	r := newReassembler(1 << 20)
   	r.push(1, []byte("a"))
   	if out, st := r.push(1, []byte("a")); st != reasmDup || len(out) != 0 {
   		t.Fatalf("dup seq1: st=%v out=%v", st, out)
   	}
   }

   func TestReassembler_OverflowBySize(t *testing.T) {
   	r := newReassembler(4) // 4-byte buffer
   	// seq 2 buffered (gap at 1); push 5 bytes → exceeds → overflow.
   	r.push(2, []byte("xx"))
   	if _, st := r.push(3, []byte("yyy")); st != reasmOverflow {
   		t.Fatalf("expected reasmOverflow, got %v", st)
   	}
   }

   func TestReassembler_HasGap(t *testing.T) {
   	r := newReassembler(1 << 20)
   	r.push(2, []byte("b")) // gap at 1
   	if !r.hasGap() {
   		t.Fatal("hasGap should be true with pending past expected")
   	}
   	r.push(1, []byte("a"))
   	if r.hasGap() {
   		t.Fatal("hasGap should be false after gap closed")
   	}
   }
   ```

2. Run: `go test ./proxy/socks5/ -run TestReassembler -v` → FAIL.

3. Minimal impl `proxy/socks5/reassembler.go`:
   ```go
   package socks5

   type reasmStatus int

   const (
   	reasmOK       reasmStatus = iota // out holds 0+ in-order frames to write
   	reasmDup                         // duplicate (seq < expected) — dropped
   	reasmOverflow                    // size cap exceeded → caller breaks stream
   )

   // reassembler reorders per-stream downlink chunks by their server-assigned
   // downSeq into a strictly monotonic stream for conn.Write (§5.4, F1).
   // expectedSeq starts at 1 (NEW-2: seq 0 is control, never reaches here).
   // Not safe for concurrent use — owned by one downlink goroutine.
   type reassembler struct {
   	expectedSeq uint64
   	pending     map[uint64][]byte
   	bufBytes    int
   	maxBytes    int
   }

   func newReassembler(maxBytes int) *reassembler {
   	return &reassembler{expectedSeq: 1, pending: make(map[uint64][]byte), maxBytes: maxBytes}
   }

   // push offers one (seq, data). Returns the ordered run now ready for
   // conn.Write (possibly empty) and a status. On reasmOverflow the caller MUST
   // break the stream (degradation, not corruption).
   func (r *reassembler) push(seq uint64, data []byte) (out [][]byte, st reasmStatus) {
   	if seq < r.expectedSeq {
   		return nil, reasmDup
   	}
   	if _, exists := r.pending[seq]; !exists {
   		r.pending[seq] = data
   		r.bufBytes += len(data)
   	}
   	for {
   		nf, ok := r.pending[r.expectedSeq]
   		if !ok {
   			break
   		}
   		out = append(out, nf)
   		r.bufBytes -= len(nf)
   		delete(r.pending, r.expectedSeq)
   		r.expectedSeq++
   	}
   	if r.bufBytes > r.maxBytes {
   		return out, reasmOverflow
   	}
   	return out, reasmOK
   }

   // hasGap reports whether buffered frames sit past expectedSeq (a hole exists)
   // — drives the gap-timer (NEW-1, §5.4).
   func (r *reassembler) hasGap() bool { return len(r.pending) > 0 }
   ```

4. Run: `go test ./proxy/socks5/ -run TestReassembler -v` → PASS. `go build ./...`.

5. Commit: `git add proxy/socks5/reassembler.go proxy/socks5/reassembler_test.go && git commit -m "feat(bug9): client — standalone downlink reassembler unit (F1, NEW-2)"`

---

## Task 14 — Wire reassembler into downlink goroutine + gap-timeout backstop + seq routing (NEW-1)

Plug the reassembler into the downlink goroutine in `proxy/socks5/tcp.go:713-795` between reading `incomingCh` and `conn.Write`, with the `reassemblyGapTimeout` (2s, NEW-1) backstop. Requires the channel to carry `streamFrame{seq, data}` in migration mode — so `client.RouteToStream` and `slotReaderWithClient` must deliver seq (this task threads seq into the channel; `client.go`/`ws_pool.go` changes here). Adds the `len(payload)<10` guard in seq-mode (NEW-2). FlagStreamAck send on flush.

**Files:**
- Modify: `proxy/socks5/tcp.go`
- Modify: `client/client.go` (`streamFrame` type, seq-aware RouteToStream)
- Modify: `client/ws_pool.go` (`slotReaderWithClient` seq parse + `<10` guard)
- Create: `proxy/socks5/downlink_reassembly_test.go`

**Steps:**

1. Write failing test `proxy/socks5/downlink_reassembly_test.go` driving the downlink loop with a fake `incomingCh` of `streamFrame`s in shuffled seq order + a `net.Pipe` `conn`, asserting bytes arrive in order; and a gap-timeout test (push seq 2..5, never push 1 → after `reassemblyGapTimeout` the stream breaks, `gap_timeout` counter ticks):
   ```go
   func TestDownlinkReassembly_OutOfOrderWritesInOrder(t *testing.T) { /* shuffled seq → ordered conn bytes */ }
   func TestDownlinkReassembly_GapTimeoutBreaks(t *testing.T)        { /* hole never fills → break after timeout */ }
   func TestDownlinkReassembly_GapClosedInTimeNoTimeout(t *testing.T){ /* hole fills before timer → continues */ }
   ```

2. Run → FAIL.

3. Minimal impl:
   - In `client/client.go`: add `type streamFrame struct { seq uint64; data []byte }`. When migration is enabled the stream channel type becomes `chan streamFrame` (introduce a parallel `streamFramesChans map[uint16]chan streamFrame` OR change the existing channel element type behind the capability gate). Add `RouteToStreamSeq(streamID uint16, seq uint64, data []byte)` that delivers a `streamFrame`. Keep `RouteToStream` for legacy.
   - In `client/ws_pool.go` `slotReaderWithClient` (`:2787`): when the session negotiated migration, change the guard to `len(chunk.Payload) < 10` (NEW-2), parse via `core.ParseStreamDataSeq`, and call `cl.RouteToStreamSeq(streamID, downSeq, data)`. Legacy path keeps `< 2` + `RouteToStream`. Gate on a per-pool `migrateEnabled` flag set from the transport's `flowMigrateEnabled` (Task 6).
   - In `proxy/socks5/tcp.go` downlink goroutine: replace the direct `conn.Write(data)` (`:774`) with reassembler-mediated writes. Sketch (migration mode; legacy mode keeps current code verbatim under an `if !migrate` branch):
     ```go
     reasm := newReassembler(reassemblyMaxBufferedFromEnv())
     gapTimer := time.NewTimer(time.Hour)
     gapTimer.Stop()
     gapArmed := false
     for {
     	select {
     	case f, ok := <-incomingCh: // incomingCh is chan streamFrame in migrate mode
     		if !ok { return }
     		if f.seq == 0 { handleControl(f.data); continue } // CONNECT_OK/FAIL (§3.1)
     		out, st := reasm.push(f.seq, f.data)
     		if st == reasmOverflow {
     			client.Stats.StreamReassemblyOverflow.Add(1)
     			return // break stream (degradation)
     		}
     		for _, d := range out {
     			if _, err := conn.Write(d); err != nil { /* existing drain-on-write-error path */ }
     			cl.OnStreamConsumed(streamID, len(d))
     		}
     		if len(out) > 0 {
     			sendStreamAck(streamID, reasm.expectedSeq-1) // throttled in Task 15; forced after MIGRATE_OK
     		}
     		if reasm.hasGap() {
     			if !gapArmed { gapTimer.Reset(reassemblyGapTimeout); gapArmed = true }
     		} else if gapArmed {
     			gapTimer.Stop(); gapArmed = false
     		}
     	case <-gapTimer.C:
     		client.Stats.StreamReassemblyGapTimeout.Add(1)
     		return // NEW-1: hole unrecoverable → break, do NOT hang
     	case <-peerFullClose:
     		// existing handling
     	}
     }
     ```
   - Add `reassemblyGapTimeout` (default 2s, env `SHADOWLINK_REASSEMBLY_GAP_TIMEOUT`) and `reassemblyMaxBufferedFromEnv` (default 4MB, env `SHADOWLINK_REASSEMBLY_BUFFER`) helpers. `sendStreamAck` builds a `FlagStreamAck` chunk (`core.BuildStreamAckFrame`) and sends via the stream's transport (reuse `TryStreamWriteControl` like `sendWindowUpdate`, `stream_flow.go:203`).
   - Keep the existing write-error drain loop (`tcp.go:785-794`) and CONNECT_OK/FAIL handling (`:736-762`) — they move into `handleControl` / the write-error branch.

4. Run: `go test ./proxy/socks5/ -run TestDownlinkReassembly -v` → PASS. `go test ./proxy/socks5/ ./client/ -v` → no regression. `go build ./...`.
   **User/CI step (Linux):** `go test -race -count=3 ./proxy/socks5/ ./client/ -run 'Reassembly|RouteToStream'`.

5. Commit: `git add proxy/socks5/tcp.go proxy/socks5/reassembler.go client/client.go client/ws_pool.go proxy/socks5/downlink_reassembly_test.go && git commit -m "feat(bug9): client — reassembler in downlink goroutine + gap-timeout + seq routing + <10 guard (F1, NEW-1, NEW-2)"`

---

# LAYER 7 — CLIENT MIGRATION LOGIC

The client decision + send side: per-slot migration threshold with anti-DPI jitter/spread (§5.6, F7), MIGRATE/RESUME send with ack-await + fail-safe (F3), uplink barrier, RESUME on slot death, drain coordination (F10).

---

## Task 15 — MIGRATE/RESUME send + ack-await + proof storage + StreamAck throttle (F3)

The client-side primitives: store the per-stream `streamSecret` (proof) received in the CONNECT reply; a `sendMigrate(streamID, kind, targetSlot)` that builds the frame, sends on the target slot, and awaits OK/FAIL within `migrateAckTimeout` (returns success/fail/timeout); the ≥3-timeout hysteresis that drops the capability flag (F3); and the StreamAck throttle (batch every ~50ms / K chunks, forced after MIGRATE_OK). No watchdog trigger yet (Task 16).

**Files:**
- Modify: `client/ws_pool.go` (send + ack-await + pending-ack registry)
- Modify: `client/client.go` (per-stream proof storage; CONNECT-reply proof capture)
- Create: `client/migrate_send_test.go`

**Steps:**

1. Write failing test `client/migrate_send_test.go`:
   ```go
   func TestSendMigrate_OKResolvesPending(t *testing.T) {
   	// inject a fake target-slot writer; sendMigrate registers a pending ack,
   	// a simulated MIGRATE_OK(streamID, resumeSeq) resolves it as success.
   }
   func TestSendMigrate_TimeoutDegrades(t *testing.T) {
   	// no OK/FAIL within migrateAckTimeout → result=timeout, migrate_timeout++.
   }
   func TestCapabilityHysteresis_DropsAfter3Timeouts(t *testing.T) {
   	// 3 consecutive timeouts → migrateCapable flag flips false until next handshake.
   }
   func TestStreamAckThrottle(t *testing.T) {
   	// acks batched: many flushes within window coalesce; forced flush bypasses throttle.
   }
   ```

2. Run → FAIL.

3. Minimal impl:
   - `client/client.go`: store `streamSecret [32]byte` per stream (e.g. in `streamEntry` or a `map[uint16][32]byte` under `streamMu`). When the CONNECT reply carrying the proof arrives (server sends it inside the encrypted CONNECT_OK extension — coordinate with Task 11's CONNECT path: extend CONNECT_OK to carry the 32-byte proof after the `"CONNECT_OK"` marker, gated by migration), capture it. Add `StreamProof(streamID) ([32]byte, bool)`.
   - `client/ws_pool.go`: add a `pendingMigrateAcks sync.Map` keyed streamID → chan migrateResult. `sendMigrate(streamID uint16, kind byte /*FlagMigrate|FlagResume*/, targetIdx int) migrateResult`:
     - build `core.BuildMigrateFrame(streamID, proof)`, wrap in a Chunk with `kind`, encrypt under the target slot's session, enqueue on the target slot writer;
     - register a pending chan, `select { case r := <-ch: ...; case <-time.After(migrateAckTimeout): Stats.MigrateTimeout++; result=timeout }`.
     - On timeout: increment a per-pool `consecutiveMigrateTimeouts`; at ≥3 set `migrateCapable=false` (hysteresis, reset on next keepalive handshake).
   - In `slotReaderWithClient`: recognize the MIGRATE_OK/FAIL/RESUME_OK/FAIL reply chunks (FlagMigrate/FlagResume from server) and resolve the pending chan. Parse `resumeDownSeq` (reply payload `[streamID(2)][resumeDownSeq(8)]`).
   - StreamAck throttle: `sendStreamAck` (called from Task 14 downlink loop) coalesces — track `lastAckNs` per stream; send if ≥50ms since last OR `forced` (after MIGRATE_OK). Wire the forced flush from the migrate-OK handler.

4. Run: `go test ./client/ -run 'TestSendMigrate|TestCapabilityHysteresis|TestStreamAckThrottle' -v` → PASS. `go build ./...`.

5. Commit: `git add client/ws_pool.go client/client.go client/migrate_send_test.go && git commit -m "feat(bug9): client — MIGRATE/RESUME send + ack-await + hysteresis + StreamAck throttle (F3)"`

---

## Task 16 — Age-watchdog with anti-DPI threshold jitter + per-stream spread (F7, §5.6)

The decision engine: per-slot migration threshold = `migrationThreshold × U(0.7,1.0)` sampled once at slot (re)connect (like `byteBudget` jitter, `ws_pool.go:621`); when a slot crosses its threshold, enqueue migration of each active stream at `t0 + U(0, migrationSpread)` (8s, NOT a burst); pick a young live slot as target; call `sendMigrate(... FlagMigrate ...)`. Adds `migrationThreshold` per-slot field + env `SHADOWLINK_MIGRATE_THRESHOLD`/`SHADOWLINK_MIGRATE_SPREAD`.

**Files:**
- Modify: `client/ws_pool.go` (slot field + watchdog logic + young-slot selection)
- Create: `client/migrate_watchdog_test.go`

**Steps:**

1. Write failing tests:
   ```go
   func TestMigrationThresholdJitter_InRange(t *testing.T) {
   	// sampled threshold ∈ [0.7×base, 1.0×base] for many samples; not all identical.
   }
   func TestSelectYoungTargetSlot(t *testing.T) {
   	// among ready slots, picks the youngest live slot that is NOT the aging one.
   }
   func TestMigrationSpread_NotBurst(t *testing.T) {
   	// N active streams on an aged slot get scheduled offsets within [0, spread),
   	// not all at t0 (variance > 0).
   }
   func TestMigrationThresholdBelowCutWindow(t *testing.T) {
   	// effective threshold (≤60s) < observed cut window (~90s) — invariant guard.
   }
   ```

2. Run → FAIL.

3. Minimal impl:
   - Add `migrationThresholdNs atomic.Int64` to `poolSlot`; sample at connect: `base × (0.7 + rand*0.3)` (reuse the jitter helper near `ws_pool.go:621`). Add `migrationSpread`/`migrationThresholdBase` from env (default 60s/8s).
   - In `rotationWatchdog` (pool-level goroutine, where age rotation already lives — referenced `ws_pool.go:2769` comment): when `slotAge > slot.migrationThresholdNs` AND migration enabled AND slot has active streams, for each active stream on the slot schedule `time.AfterFunc(U(0, spread), func(){ migrateStream(streamID) })`. `migrateStream` selects a young target via `selectYoungTargetSlot(agingIdx)` and calls `sendMigrate(streamID, FlagMigrate, targetIdx)`; on success update the streamEntry's `slotIdx` to target; on fail/timeout leave the stream to break naturally.
   - `selectYoungTargetSlot(agingIdx int) (int, bool)`: among `slotReady` slots != agingIdx, return the one with the most recent `slotStart` (youngest). false if none.

4. Run: `go test ./client/ -run 'TestMigrationThreshold|TestSelectYoungTargetSlot|TestMigrationSpread' -v` → PASS. `go build ./...`.

5. Commit: `git add client/ws_pool.go client/migrate_watchdog_test.go && git commit -m "feat(bug9): client — age-watchdog migration threshold jitter + per-stream spread + young-slot select (F7, §5.6)"`

---

## Task 17 — Uplink barrier + RESUME-on-slot-death + drain coordination (`migrating` flag, F10)

Uplink ordering (§5.3 barrier): after sending MIGRATE for stream 42, the client stops sending uplink on slot A and waits for MIGRATE_OK before sending on B. RESUME path: `handleSlotDeath` (`ws_pool.go:3050`), for each active stream of the dead slot, calls `sendMigrate(streamID, FlagResume, liveIdx)` BEFORE closing the stream chan; only closes the chan if RESUME fails/times out. Drain coordination (F10): a per-stream `migrating` flag (in `streamEntry`) makes `handleSlotDeath`/drain-teardown skip the chan-close for migrating streams; `migrating` stream is not "active" for sticky-backstop.

**Files:**
- Modify: `client/stream_entry.go` (add `migrating atomic.Bool`)
- Modify: `client/ws_pool.go` (`handleSlotDeath` RESUME path + skip-close-on-migrating)
- Modify: `proxy/socks5/tcp.go` (uplink barrier around MIGRATE)
- Create: `client/migrate_resume_test.go`

**Steps:**

1. Write failing tests:
   ```go
   func TestHandleSlotDeath_ResumesMigratingStreamsBeforeClose(t *testing.T) {
   	// dead slot with 1 active stream → RESUME sent on a live slot; on RESUME_OK
   	// the stream chan is NOT closed and slotIdx repoints to the live slot.
   }
   func TestHandleSlotDeath_ClosesWhenResumeFails(t *testing.T) {
   	// RESUME_FAIL/timeout → chan closed (degradation, exactly as today).
   }
   func TestDrainTeardown_SkipsMigratingStream(t *testing.T) {
   	// migrating=true stream is skipped by the streamMap.Range close loop.
   }
   func TestMigratingNotCountedActiveForSticky(t *testing.T) {
   	// allStreamsIdle / sticky backstop treats migrating streams as not-active.
   }
   ```

2. Run → FAIL.

3. Minimal impl:
   - `client/stream_entry.go`: add `migrating atomic.Bool` to `streamEntry`. Set true at MIGRATE send (Task 16/15), cleared on OK/FAIL/timeout.
   - `client/ws_pool.go` `handleSlotDeath` (`:3067-3081` Range loop): before closing a stream's chan, if migration enabled and the stream is recoverable, attempt RESUME on a live slot (`sendMigrate(streamID, FlagResume, liveIdx)`); if it succeeds, skip the close and repoint `slotIdx`; if `e.migrating.Load()` (a MIGRATE was already in flight), also skip close (the stream is mid-move). Only close on confirmed failure. Keep `deathCauseNatural` semantics intact for the rest.
   - The sticky-backstop / `allStreamsIdle` (`stream_entry.go:122`) and `snapshotDrainStreams`: treat `e.migrating.Load()==true` as NOT active (it's leaving the slot) so drain can finish — add the check inside the Range callbacks.
   - `proxy/socks5/tcp.go` uplink goroutine (`:652`-ish read → `:703` `client.StreamWrite`): when a MIGRATE for this stream is in flight, hold uplink (do not StreamWrite on the old slot); resume sending after MIGRATE_OK (the stream's `slotIdx` now points at B and `StreamWrite` routes to B). Implement as a per-stream `uplinkGate` (a channel/flag the migrate path closes on OK) the uplink goroutine checks before each write. Keep it minimal: a `migrating` check + short wait loop bounded by `migrateAckTimeout`.

4. Run: `go test ./client/ -run 'TestHandleSlotDeath_Resumes|TestHandleSlotDeath_Closes|TestDrainTeardown_Skips|TestMigratingNotCounted' -v` → PASS. `go test ./client/ ./proxy/socks5/ -v` → no regression. `go build ./...`.
   **User/CI step (Linux):** `go test -race -count=3 ./client/ -run 'HandleSlotDeath|Drain|Migrat'`.

5. Commit: `git add client/stream_entry.go client/ws_pool.go proxy/socks5/tcp.go client/migrate_resume_test.go && git commit -m "feat(bug9): client — uplink barrier + RESUME-on-slot-death + drain coordination migrating flag (F10, §5.3)"`

---

# LAYER 8 — METRICS + ENV FINALIZATION

Wire all §4.3 counters into the hand-rolled exporters (project does NOT use prometheus/client_golang — atomic counters + text exposition, per CLAUDE.md Phase 2 note) and finalize the env table (§7). Some counters were referenced in earlier tasks as `Stats.X` / `h.metrics.X` placeholders — this layer defines them.

---

## Task 18 — Server metrics (`server/metrics.go`) + env flags (`cmd/shadowlink-server/main.go`)

Defines the server-side counters used by Tasks 11-12 and the server env flags (§7). Pattern: existing atomic counters in `server/metrics.go` + the `-flow-max-window` flag pattern in `cmd/shadowlink-server/main.go:68`.

**Files:**
- Modify: `server/metrics.go`
- Modify: `server/handler.go` (config fields + Handler init: `serverMasterKey`, `relayReg`, limits)
- Modify: `cmd/shadowlink-server/main.go`
- Modify: `server/config.go`
- Create: `server/migrate_metrics_test.go`

**Steps:**

1. Write failing test `server/migrate_metrics_test.go`:
   ```go
   func TestMigrateMetricsExist(t *testing.T) {
   	m := newMetrics() // or the existing constructor
   	m.MigrateOK.Add(1)
   	m.MigrateFailNotFound.Add(1)
   	m.ResumeOK.Add(1)
   	m.OrphanedRelaysActive.Add(1)
   	m.OrphanFDBudgetRejected.Add(1)
   	m.MigrateGraceExpired.Add(1)
   	m.MigrateTailResent.Add(1)
   	if m.MigrateOK.Load() != 1 { t.Fatal("MigrateOK not wired") }
   }

   func TestMigrateEnvDefaults(t *testing.T) {
   	// default config: StreamMigrationEnabled=true, grace=8s, perClient=16,
   	// total=1024, ackTimeout=1.5s.
   }
   ```

2. Run → FAIL.

3. Minimal impl:
   - `server/metrics.go`: add atomic counters (mirror existing `FlowSessionsActive` etc.):
     `MigrateOK`, `MigrateFailNotFound`, `MigrateFailBadProof`, `MigrateFailLimit`, `MigrateFailDestClosed`, `MigrateTimeout`, `ResumeOK`, `ResumeFailNotFound`, `ResumeFailBadProof`, `ResumeFailGraceExpired`, `ResumeFailLimit`, `OrphanedRelaysActive` (gauge), `OrphanedEvictedLimit`, `OrphanFDBudgetRejected`, `MigrateGraceExpired`, `MigrateTailResent`, `MigrateTailBufferedBytes` (gauge). Add them to the text exporter section (the `shadowlink_*` names from §4.3) and the JSON snapshot.
   - `server/config.go`: add `StreamMigrationEnabled bool`, `MigrateGracePeriod time.Duration`, `MaxOrphanedPerClient int`, `MaxOrphanedTotal int` with defaults (true / 8s / 16 / 1024). `serverMasterKey []byte` is the existing static server key material (reuse — do NOT generate a new one).
   - `cmd/shadowlink-server/main.go`: add flags after `flow-max-window` (`:68`):
     ```go
     streamMigration := flag.Bool("stream-migration", true, "Bug #9: enable stream migration across WS slots")
     migrateGrace := flag.Duration("migrate-grace", 8*time.Second, "Bug #9: how long to hold an orphaned relay for RESUME (0 disables grace)")
     migrateMaxOrphaned := flag.Int("migrate-max-orphaned", 16, "Bug #9: max orphaned relays per clientID")
     migrateMaxOrphanedTotal := flag.Int("migrate-max-orphaned-total", 1024, "Bug #9: global cap on orphaned relays")
     ```
     Also read env equivalents `SHADOWLINK_STREAM_MIGRATION` / `SHADOWLINK_MIGRATE_GRACE` / `SHADOWLINK_MIGRATE_MAX_ORPHANED` / `SHADOWLINK_MIGRATE_MAX_ORPHANED_TOTAL` (flag default applies when unset, like flow-max-window). Plumb into `config`.
   - `server/handler.go`: init `h.relayReg = newRelayRegistry()` with limits + FD budget (Task 12) in the Handler constructor; store `h.serverMasterKey`. Maintain `OrphanedRelaysActive` gauge on orphan add/remove.

4. Run: `go test ./server/ -run 'TestMigrateMetrics|TestMigrateEnvDefaults' -v` → PASS. `go build ./...`. `go vet ./...`.

5. Commit: `git add server/metrics.go server/config.go server/handler.go cmd/shadowlink-server/main.go server/migrate_metrics_test.go && git commit -m "feat(bug9): server metrics + env flags (§4.3, §7)"`

---

## Task 19 — Client metrics (`client/stats.go`) + client env helpers

Defines the client-side counters used by Tasks 14-17 (`StreamReassemblyOverflow`, `StreamReassemblyGapTimeout`, `MigrateTimeout`, etc.) + `reassemblyGapTimeout`/`reassemblyMaxBuffered` env helpers (§7).

**Files:**
- Modify: `client/stats.go`
- Modify: `client/ws_pool.go` (or a small `client/migrate_env.go`) — env helpers
- Create: `client/migrate_stats_test.go`

**Steps:**

1. Write failing test `client/migrate_stats_test.go`:
   ```go
   func TestClientMigrateStatsExist(t *testing.T) {
   	Stats.StreamReassemblyOverflow.Add(1)
   	Stats.StreamReassemblyGapTimeout.Add(1)
   	Stats.MigrateOK.Add(1)
   	Stats.MigrateTimeout.Add(1)
   	Stats.ResumeOK.Add(1)
   	if Stats.MigrateOK.Load() != 1 { t.Fatal("not wired") }
   }
   func TestReassemblyEnvDefaults(t *testing.T) {
   	t.Setenv("SHADOWLINK_REASSEMBLY_GAP_TIMEOUT", "")
   	if reassemblyGapTimeout != 2*time.Second && reassemblyGapTimeoutFromEnv() != 2*time.Second {
   		t.Fatal("default gap timeout != 2s")
   	}
   	t.Setenv("SHADOWLINK_REASSEMBLY_BUFFER", "")
   	if reassemblyMaxBufferedFromEnv() != 4<<20 {
   		t.Fatal("default buffer != 4MB")
   	}
   }
   ```

2. Run → FAIL.

3. Minimal impl:
   - `client/stats.go`: add atomic counters to the `Stats` struct (mirror `WriterExits`, `DownlinkBytes`, `FlowWindowUpdatesSent`): `StreamReassemblyBufferedBytes` (gauge), `StreamReassemblyOverflow`, `StreamReassemblyGapTimeout`, `MigrateOK`, `MigrateFail`, `MigrateTimeout`, `ResumeOK`, `ResumeFail`. Add to the text/JSON exposition.
   - env helpers (`reassemblyGapTimeoutFromEnv`, `reassemblyMaxBufferedFromEnv`) with the standard parse-or-default pattern (`flowWindowFromEnv`, `stream_flow.go:29`). Default 2s / 4MB. If both a const and an env-helper are referenced by Task 14, keep just the env-helper and have Task 14 call it once at downlink-goroutine start.

4. Run: `go test ./client/ -run 'TestClientMigrateStats|TestReassemblyEnvDefaults' -v` → PASS. `go build ./...`.

5. Commit: `git add client/stats.go client/migrate_env.go client/migrate_stats_test.go && git commit -m "feat(bug9): client metrics + reassembly env helpers (§4.3, §7)"`

---

# LAYER 9 — INTEGRATION + ACCEPTANCE

End-to-end tests over a real (in-process) client↔server WS pair, plus the perf/anti-DPI acceptance harnesses. These are the spec §6 acceptance gates.

---

## Task 20 — End-to-end migration integration tests (no byte loss, grace-resume, A→B→C, compat)

Full-stack in-process tests: spin up a `Handler` + WS server (httptest or the existing test harness used by `server/websocket_test.go`), connect a real client pool, open a stream, force a preemptive migration and a sudden slot death, assert bytes arrive intact and in order.

**Files:**
- Create: `server/migrate_e2e_test.go`

**Steps:**

1. Write failing tests (use the existing WS test harness pattern — find it via the current `server/*_test.go` that exercises `runWebSocketSession`):
   ```go
   func TestE2E_PreemptiveMigration_NoByteLoss(t *testing.T) {
   	// stream downloads >1MB from a fake origin; trigger MIGRATE mid-flight;
   	// assert client-received bytes == origin bytes, exact order (sha256 match).
   }
   func TestE2E_GraceResume_AfterSuddenSlotDeath(t *testing.T) {
   	// kill slot A WS-conn abruptly; client sends RESUME on B within grace;
   	// stream continues; downBuffer drained in seq order; no loss.
   }
   func TestE2E_DoubleMigration_ABC_OrderPreserved(t *testing.T) {
   	// A→B→C; downSeqCounter monotonic across both; reassembler drops no valid data.
   }
   func TestE2E_Compat_NewClientOldServer(t *testing.T) {
   	// server with StreamMigrationEnabled=false → capability off → legacy path,
   	// stream works exactly as today (no seq, no migration).
   }
   func TestE2E_Compat_OldClientNewServer(t *testing.T) {
   	// client advertises no migrate bit → server keeps legacy relay; works.
   }
   func TestE2E_TailResentOnADeathBeforeAck(t *testing.T) {
   	// preemptive migrate, A dies before StreamAck → unackedTail resent on B;
   	// client dedups duplicate seqs; final bytes intact.
   }
   ```

2. Run → FAIL.

3. Minimal impl: implement the harness + assertions. Drive migration triggers directly (call the internal migrate path / inject slot death) rather than waiting wall-clock 60s. Reuse origin-server + sha256 verification idioms. No production code changes expected — if a test reveals a defect, fix the production code in this commit and note it.

4. Run: `go test ./server/ -run TestE2E -v` → PASS. `go build ./...`.
   **User/CI step (Linux):** `go test -race -count=3 ./server/ -run TestE2E`.

5. Commit: `git add server/migrate_e2e_test.go && git commit -m "test(bug9): e2e — no-byte-loss migration, grace-resume, A→B→C, compat matrix, tail-resend (§6)"`

---

## Task 21 — Perf (session-mu contention, NEW-4) + anti-DPI (FFT/ACF) acceptance harnesses

The two acceptance harnesses the spec mandates (§6 Race/HoL/Perf + §5.6 anti-DPI): (a) a benchmark migrating hundreds of streams onto ONE slot B and measuring `NextSeqNum` mutex contention vs a spread baseline (NEW-4); (b) an FFT/ACF check over simulated migration timestamps confirming no periodic peak (F7). These gate the canary; if (a) shows regression, apply the §8 mitigation (atomic sendSeq or spread cap).

**Files:**
- Create: `server/migrate_perf_test.go` (benchmark + mutexprofile guidance)
- Create: `client/migrate_antidpi_test.go` (FFT/ACF over migration offsets)

**Steps:**

1. Write the benchmark + tests:
   ```go
   // server/migrate_perf_test.go
   func BenchmarkRelayContention_AllOnOneSlot(b *testing.B) { /* N relayLoops, one session B */ }
   func BenchmarkRelayContention_SpreadBaseline(b *testing.B) { /* N relayLoops, N sessions */ }
   func TestSessionMuContention_NoThroughputCliff(t *testing.T) {
   	// run both at N=256; assert all-on-one throughput >= X% of spread baseline.
   	// (Threshold documented; if it fails, mitigation note triggers.)
   }
   ```
   ```go
   // client/migrate_antidpi_test.go
   func TestMigrationTimestamps_NoPeriodicFFTPeak(t *testing.T) {
   	// generate migration offsets via the Task 16 jitter/spread sampler for many
   	// slots/streams; run a DFT; assert no dominant peak above noise floor
   	// (mirror the jittered-keepalive check from wire-trigger followup 2026-05-02).
   }
   func TestMigrationTimestamps_ACFNoPeak(t *testing.T) { /* autocorrelation flat */ }
   ```

2. Run → FAIL.

3. Minimal impl: implement the harnesses against the real samplers/relay loop. For the FFT, reuse the approach from the existing jittered-keepalive acceptance (search `client/jitter_test.go` / wire-trigger followup tests for the DFT helper; if none, implement a small real-DFT over the offset series and assert max-bin / mean < threshold).

4. Run: `go test ./server/ -run TestSessionMuContention -v`, `go test -bench BenchmarkRelayContention -benchmem ./server/`, `go test ./client/ -run TestMigrationTimestamps -v` → PASS.
   **User/CI step (Linux):** `go test -mutexprofile mu.out -bench BenchmarkRelayContention ./server/` and inspect contention; `go test -race -count=3 ./server/ ./client/`.

5. Commit: `git add server/migrate_perf_test.go client/migrate_antidpi_test.go && git commit -m "test(bug9): perf session-mu contention (NEW-4) + anti-DPI FFT/ACF acceptance (F7, §6)"`

---

# FINAL — Self-review

(Done by the executing session after Task 21, before declaring READY-TO-SHIP — mirror Bug#6/#8 final opus review.)

## Spec coverage (§3-§7 → tasks)

| Spec section | Task(s) |
|---|---|
| §3.1 per-stream seq format + NEW-2 guard + NEW-3 invariant | 2, 9, 14 |
| §3.2 FlagMigrate/Resume/StreamAck | 1 |
| §3.3 control-frame formats | 1 |
| §3.4 MIGRATE_OK/FAIL replies | 11, 15 |
| §3.5 capability negotiation + migrateAckTimeout (F3) | 5, 6 |
| §3.6 globalStreamID registry key (F11) | 8, 10 |
| §4.1 HKDF + HMAC proof + nonce (F2, F12) | 3, 4 |
| §4.2 DoS caps + FD budget (F5, F6) | 12 |
| §4.3 metrics | 18, 19 |
| §4.4 / §5.6 anti-DPI distribution (F7) | 16, 21 |
| §5.1 relayRegistry + relayEntry + binding (NEW-5) + state machine (F8) | 7, 8 |
| §5.2 relay-loop dynamic bound + decouple from done (F4) | 10 |
| §5.3 preemptive migration + unackedTail resend (NEW-1) + uplink barrier | 9, 11, 17 |
| §5.4 client reassembler + gap-timeout (NEW-1) + StreamAck barrier | 13, 14, 15 |
| §5.5 grace-fallback + dest-closed (F13) | 11, 12 |
| §5.7 drain coordination (F10) | 17 |
| §5.8 edge cases (double-migrate, etc.) | 20 |
| §5.9 credit migrates into relayEntry (F9) | 8, 10 |
| §6 testing (e2e, compat, perf, anti-DPI) | 20, 21 |
| §7 env flags | 6, 18, 19 |

**All layers §3-§7 covered: YES.** Every spec section maps to ≥1 task; every review finding F1-F13 + NEW-1..NEW-5 maps to a task (see commit messages).

## Placeholder scan

- No "add error handling" / "similar to Task N" / "TODO" left in task bodies — every step carries concrete code or a concrete code sketch with named symbols.
- The only deliberately-abbreviated bodies are the integration/perf test *function bodies* (Tasks 20-21) and a few server e2e/handler tests (Task 11) where the harness scaffolding is described in prose + signatures rather than full text — these are test scaffolds whose exact assertions are spelled out; the production code they exercise is fully specified in Tasks 1-19. This is acceptable for XL integration tests (Bug#8 plan did the same for its acceptance layer).

## Type-consistency check

Names are used identically across tasks (see the shared-type table in Architecture):
- `FlagMigrate/FlagResume/FlagStreamAck` (Task 1) → Tasks 5,6,11,14,15.
- `NewStreamDataChunkSeq`/`ParseStreamDataSeq` (Task 2) → Tasks 10,14.
- `BuildMigrateFrame`/`ParseMigrateFrame`/`BuildStreamAckFrame`/`ParseStreamAckFrame` (Task 1) → Tasks 11,14,15.
- `Session.MigrateNonce` (Task 3) → Tasks 4,11.
- `DeriveServerPerClientKey`/`ComputeStreamProof`/`VerifyStreamProof` (Task 4) → Tasks 11,15.
- `BuildFlowCtlMarkerV2`/`ParseFlowCtlMarkerV2` (Task 5) → Task 6.
- `binding{session,writer}` + `relayEntry` (Task 7, fields `downSeqCounter`/`downBuffer`/`unackedTail`/`bound`/`state`/`credit`) → Tasks 8,9,10,11,12. `relayEntry.tc` starts as a minimal interface (Task 7) and is refined to `net.Conn` in Task 10 — flagged explicitly in both task bodies.
- `relayRegistry` + `newRelayRegistry`/`add`/`find`/`remove`/`admitOrphan` (Tasks 8,12) → Tasks 10,11.
- `pendingDownFrame`/`boundedBuffer` (Task 7) → Tasks 9,11.
- `streamFrame{seq,data}` + `RouteToStreamSeq` (Task 14) → Tasks 14,17.
- `reassembler`/`reasmStatus` (Task 13) → Task 14.
- State consts `stActive/stOrphaned/stClosing` (Task 7) → Tasks 8,11,12.

No collisions, no renamed-mid-plan symbols. **Type-consistency OK.**

## Notes for the executing session

- Branch: `new-version`. One commit per task. Run per-task spec+quality review (subagent-driven-development).
- Windows dev: plain `go test`. Every `-race`/`-count=3`/`-bench`/`-mutexprofile` line is a **Linux/CI step for the user** — collect them and hand to the user at the end (the relay torn-pair test, e2e, and perf benches are the ones that MUST run under `-race` on Linux before canary).
- `gofmt -w` is NOT run automatically (CRLF preexists in repo per Bug#6 notes) — leave line endings as-is.
- Deferred to canary (not this plan): the actual pl1 redeploy (staged, server-first), and the field FFT/ACF check on real migration timestamps (Task 21 only proves the *sampler* is non-periodic).

