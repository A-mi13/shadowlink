# ShadowLink Body-Prefix Protocol v1

**Status:** Phase 1 deployed 2026-04 (hybrid with v0). Phase 3 legacy-retirement planned T+6mo.

The v1 wire format eliminates the `Authorization: Bearer` header from data
traffic and carries the session token at the start of the JSON-envelope
`data` field. Closes DPI-detectable vector V1 (Authorization-on-every-frame).

## Wire Format

All data transport rides inside the analytics envelope:

```json
{"events":[{"type":"page_view","ts":<ms>,"data":"<base64url(payload)>"}]}
```

`payload` is format-dependent.

### Data request

```
payload = [tokenWithHint (36 B)] [encrypted_chunk (variable)]

tokenWithHint  = 4B XOR hint || 32B AES-GCM(session_token)
encrypted_chunk = AES-GCM per core.Chunk (header + ciphertext + 16B tag)
```

Server dispatch (`handleNewFormatPost`) reads the fixed-size `sessionTokenSize`
prefix, looks up the session via `findSessionByHint` (O(1)), then decrypts
the remainder with `session.DecryptChunkSafe`. Tag failure → fall closed to
decoy.

### Handshake request

```
payload = [ephemeral_pub (32 B)] [encrypted_client_id (65 B)] [random_pad (0..N)]

encrypted_client_id = NaCl Box(timestamp_8B || client_id_16B)
random_pad          = sampled from PayloadDistribution.UploadSize()
```

`core.EncryptedClientIDSize = 65` is protocol-fixed and assumes a 16-byte
UUID `client_id`. Non-UUID clients must use the legacy v0 path (client
detects this and skips `handshakeNew`, per client nuance N-D2).

`random_pad` closes the first-packet-size-signature vector: handshake byte
length is drawn from the same distribution as steady-state data uploads, so
a DPI observer cannot distinguish a fresh session by size alone.

### WebSocket upgrade + first frame

The upgrade request carries **no** Authorization header. Immediately after
the `101 Switching Protocols` response, the client sends exactly one binary
frame:

```
first_frame = [tokenWithHint (36 B)] [encrypted_chunk (variable)]

encrypted_chunk = AES-GCM over a FlagKeepalive Chunk
```

Server `authenticateFirstFrame` validates this within a 1.5 s deadline. Only
`FlagKeepalive` is accepted as the first flag — `FlagConnect`, `FlagData`,
`FlagStreamOpen` on the first frame are rejected and the connection is
dropped via `fakeAckAndClose` (random 200–2000 B body, jitter, normal close
code) to match the timing of a legitimate idle-close.

### Split-HTTP download stream

Previously a bare GET with `Authorization: Bearer`. In v1 it is a POST whose
body carries:

```
payload = [tokenWithHint (36 B)] [encrypted FlagStreamOpen Chunk (variable)]
```

Server `handleDownloadStreamV2` decrypts, confirms `FlagStreamOpen`, and
flips the connection to a chunked download stream.

## Session Sequence Space

- Handshake POST does **not** consume client→server seq space.
- WebSocket first frame starts at seq=0 client→server (consumed by
  FlagKeepalive).
- POST data first chunk starts at seq=0 client→server (the first
  non-handshake payload).
- A session picks ONE primary transport (WS xor POST). Mixing on the same
  session is not supported in v1.

Server anti-replay uses a 16384-slot sliding window (`core.WindowSize`) to
tolerate out-of-order arrivals from per-stream WS pools and CDN jitter.

## Version Negotiation

`ServerHello` JSON includes `"_v": <uint8>`. Clients pin
`session.ProtoVersion` on receipt:

- `_v == 1` → new body-prefix keys; `session.ProtoVersion = 1`.
- `_v` absent → legacy v0 server; client falls back if TLS is verified
  (InsecureSkipVerify off) — else it hard-fails, since a MITM could strip
  `_v` without TLS guarantees.
- `_v > 1` → client refuses with "update required".

Downgrade attempts that alter `_v` produce non-matching session keys because
`_v` is bound into `HKDF-Expand` info in `core.DeriveSessionKeys`. See
Phase A task A4 in the migration plan for the binding proof test.

## Hybrid Compatibility (Phase 1)

The server dispatches via a single gate:

| Request shape                            | Route                 |
|------------------------------------------|-----------------------|
| GET + Authorization                      | legacy SplitHTTP GET  |
| POST + application/json + Authorization  | legacy Bearer path    |
| POST + application/json (no Auth header) | new body-prefix path  |
| Upgrade: websocket                       | protocol-agnostic WS  |
| anything else                            | decoy site            |

Migrated clients stop sending Authorization, landing on the new path.
Pre-migration clients keep working via the legacy branch until their binary
is updated.

Client-side probe flow (`runHandshakeSequence`):

1. Non-UUID clientID → skip new path, go direct to legacy (N-D2).
2. Try `handshakeNew` (padded payload, no Authorization).
3. HTTP 4xx → fall back to legacy path *if* TLS is verified, else hard-fail.
4. HTTP 200 + body that isn't JSON → hard-fail with "possible MITM".
5. Success with `_v == nil` → fall back to legacy, same InsecureSkipVerify
   guard.
6. Success with `_v == 1` → pin `session.ProtoVersion = 1`.

## Phase 3 (T+6mo) Legacy Retirement

After the migration tail has drained (tracked via
`shadowlink_handshakes_legacy_total / shadowlink_handshakes_total`), the
legacy branch is gated behind `ALLOW_LEGACY_EMERGENCY=true` for a 24h
emergency recall window, then removed.

## Monitoring

Prometheus counters exposed at `/metrics?format=prom`:

| Counter                                              | Meaning |
|------------------------------------------------------|---------|
| `shadowlink_handshakes_new_total`                    | v1 handshakes |
| `shadowlink_handshakes_legacy_total`                 | v0 handshakes |
| `shadowlink_legacy_path_hits_total`                  | POST dispatches → legacy branch |
| `shadowlink_new_path_hits_total`                     | POST dispatches → new branch |
| `shadowlink_dual_auth_detected_total`                | client sending BOTH body-prefix and Authorization — rollout bug canary |
| `shadowlink_v0_fallback_from_new_path_total`         | legacy-shaped handshakes entering via the new-path router — sizes the tail |

Target migration ratio before Phase 3: `new / total ≥ 0.99` for 7
consecutive days.

## References

- Spec: `docs/superpowers/specs/2026-04-20-bearer-body-prefix-migration.md`
- Plan: `docs/superpowers/plans/2026-04-20-bearer-body-prefix-migration.md`
- DPI research: `shadowlink/docs/research/2026-04-19-dpi-evasion-state-of-art.md`
- Phase nuances: memory files `phase-a-nuances.md`, `phase-b-nuances.md`,
  `phase-c-nuances.md`, `phase-d-nuances.md`
