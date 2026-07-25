# Firefox H2-pairing gate — diagnostic result

Task A6 gate-proof. Question: can we add a Firefox profile whose TLS layer is
uTLS `HelloFirefox_148` (cold-path) but whose H2 layer is bogdanfinn
`Firefox_147` (hot-path) without producing a detectable TLS↔H2 mismatch on the
wire?

H2 SETTINGS are sent ONLY by the bogdanfinn hot-path (uTLS is the TLS layer and
sends no H2). So the candidate Firefox profile would ship:

- TLS ClientHello = `utls.HelloFirefox_148`
- H2 SETTINGS     = `profiles.Firefox_147` (bogdanfinn)

A mismatch exists only if real Firefox 148 changed its H2 SETTINGS relative to
147. We cannot run real Firefox 148 here, so we use a proxy: Firefox is
conservative with H2 between minors — if bogdanfinn's H2 is identical across
adjacent minors, that is strong evidence Firefox did not touch H2 at 148 either.

## Version availability (verified, not assumed)

| Layer | Available Firefox (140-series) | Notes |
|-------|-------------------------------|-------|
| uTLS (our fork v1.8.3-aa6edf4b) | `HelloFirefox_148` only | 148 = `HelloFirefox_Auto`; no 147 |
| bogdanfinn tls-client v1.14.0 | `Firefox_146_PSK`, `Firefox_147`, `Firefox_147_PSK` | **no flat `Firefox_146`** |

**Discrepancy vs original spec:** the spec assumed `profiles.Firefox_146`
exists. It does NOT in v1.14.0 — only `Firefox_146_PSK`. The gate test uses
`Firefox_146_PSK` in the "146" role and proves PSK is H2-orthogonal (below), so
the substitution is valid. There is still no flat-versioned pair (148/148 or
147/147), so the candidate pair would be 148(TLS)/147(H2) — exactly as the spec
described.

## Measured H2 parameters

All values measured via `profiles.ClientProfile` getters.

### Firefox_146_PSK (proxy for "146")
- settings: `HEADER_TABLE_SIZE:65536 ENABLE_PUSH:0 INITIAL_WINDOW_SIZE:131072 MAX_FRAME_SIZE:16384`
- order: `[HEADER_TABLE_SIZE ENABLE_PUSH INITIAL_WINDOW_SIZE MAX_FRAME_SIZE]`
- connectionFlow: `12517377`
- pseudoHeaderOrder: `[:method :path :authority :scheme]`
- priorities: `[]`

### Firefox_147
- settings: `HEADER_TABLE_SIZE:65536 ENABLE_PUSH:0 INITIAL_WINDOW_SIZE:131072 MAX_FRAME_SIZE:16384`
- order: `[HEADER_TABLE_SIZE ENABLE_PUSH INITIAL_WINDOW_SIZE MAX_FRAME_SIZE]`
- connectionFlow: `12517377`
- pseudoHeaderOrder: `[:method :path :authority :scheme]`
- priorities: `[]`

## Comparisons

| Comparison | Result |
|------------|--------|
| 146_PSK vs 147 (settings, order, flow, pseudo) | **IDENTICAL** — no GATE-SIGNAL |
| 147 vs 147_PSK (PSK orthogonality check) | **IDENTICAL** — PSK does not touch H2 → 146_PSK is a valid "146" proxy |
| 135 vs 147 (wide window, 12 minors) | **IDENTICAL** — Firefox H2 stable across 12 minor versions |

Also verified identical on Firefox_133. Across every available Firefox profile
in bogdanfinn (133, 135, 146, 147), the H2 SETTINGS / order / connectionFlow /
pseudoHeaderOrder are byte-for-byte the same.

## Verdict

**GATE: PASS** (diagnostic recommendation — final call is the controller's).

Reasoning:
1. No GATE-SIGNAL: bogdanfinn's H2 for 146 and 147 is identical on all four
   compared surfaces.
2. PSK proven H2-orthogonal (147 == 147_PSK), so the 146_PSK substitution
   introduced no contamination.
3. Wide-window corroboration: H2 identical from 133 through 147 — Firefox has
   not changed its H2 SETTINGS in 12+ minor versions. The probability that it
   changed at exactly 148 (while 133–147 stayed frozen) is very low.

Therefore the candidate pair TLS=`HelloFirefox_148` / H2=`Firefox_147` is very
unlikely to produce a wire-detectable TLS↔H2 mismatch.

## Residual risk (controller input)

- This is a PROXY argument, not a capture of real Firefox 148 H2. It cannot
  exclude a Firefox 148 H2 change with 100% certainty — only show it is
  improbable given the multi-version freeze.
- bogdanfinn `Firefox_147` H2 itself is a model, not a guaranteed match for real
  148 wire — but Chrome lockstep relies on the same modelling assumption.
- A direct capture of real Firefox 148 (`SETTINGS` frame + `WINDOW_UPDATE`
  connection-flow + HEADERS pseudo order) would upgrade this from "strong
  evidence" to "confirmed". Not performed in this task.

**This task collects data only. It does NOT add Firefox to the registry.** The
add/Chrome-only decision is left to the controller.

## Reproduce

```
go test ./skins/browser/ -run TestFirefoxGate_H2Settings146vs147 -v
```
