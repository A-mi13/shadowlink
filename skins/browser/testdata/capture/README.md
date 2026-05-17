# Mixpanel Capture Tooling — RETIRED 2026-04-28

> ⚠️ **STATUS: FROZEN.** This tooling was set up for Phase 3 Plan B (Mixpanel envelope mimicry) which was **cancelled** the same day per threat model assessment. Files preserved for fast reactivation if DPI evolves to deep body inspection.

## Why retired

Field evidence in 2026: Hysteria2-modified, VLESS+Reality, and TrustTunnel all work in РФ. None of them mimic application body shape. ТСПУ does not currently parse JSON envelope structure for known SDK match. Wire-format work closed a phantom signal.

ShadowLink shifted focus to **Domain Diversity** (`docs/superpowers/specs/2026-04-28-shadowlink-domain-diversity-design.md`) — closing single-domain failure mode (real, observed in field).

## What's here

- `setup.ps1` / `setup.sh` — venv bootstrap (Python 3.14 + mitmproxy 12.2.2 + playwright 1.58.0 + Chromium)
- `requirements.txt` — pinned versions
- `mixpanel_capture.html` — browser harness with mixpanel-js SDK, 55 events
- `mitmproxy_dump.py` — addon filtering Mixpanel POSTs
- `run_capture.py` — Playwright driver
- `.venv/` — installed environment (gitignored)
- `.gitignore` — exclude venv + raw flows

## How to reactivate

If threat model shifts (DPI starts parsing body shapes):

1. Re-read retired spec: `docs/superpowers/specs/2026-04-28-shadowlink-phase-3-wire-modernization-design.md`
2. Re-read retired plan: `docs/superpowers/plans/2026-04-28-shadowlink-phase-3-plan-b-stage1.md`
3. Run capture: `MIXPANEL_TOKEN=<token> ./.venv/Scripts/python.exe run_capture.py`
4. Re-validate plan against current state of code (Plan A timing distributions may have shifted constants)
5. Restart Plan B Stage 1 with potentially updated padding refit numbers

Estimated reactivation cost: 1 session.

## Memory references

- Decision rationale: memory `phase-3-plan-a-done.md` + brainstorming log 2026-04-28
- Retired spec marker: see header of `2026-04-28-shadowlink-phase-3-wire-modernization-design.md`
