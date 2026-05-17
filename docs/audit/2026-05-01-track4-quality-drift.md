# ShadowLink Quality & Drift Audit — Track 4

**Date**: 2026-05-01
**Reviewer**: Claude Sonnet (automated grep-driven audit)
**Scope**: Post Tier-S R.3a drift check — mismatched comments, test gaps, race smells, linter, -race readiness.

---

## Executive Summary

Codebase is in solid shape post-Phase-0/1/2/3 refactors. The most significant
finding is a **persistent zombie UDP/WB-TURN block** in `internal/admin/` that
the 2026-04-25 cleanup audit (Part A.2) already documented as HIGH severity but
has NOT been fixed: `enable_udp`/`udp_listen`/`EnableUDP`/`UDPPort` still live
in `shadowlink_handlers.go` and `steps_shadowlink.go`. The handlers_test.go
was updated (negated the assertions — now checks absence), which is good, but
the production code path that patches the systemd ExecStart with deleted flags
(≈line 723-733) remains, meaning a live server **Update** would break the
running daemon. Beyond this carryover, new Tier-S / Domain-Diversity code is
clean: no stale Bearer references in production paths, no unguarded goroutine
launches, no `for i:=0` loops.

---

## 1. Mismatched / Stale Comments

### 1.1 UDP / WB TURN zombie (HIGH — carryover from 2026-04-25 audit, still present)

Confirmed live via grep on `internal/admin`:

| File | Pattern still present |
|------|-----------------------|
| `internal/admin/shadowlink_handlers.go` | `EnableUDP`, `UDPPort` fields in `ShadowLinkConfig` struct; `// всегда включаем UDP для WB TURN relay` comment; sed-patch block adding `--enable-udp --udp-listen` to systemd unit |
| `internal/deploy/steps_shadowlink.go` | `EnableUDP`, `UDPPort` in `ShadowLinkDeployConfig`; YAML template writes `enable_udp:`/`udp_listen:` lines |

The test file (`shadowlink_handlers_test.go:37,75`) was already corrected to
assert **absence** (`if strings.Contains(out, "enable_udp")`), confirming the
contract changed — but production code still writes these fields. Risk: `Update`
handler's sed-patch attempts `--enable-udp` flag that no longer exists in the
server binary → `systemd start shadowlink` exits with "flag provided but not
defined".

### 1.2 Bearer comment in client/datapath.go (LOW — informational comment, accurate)

```
shadowlink/client/datapath.go:18
// Authorization: Bearer header. Gated via SHADOWLINK_DATAPATH_BODYPREFIX env
```
Comment describes legacy path that IS still accessible via opt-out env var —
this is accurate documentation, not a stale reference.

### 1.3 `withBearer` in test stubs (LOW — test-only, accurate)

```
shadowlink/client/performhandshake_test.go:84,101-102
func (t *probeTransport) post(..., withBearer bool) ...
req.Header.Set("Authorization", "Bearer stub")
```
Used by unit tests probing the negative path ("server should reject
Authorization header now"). Accurate per-test intent; safe.

### 1.4 `findSessionByHint` comment in migration_e2e_test.go (LOW)

```
shadowlink/client/migration_e2e_test.go:51
// findSessionByHint).
```
Dangling close-paren suggests the comment was trimmed when `findSession` was
deleted. Cosmetic only.

### 1.5 `client_test.go:30` legacy-path comment (LOW)

```
// legacy Bearer path, which the new client no longer uses by default.
```
Accurate — used to describe old behavior in a "should-no-longer-happen" test.
OK as-is.

---

## 2. Test Coverage Gaps

Glob result for `internal/admin/shadowlink_pool*.go`:

| File | Has `_test.go`? |
|------|----------------|
| `shadowlink_pool_models.go` | **NO** — no `shadowlink_pool_models_test.go` exists |
| `shadowlink_pool_servers_handlers.go` | YES → `shadowlink_pool_servers_handlers_test.go` |
| `shadowlink_pool_domains_handlers.go` | YES → `shadowlink_pool_domains_handlers_test.go` |
| `shadowlink_pool_decoy_templates_handlers.go` | YES → `shadowlink_pool_decoy_templates_handlers_test.go` |

`shadowlink_pool_models.go` is the **only untested file** in the pool namespace.
It likely contains shared structs/helpers used by the three handlers. Risk:
model-level validation logic (if any) is unverified in isolation.

---

## 3. Race Smells

### 3.1 `client/connmanager.go:320` — `startRotation()` goroutine (MEDIUM)

```go
go func() {
    for {
        interval := cm.lifecycle.NextActiveInterval()  // reads lifecycle state
        ...
    }
}()
```
`cm.lifecycle` is read inside the goroutine without any visible lock. If
`ConnManager` fields are mutated from outside (e.g. `SetDomainPool` added in
sub-phase C), there is a potential data race on the `lifecycle` field pointer.
Needs `-race` confirmation.

### 3.2 `client/client.go:964` — deferred key zeroing goroutine (LOW — by design)

```go
go func() {
    time.Sleep(5 * time.Second)
    oldSession.Destroy()
    core.ZeroBytes(oldToken)
}()
```
Pattern is intentional (R-4 comment in code). The 5s delay is correct for
in-flight handler safety. Not a race per se, but the goroutine leaks until
timeout — acceptable.

### 3.3 `client/probe.go:151` — probe goroutine without cancel propagation (LOW)

`go func()` launch inside `probe.go` — if the caller context is cancelled
before the goroutine finishes, the goroutine continues until its internal
timeout. Minor leak under aggressive cancellation. Non-critical for current
use patterns.

---

## 4. Linter Cleanup

### 4.1 No `for i := 0; i < N; i++` loops found (CLEAN)

Grep for C-style for loops in `shadowlink/` returned **zero matches**.
All iteration uses range — Go 1.22+ range-over-int idiom already applied or
simply not needed.

### 4.2 `strings.Contains` chains in `client/client.go:33-34` (MINOR)

```go
return strings.Contains(ua, "Mozilla/") &&
    (strings.Contains(ua, "Chrome/") || strings.Contains(ua, "Firefox/") || strings.Contains(ua, "Safari/"))
```
Could be replaced with a small helper or `slices.ContainsFunc`, but the
current form is readable. No `slices.Contains` candidates found that would
materially benefit from replacement.

### 4.3 `cmd/shadowlink-client/main.go:449,460,468` — `strings.Contains` on routing table parser (MINOR)

Three `strings.Contains` calls parse IPv4 gateway strings from `netstat`
output. These are correctness-sensitive string probes that cannot be
replaced by `slices.Contains` — they check substrings, not equality.
No actionable linter suggestion here.

**Net linter verdict**: no actionable range-over-int or slices.Contains
refactors needed. The codebase already uses modern Go iteration patterns.

---

## 5. `-race` Readiness

The codebase has **explicit `-race` infrastructure** in two places:
`core/pool_race_test.go` (annotated "skip on Windows, run on Linux CI") and
`CLAUDE.md:325-331` which mandates `go test -race -count=3 ./server/ ./client/ ./skins/...`
before deploy. There are **zero `t.Parallel()` calls** in the test suite
(grep returned no matches), meaning tests run serially by default — this
limits the value of `-race` for detecting cross-test races but does not
prevent within-test race detection. The `pool_race_test.go` pattern
(explicit goroutine launch + sync within a single test) is the correct
approach. The absence of `t.Parallel()` is intentional on Windows dev hosts
(no CGO/gcc). **Gap**: Domain Diversity sub-phase A-D code
(`internal/admin/shadowlink_pool_*.go`) was added without any race-gated tests;
the DB-backed handlers are harder to race-test but the model helpers are not.
Overall `-race` posture: adequate for `shadowlink/` core; integration-layer
pool handlers have no coverage at all.

---

## 6. Cleanup Actions — Estimated Effort

| # | Action | Severity | Effort |
|---|--------|----------|--------|
| C1 | Remove `EnableUDP`/`UDPPort` fields + systemd-patch sed block from `internal/admin/shadowlink_handlers.go` (≈lines 40-41, 394-395, 567-569, 700-733, 881-894) and `internal/deploy/steps_shadowlink.go` (≈lines 26-27, 40-42, 49-67, 217-234) | HIGH | M |
| C2 | Add unit tests for `shadowlink_pool_models.go` struct validation / helpers | MEDIUM | S |
| C3 | Audit `ConnManager.lifecycle` field access in `startRotation()` goroutine — confirm no data race with `SetDomainPool` | MEDIUM | S |
| C4 | Remove dangling comment fragment in `migration_e2e_test.go:51` | LOW | S |
| C5 | Clean up `shadowlink/config.yaml` dev file — remove orphan `wbturn: true` line (noted in 2026-04-25 audit, still present per that audit) | LOW | S |
| C6 | Run `go mod tidy` to verify `github.com/pion/turn/v4` orphan dependency (confirmed by 2026-04-25 audit, not re-verified today) | LOW | S |

**Legend**: S = <30 min, M = 1-3h, L = >3h

---

*Audit performed via grep-only analysis. No code was modified.*
