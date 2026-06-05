# TSPU age-window tuning — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Резать WS-слоты ДО окна TSPU-заморозки (~130с) так, чтобы долгий single-stream GET (Claude update) не рвался; поднять server rate-limit под учащённую ротацию.

**Architecture:** Клиентский tuning порогов ротации + НОВЫЙ cap на per-slot staggerOffset (idx 0..15 uniform-cells), всё через env-флаги. Сервер: rate-limit уже YAML-ready — добавить блок `rate_limit:` в генератор config.yaml (main tree) с поднятыми значениями. Бинарь сервера НЕ меняется.

**Tech Stack:** Go, shadowlink module (client/ws_pool.go, cmd/nixavpn-client), main tree (internal/deploy).

**Спека:** `docs/superpowers/specs/2026-06-05-tspu-age-window-tuning-design.md` (опус-ревью CHANGES-REQUIRED → 2 BLOCKER исправлены).
**Ревью:** `docs/age-tuning-spec-review-opus-2026-06-05.md`.

**Финальные значения:** MaxSlotAge=75s, staggerStep=6s + staggerOffsetCap=45s, DrainHardCap=30s, migrationThresholdBase=45s, ageCutMinAgeMs=45s; ws_upgrade burst=90/refill=120, handshake burst=80/refill=300.

---

## File Structure

- `client/ws_pool.go` — staggerOffset формула с cap (метод вместо пакетной функции), новые поля транспорта `staggerStep`/`staggerOffsetCap`, `ageCutMinAge`; WSPoolConfig новые поля.
- `cmd/nixavpn-client/engine_shadowlink.go` — env-парсинг новых флагов + понижение дефолтов maxSlotAge/drainHardCap/migrationThreshold.
- `client/migrate_watchdog.go` — migrationThresholdBase env-default 60s→45s (env уже есть).
- `internal/deploy/steps_shadowlink.go` — рендер блока `rate_limit:` в config.yaml + поля в ShadowLinkYAMLParams.
- Тесты: `client/ws_pool_test.go`, `internal/deploy/steps_shadowlink_test.go`.

---

## Task 1: staggerOffset cap — формула + поля транспорта (BLOCKER-1)

**Files:**
- Modify: `client/ws_pool.go:517` (slotStaggerOffset → метод), `:473` (const), `:1118` (struct поля), `:1520` (NewWSPoolTransport), `:2127` (вызов)
- Modify: `client/ws_pool.go:1414+` (WSPoolConfig поля StaggerStep/StaggerOffsetCap)
- Test: `client/ws_pool_test.go`

- [ ] **Step 1: Failing test для capped staggerOffset**

```go
func TestSlotStaggerOffset_Capped(t *testing.T) {
	p := &WSPoolTransport{
		staggerStep:      6 * time.Second,
		staggerOffsetCap: 45 * time.Second,
	}
	// idx 0 → 0
	if got := p.slotStaggerOffset(0); got != 0 {
		t.Fatalf("idx=0: got %v want 0", got)
	}
	// idx 7 → 42s ± 3s jitter
	g7 := p.slotStaggerOffset(7)
	if g7 < 39*time.Second || g7 > 45*time.Second {
		t.Fatalf("idx=7: got %v want ~42s±3s", g7)
	}
	// idx 15 → capped 45s ± 3s jitter (NOT 90s)
	g15 := p.slotStaggerOffset(15)
	if g15 < 42*time.Second || g15 > 48*time.Second {
		t.Fatalf("idx=15: got %v want ~45s (capped), NOT 90s", g15)
	}
	// инвариант: idx=15 effective age < 130s freeze floor
	maxSlotAge := 75 * time.Second
	if eff := maxSlotAge + g15; eff >= 130*time.Second {
		t.Fatalf("idx=15 effectiveMaxAge=%v must be < 130s freeze window", eff)
	}
}
```

- [ ] **Step 2: Run — expect FAIL (slotStaggerOffset не метод, полей нет)**

Run: `cd shadowlink && go test ./client/ -run TestSlotStaggerOffset_Capped -v`
Expected: FAIL (compile: p.slotStaggerOffset undefined / staggerStep undefined)

- [ ] **Step 3: Добавить поля в WSPoolTransport struct (после maxSlotAge ~1125)**

```go
	maxSlotAge        time.Duration // rotate slot after this much wallclock age (0 = disabled)
	staggerStep       time.Duration // per-slot grid interval added to maxSlotAge (0 → slotRotationStaggerStep)
	staggerOffsetCap  time.Duration // max staggerOffset regardless of idx (0 → no cap); caps idx 8..15 under freeze window
	ageCutMinAge      time.Duration // slot-age floor for age-cut classification (0 → ageCutMinAgeMs default)
```

- [ ] **Step 4: Добавить поля в WSPoolConfig (после MaxSlotAge ~1436)**

```go
	// StaggerStep is the per-slot grid interval added to MaxSlotAge for
	// rotation. 0 → slotRotationStaggerStep default. Field-tune via
	// SHADOWLINK_STAGGER_STEP.
	StaggerStep time.Duration

	// StaggerOffsetCap caps the per-slot staggerOffset regardless of slot
	// index. The pool uses a 2*Size slice (uniform-cells), so idx runs 0..2*Size-1;
	// without a cap, high-idx slots rotate at MaxSlotAge + idx*StaggerStep which
	// can land inside the TSPU freeze window. 0 → no cap. Field-tune via
	// SHADOWLINK_STAGGER_OFFSET_CAP.
	StaggerOffsetCap time.Duration

	// AgeCutMinAge is the slot-age floor above which a terminal read error is
	// classified as an expected TSPU age-cut. 0 → ageCutMinAgeMs (60s) default.
	// Lower it in lockstep with MaxSlotAge so the classification window doesn't
	// collapse. Field-tune via SHADOWLINK_AGE_CUT_MIN_AGE.
	AgeCutMinAge time.Duration
```

- [ ] **Step 5: Присвоить поля в NewWSPoolTransport (рядом с maxSlotAge: cfg.MaxSlotAge ~1596)**

```go
		maxSlotAge:        cfg.MaxSlotAge,
		staggerStep:       cfg.StaggerStep,
		staggerOffsetCap:  cfg.StaggerOffsetCap,
		ageCutMinAge:      cfg.AgeCutMinAge,
```

- [ ] **Step 6: Переписать slotStaggerOffset как метод с cap (заменить функцию на :517)**

```go
// slotStaggerOffset returns the per-slot additive age-rotation offset for the
// given uniform-cells slice index (0..2*Size-1). Linear idx*step, capped at
// staggerOffsetCap (when >0) so high-idx slots don't rotate inside the TSPU
// freeze window, plus uniform [-step/2, step/2) jitter to smear FFT periodicity.
func (p *WSPoolTransport) slotStaggerOffset(idx int) time.Duration {
	if idx <= 0 {
		return 0
	}
	step := p.staggerStep
	if step <= 0 {
		step = slotRotationStaggerStep
	}
	base := time.Duration(idx) * step
	if p.staggerOffsetCap > 0 && base > p.staggerOffsetCap {
		base = p.staggerOffsetCap
	}
	jitter := time.Duration((rand.Float64() - 0.5) * float64(step))
	return base + jitter
}
```

- [ ] **Step 7: Обновить вызов на :2127**

Было: `slot.staggerOffsetNs.Store(int64(slotStaggerOffset(idx)))`
Стало: `slot.staggerOffsetNs.Store(int64(p.slotStaggerOffset(idx)))`

- [ ] **Step 8: Run — expect PASS**

Run: `cd shadowlink && go test ./client/ -run TestSlotStaggerOffset_Capped -v`
Expected: PASS

- [ ] **Step 9: Переписать существующие тесты, пинящие старую формулу**

В `client/ws_pool_test.go:489, :994, :1063` — найти `int(i)*int(slotRotationStaggerStep)` / прямой вызов `slotStaggerOffset(idx)`. Заменить на вызов через транспорт `p.slotStaggerOffset(idx)` и обновить ожидания на capped-формулу (для idx ≤ cap/step линейно, выше — потолок). Если тест конструирует staggerOffset без транспорта — создать `p := &WSPoolTransport{staggerStep: slotRotationStaggerStep}` (cap=0 → старое поведение для совместимости).

- [ ] **Step 10: Run весь client — expect PASS**

Run: `cd shadowlink && go test ./client/ -count=1`
Expected: ok

- [ ] **Step 11: Commit**

```bash
git add shadowlink/client/ws_pool.go shadowlink/client/ws_pool_test.go
git commit -m "fix(shadowlink): cap staggerOffset under TSPU freeze window (idx 0..15)"
```

---

## Task 2: ageCutMinAge параметризация (HIGH-3)

**Files:**
- Modify: `client/ws_pool.go:1078` (isAgeCut), `:1032` (const → fallback)
- Test: `client/ws_pool_test.go`

- [ ] **Step 1: Failing test**

```go
func TestIsAgeCut_ConfigurableFloor(t *testing.T) {
	p := &WSPoolTransport{ageCutMinAge: 45 * time.Second}
	if !p.isAgeCut(50_000) { // 50s ≥ 45s floor → age-cut
		t.Fatal("50s with 45s floor should be age-cut")
	}
	if p.isAgeCut(40_000) { // 40s < 45s → genuine early failure
		t.Fatal("40s with 45s floor should NOT be age-cut")
	}
	// fallback: zero floor → 60s default const
	p0 := &WSPoolTransport{}
	if p0.isAgeCut(50_000) {
		t.Fatal("50s with default 60s floor should NOT be age-cut")
	}
}
```

- [ ] **Step 2: Run — expect FAIL (isAgeCut не метод или не читает поле)**

Run: `cd shadowlink && go test ./client/ -run TestIsAgeCut_ConfigurableFloor -v`
Expected: FAIL

- [ ] **Step 3: Найти текущую isAgeCut (~1051-1079) и переписать как метод**

Текущая (пакетная) `func isAgeCut(slotAgeMs int64) bool { return slotAgeMs >= ageCutMinAgeMs }`.
Заменить на метод с fallback:

```go
func (p *WSPoolTransport) isAgeCut(slotAgeMs int64) bool {
	floorMs := int64(ageCutMinAgeMs)
	if p.ageCutMinAge > 0 {
		floorMs = p.ageCutMinAge.Milliseconds()
	}
	return slotAgeMs >= floorMs
}
```

- [ ] **Step 4: Обновить все вызовы isAgeCut → p.isAgeCut**

Run: `cd shadowlink && grep -n "isAgeCut(" client/ws_pool.go` — заменить каждый callsite на `p.isAgeCut(` (все внутри методов *WSPoolTransport; проверить receiver доступен). Если есть вызов вне транспорта — передать floor.

- [ ] **Step 5: Run — expect PASS**

Run: `cd shadowlink && go test ./client/ -run TestIsAgeCut_ConfigurableFloor -v`
Expected: PASS

- [ ] **Step 6: Run весь client + build**

Run: `cd shadowlink && go build ./... && go test ./client/ -count=1`
Expected: ok

- [ ] **Step 7: Commit**

```bash
git add shadowlink/client/ws_pool.go shadowlink/client/ws_pool_test.go
git commit -m "fix(shadowlink): make ageCutMinAge configurable (lockstep with MaxSlotAge)"
```

---

## Task 3: Env-флаги + понижение дефолтов (клиент)

**Files:**
- Modify: `cmd/nixavpn-client/engine_shadowlink.go:386` (maxSlotAge), `:433` (drainHardCap), `:472+` (новые env), `:484+` (WSPoolConfig)
- Modify: `client/migrate_watchdog.go:52` (migrationThresholdBase default 60s→45s)

- [ ] **Step 1: Понизить maxSlotAge дефолт (engine_shadowlink.go:386)**

Было: `maxSlotAge = 2 * time.Minute`
Стало: `maxSlotAge = 75 * time.Second` (комментарий: TSPU freeze window ~130s, see 2026-06-05 spec).
Сделать env-tunable рядом — если уже не через env, обернуть: `maxSlotAge := envDurationDefault("SHADOWLINK_MAX_SLOT_AGE", 75*time.Second)` (проверить, что переменная не переопределяется ниже; маршрут direct).

- [ ] **Step 2: Понизить drainHardCap дефолт (engine_shadowlink.go:433)**

Было: `drainHardCap := envDurationDefault("SHADOWLINK_DRAIN_HARD_CAP", 90*time.Second)`
Стало: `drainHardCap := envDurationDefault("SHADOWLINK_DRAIN_HARD_CAP", 30*time.Second)`

- [ ] **Step 3: Добавить новые env (после keepaliveInterval ~472)**

```go
	// TSPU age-window tuning (2026-06-05): rotate slots BEFORE the ~130s
	// middlebox freeze window. staggerOffsetCap keeps high-idx uniform-cells
	// (idx up to 2*Size-1) under the window. Field-tunable without rebuild.
	staggerStep := envDurationDefault("SHADOWLINK_STAGGER_STEP", 6*time.Second)
	staggerOffsetCap := envDurationDefault("SHADOWLINK_STAGGER_OFFSET_CAP", 45*time.Second)
	ageCutMinAge := envDurationDefault("SHADOWLINK_AGE_CUT_MIN_AGE", 45*time.Second)
```

- [ ] **Step 4: Прокинуть в WSPoolConfig (после KeepaliveInterval ~487)**

```go
		KeepaliveInterval:   keepaliveInterval,
		StaggerStep:         staggerStep,
		StaggerOffsetCap:    staggerOffsetCap,
		AgeCutMinAge:        ageCutMinAge,
```

- [ ] **Step 5: migrationThresholdBase default 60s→45s (migrate_watchdog.go:52)**

Прочитать функцию `migrationThresholdBase()` — она читает env `SHADOWLINK_MIGRATE_THRESHOLD` с default 60s. Поменять default на `45 * time.Second`. Обновить тест migrate_watchdog_test.go:74 (`want 60s` default → `want 45s`).

- [ ] **Step 6: Build + vet**

Run: `cd shadowlink && go build ./... && go vet ./client/ ./cmd/...`
Expected: OK

- [ ] **Step 7: Run client tests (migrate threshold default change)**

Run: `cd shadowlink && go test ./client/ -run "Migrat|Threshold" -count=1 -v`
Expected: PASS (после обновления теста в Step 5)

- [ ] **Step 8: Commit**

```bash
git add shadowlink/cmd/nixavpn-client/engine_shadowlink.go shadowlink/client/migrate_watchdog.go shadowlink/client/migrate_watchdog_test.go
git commit -m "feat(shadowlink): lower slot age-window defaults under TSPU freeze (75s/6s/cap45s/drain30s/migrate45s)"
```

---

## Task 4: Server rate-limit в генератор config.yaml (BLOCKER-2 + MEDIUM-3)

**Files:**
- Modify: `internal/deploy/steps_shadowlink.go:34` (ShadowLinkYAMLParams), `:60` (renderShadowLinkYAMLContent)
- Test: `internal/deploy/steps_shadowlink_test.go`

- [ ] **Step 1: Failing test — генератор пишет rate_limit блок**

```go
func TestRenderShadowLinkYAML_RateLimitBlock(t *testing.T) {
	out := renderShadowLinkYAMLContent(ShadowLinkYAMLParams{
		Listen: "127.0.0.1:10443", ServerKeyPath: "/k", DecoyDir: "/d", MaxClients: 500, MgmtKey: "ab",
	})
	for _, want := range []string{
		"rate_limit:",
		"  ws_upgrade:",
		"    burst: 90",
		"    refill_per_min: 120",
		"  handshake:",
		"    burst: 80",
		"    refill_per_min: 300",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("YAML missing %q\n---\n%s", want, out)
		}
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `cd /d/NIXAVPN && go test ./internal/deploy/ -run TestRenderShadowLinkYAML_RateLimitBlock -v`
Expected: FAIL (нет блока rate_limit)

- [ ] **Step 3: Добавить поля в ShadowLinkYAMLParams (после DomainDecoyMap ~51)**

```go
	// Rate-limit buckets (2026-06-05 TSPU age-tuning): faster slot rotation
	// raises per-IP WS upgrade / handshake frequency. Defaults written ALWAYS
	// (non-zero) so deploys don't fall back to the server's 18/30 default and
	// hit HTTP 429 under the accelerated reconnect cadence. 0 → use the constant
	// defaults below.
	WSUpgradeBurst        int
	WSUpgradeRefillPerMin int
	HandshakeBurst        int
	HandshakeRefillPerMin int
```

- [ ] **Step 4: Рендерить блок rate_limit (в renderShadowLinkYAMLContent, ПОСЛЕ management, ПЕРЕД domain_decoy_map ~78)**

```go
	// Rate-limit block — always emitted with non-zero values (zero → defaults)
	// so deploys never fall back to the server-side 18/30 that triggers 429
	// under the 2026-06-05 accelerated slot rotation.
	wsB, wsR := cfg.WSUpgradeBurst, cfg.WSUpgradeRefillPerMin
	if wsB <= 0 { wsB = 90 }
	if wsR <= 0 { wsR = 120 }
	hsB, hsR := cfg.HandshakeBurst, cfg.HandshakeRefillPerMin
	if hsB <= 0 { hsB = 80 }
	if hsR <= 0 { hsR = 300 }
	sb.WriteString("\nrate_limit:\n")
	sb.WriteString("  ws_upgrade:\n")
	fmt.Fprintf(&sb, "    burst: %d\n", wsB)
	fmt.Fprintf(&sb, "    refill_per_min: %d\n", wsR)
	sb.WriteString("  handshake:\n")
	fmt.Fprintf(&sb, "    burst: %d\n", hsB)
	fmt.Fprintf(&sb, "    refill_per_min: %d\n", hsR)
```

- [ ] **Step 5: Run — expect PASS**

Run: `cd /d/NIXAVPN && go test ./internal/deploy/ -run TestRenderShadowLinkYAML_RateLimitBlock -v`
Expected: PASS

- [ ] **Step 6: Проверить, что существующие снапшот-тесты генератора обновлены**

Run: `cd /d/NIXAVPN && go test ./internal/deploy/ -count=1`
Expected: ok (если есть golden-снапшот renderShadowLinkYAMLContent — обновить ожидаемый YAML, добавив rate_limit блок).

- [ ] **Step 7: Commit**

```bash
git add internal/deploy/steps_shadowlink.go internal/deploy/steps_shadowlink_test.go
git commit -m "feat(deploy): emit rate_limit block in shadowlink config.yaml (ws 90/120, hs 80/300)"
```

---

## Task 5: Регресс + race + сборка

**Files:** все затронутые

- [ ] **Step 1: Полный тест shadowlink (клиент + смежное)**

Run: `cd shadowlink && go test ./client/ ./proxy/socks5/ ./core/ -count=1`
Expected: ok (half-open A+B, Bug#6/#8/#9/#10 не сломаны)

- [ ] **Step 2: Полный тест main tree (генератор)**

Run: `cd /d/NIXAVPN && go test ./internal/deploy/ -count=1`
Expected: ok

- [ ] **Step 3: Race на Linux/pl1 (watchdog + migrate goroutines)**

Run (на Linux/CI с gcc; Windows без gcc пропускает -race): `cd shadowlink && go test -race -count=3 ./client/`
Expected: 0 DATA RACE. (Если Windows-хост без gcc — отметить, что race гоняется юзером на pl1/Linux.)

- [ ] **Step 4: Собрать клиентский бинарь**

```bash
cd shadowlink && go build -o /d/NIXAVPN/bin/nixavpn-client-graceful-drain.exe ./cmd/nixavpn-client/
```
Expected: OK, mtime обновлён.

- [ ] **Step 5: Commit (если остались незакоммиченные правки тестов)**

```bash
git add -A shadowlink/ internal/
git commit -m "test(shadowlink): age-window tuning regression + race green"
```

---

## Deploy (юзер, СВЯЗКА — MEDIUM-3)

Клиент-тюнинг и серверный config.yaml катятся ВМЕСТЕ:
1. Передеплоить config.yaml на pl1 с блоком rate_limit (через деплой-оркестратор ИЛИ временно вручную: добавить блок + `systemctl reload shadowlink`).
2. Запустить новый клиент (бинарь из Task 5 Step 4) через `connect-vpn-DEBUG.bat`.
3. Канарейка: смотреть метрики из спеки §Канарейка — особенно `DrainForceEvictedActiveTotal` (должен ≈0), HTTP 429 (должен исчезнуть), age-cut на слотах >130с (должны исчезнуть).
4. **Приёмка: Claude Code auto-update через туннель проходит.**

---

## Self-Review (проверка плана против спеки)

- ✅ BLOCKER-1 (cap staggerOffset idx 0..15) → Task 1.
- ✅ BLOCKER-2 + MEDIUM-3 (rate-limit 90/120 + 80/300, всегда non-zero, связка деплоя) → Task 4 + Deploy.
- ✅ HIGH-1 (формула с cap, не только const) → Task 1 Step 6.
- ✅ HIGH-2 (staggerStep+cap в env) → Task 3 Step 3.
- ✅ HIGH-3 (ageCutMinAge 45s) → Task 2 + Task 3.
- ✅ MEDIUM-1 (migrationThreshold 45s) → Task 3 Step 5.
- ✅ MEDIUM-2 (DrainHardCap 30s) → Task 3 Step 2.
- ✅ MEDIUM-4 (канарейка force-evict-active) → Deploy Step 3.
- ✅ NIT-3 (переписать тесты на capped-формулу) → Task 1 Step 9.
- Типы согласованы: `slotStaggerOffset`/`isAgeCut` — методы `*WSPoolTransport`; поля `staggerStep`/`staggerOffsetCap`/`ageCutMinAge` едины во всех тасках; WSPoolConfig поля `StaggerStep`/`StaggerOffsetCap`/`AgeCutMinAge`.
