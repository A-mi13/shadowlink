package client

import (
	"time"
)

const (
	drainPollInterval  = 500 * time.Millisecond
	drainRevertBackoff = 30 * time.Second
)

// findFreeReserveSlot returns the first nil cell in reserve range
// [poolSize, 2*poolSize), or -1 if all reserve cells are occupied.
// Lock-free read of the slice; reserve cells are written exclusively
// by startDrain/connectReserveSlot under the implicit serialization
// that only one drain can start per primary idx (tryMarkDraining CAS).
func (p *WSPoolTransport) findFreeReserveSlot() int {
	for i := p.poolSize; i < len(p.slots); i++ {
		if p.slots[i] == nil {
			return i
		}
	}
	return -1
}

// startDrain transitions p.slots[oldIdx] from slotReady to slotDraining
// and spawns parallel connect-reserve + drain-watchdog goroutines.
//
// Sequence of checks (order matters):
//  1. Feature flag off → no-op.
//  2. oldIdx out of primary range → no-op.
//  3. oldSlot nil → no-op.
//  4. Storm brake (countNonReadySlots >= threshold) → set backoff,
//     no-op. This check runs BEFORE tryMarkDraining so the slot we're
//     about to transition doesn't inflate the non-ready count itself.
//  5. tryMarkDraining CAS → false on race loss (another drain or natural
//     failure beat us); no-op.
//  6. findFreeReserveSlot → -1 means all reserve cells occupied; revert
//     state + set backoff.
//  7. Success: spawn connectReserveSlot + drainWatchdog goroutines.
//
// Reason: "age", "byte_budget", or "anti_fingerprint". Propagated to
// logs and (via handleSlotDeath cause) to the meltdown-counter
// machinery.
func (p *WSPoolTransport) startDrain(cl *Client, oldIdx int, reason string) {
	if !p.gracefulDrain {
		return
	}
	if oldIdx < 0 || oldIdx >= p.poolSize {
		return
	}
	oldSlot := p.slots[oldIdx]
	if oldSlot == nil {
		return
	}

	// Storm brake check BEFORE tryMarkDraining — see func doc comment.
	nonReady := p.countNonReadySlots()
	threshold := p.rotationStormBrakeThreshold()
	if nonReady >= threshold {
		p.log.Info("WS pool slot drain deferred (storm brake)",
			"slot", oldIdx, "reason", reason,
			"non_ready_slots", nonReady, "brake_threshold", threshold)
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainRevertBackoff).UnixNano())
		return
	}

	if !oldSlot.tryMarkDraining() {
		return
	}

	newIdx := p.findFreeReserveSlot()
	if newIdx < 0 {
		p.log.Warn("WS pool drain skipped — no free reserve cell",
			"slot", oldIdx, "reason", reason)
		// Revert state + set backoff. If CAS fails, slot was concurrently
		// transitioned (e.g. handleSlotDeath raced us in) — log for
		// visibility, then bail.
		if !oldSlot.state.CompareAndSwap(int32(slotDraining), int32(slotReady)) {
			p.log.Debug("WS pool revert CAS failed — slot died concurrently",
				"slot", oldIdx)
		}
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainRevertBackoff).UnixNano())
		return
	}

	Stats.DrainStartedTotal.Add(1)
	drainStart := time.Now()
	activeAtStart := oldSlot.streams.Load()

	p.log.Info("WS pool slot drain started",
		"slot", oldIdx,
		"reserve_slot", newIdx,
		"reason", reason,
		"active_streams", activeAtStart,
		"hard_cap", p.drainHardCap,
	)

	// Claim the reserve cell IMMEDIATELY (before goroutine spawn) so a
	// concurrent startDrain on another primary slot cannot pick the
	// same newIdx via findFreeReserveSlot. connectSlot will overwrite
	// this placeholder with its own freshly-constructed *poolSlot.
	p.slots[newIdx] = &poolSlot{}
	p.slots[newIdx].setState(slotConnecting)

	go p.connectReserveSlot(cl, newIdx, oldIdx)
	go p.drainWatchdog(cl, oldIdx, oldSlot, drainStart, reason)
}

// connectReserveSlot runs the standard connect path at newIdx. On
// success, AssignStream picks it up via its slotReady filter. On
// failure, schedules reconnectLoop at newIdx so capacity recovers
// asynchronously; the drainWatchdog tears down oldIdx on its own
// schedule regardless.
//
// Note: the reserve cell at newIdx has already been claimed with a
// placeholder *poolSlot in slotConnecting state by startDrain (under
// the synchronous portion of the call) — connectSlot will overwrite
// that placeholder with its own freshly-constructed slot.
func (p *WSPoolTransport) connectReserveSlot(cl *Client, newIdx, oldIdx int) {
	if newIdx < 0 || newIdx >= len(p.slots) {
		return
	}

	if err := p.connectSlot(p.ctx, newIdx); err != nil {
		p.log.Warn("WS pool reserve slot connect failed",
			"slot", newIdx, "for_drain_of", oldIdx, "err", err)
		go p.reconnectLoop(newIdx)
		return
	}
	go p.slotReader(newIdx)
}

// drainWatchdog polls oldSlot.streams every drainPollInterval until
// either count reaches 0 (natural finish) or drainHardCap elapses
// (hard cap). In both cases:
//   - Bumps oldSlot.generation BEFORE handleSlotDeath so any concurrent
//     slotReader exits silently via shouldExitReader (no false
//     ReaderExits++ or frame-anomaly counter inflation).
//   - Calls handleSlotDeath with deathCauseDrainTeardown so the slot
//     is torn down without advancing the meltdown counter and the
//     cell is freed for reserve reuse.
func (p *WSPoolTransport) drainWatchdog(cl *Client, oldIdx int, oldSlot *poolSlot,
	drainStart time.Time, reason string) {

	ticker := time.NewTicker(drainPollInterval)
	defer ticker.Stop()
	deadline := time.NewTimer(p.drainHardCap)
	defer deadline.Stop()

	tearDown := func(hardCap bool) {
		duration := time.Since(drainStart)
		if hardCap {
			Stats.DrainHardCapTotal.Add(1)
			p.log.Warn("WS pool slot drain hard cap reached",
				"slot", oldIdx, "reason", reason,
				"remaining_streams", oldSlot.streams.Load(),
				"drain_duration", duration.Truncate(time.Second))
		} else {
			Stats.DrainNaturalFinishTotal.Add(1)
			p.log.Info("WS pool slot drain natural finish",
				"slot", oldIdx, "reason", reason,
				"drain_duration", duration.Truncate(time.Second))
		}
		Stats.DrainDurationSeconds.Observe(duration.Seconds())

		oldSlot.generation.Add(1)
		p.handleSlotDeath(cl, oldIdx, deathCauseDrainTeardown)
	}

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-deadline.C:
			tearDown(true)
			return
		case <-ticker.C:
			if oldSlot.streams.Load() == 0 {
				tearDown(false)
				return
			}
		}
	}
}
