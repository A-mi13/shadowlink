# Design A — Front-Loaded Mimicry Against Unidirectional First-N-Packet Allowlists

*Design section for the censorship-circumvention whitepaper. Verified ground truth (June 2026) is cited inline; every assumption that may not hold is flagged explicitly.*

---

## A.1 Motivation and the gap being addressed

Allowlist (default-drop) censorship inverts the economics of evasion. Against a
**blocklist** censor a tunnel survives by *not matching* any prohibited
signature; the censor must enumerate what is bad. Against an **allowlist**
censor a tunnel survives only by *affirmatively matching* a permitted
signature; the censor enumerates what is good and silently drops the residual.
Generic obfuscation — randomized/high-entropy transports (obfs4, Shadowsocks)
or naive HTTPS-wrapping (meek, and crucially the user's own ShadowLink
analytics-mimicry) — is engineered for the blocklist world: it makes traffic
look like *nothing in particular*. Under an allowlist, "nothing in particular"
is exactly the residual class that gets dropped. This is an established,
adversarially-confirmed result: **no research supports the claim that generic
HTTPS-wrapping defeats a true allowlist** (the contrary is a refuted
hallucination). ShadowLink's HTTP-over-analytics persona is therefore
*insufficient by construction* against the allowlist threat, regardless of how
well its statistical distributions are calibrated — its body is encrypted and
ML-resistant, but its *opening* is a generic TLS-to-an-arbitrary-CDN-domain,
which is precisely what an SNI/protocol allowlist gates on.

The specific structural weakness of the deployed allowlist gives a narrow
opening. Per **Alaraj & Wustrow, "Proxies as Sensors," ACM AsiaCCS 2025** and
**arXiv:2507.14183**, Iran's per-AS protocol allowlist inspects only the **first
~4 packets client→server, unidirectionally**, matching them against a
permitted-protocol signature (a real TLS ClientHello shape, an SSH signature,
etc.); flows whose opening does not match are silently dropped (OpenVPN
UDP/1194, SSH/22, generic TCP/UDP all fall through). Russia's TSPU
SNI-allowlist (the ~720-domain mobile-network whitelist observed during regional
drills, late 2025 — **not yet permanent fixed-line**; Tor blog 2025) is a
related but distinct gate: it keys on cleartext SNI inside a real TLS
ClientHello rather than on a protocol fingerprint per se.

**Idea A — "front-loaded mimicry"** exploits the *temporal boundedness and
unidirectionality* of the check. If the connection's first N packets are a
byte-exact, behaviorally-exact instance of a permitted client, the gate passes;
the covert tunnel then "grows" *after* the inspection window inside the
already-admitted flow. The design question this section answers rigorously is
not "can we mimic a ClientHello" (uTLS already does that) but: **does
front-loading — being perfect only for the inspection window rather than for the
whole session — convert mimicry from an unsound parrot into a sound gate-pass?**

---

## A.2 Threat model

### A.2.1 Censor capabilities (assumed present)

- **C1 — First-N-packet protocol classification, client→server.** On each new
  5-tuple flow the censor buffers and inspects the first N packets sent
  *client→server* (N ≈ 4, per the cited measurement) and matches them against a
  per-AS allowlist of permitted-protocol signatures. Match → flow admitted and
  (we assume) no longer inspected by *this* classifier. No match → silent drop.
- **C2 — SNI / outer-identity allowlisting (RU TSPU variant).** Inside an
  admitted TLS ClientHello the censor reads cleartext SNI and admits only
  allowlisted domains. ECH outer-SNI is itself a droppable signal where
  TSPU-scoped (Nov 2024 Cloudflare-IP ECH block, dropping the ClientHello when
  outer SNI = `cloudflare-ech.com` AND dest = Cloudflare IP).
- **C3 — Active probing.** The censor may connect to the server endpoint and
  replay/forge opening packets to test whether the endpoint *responds like the
  protocol it claims*. This is the canonical mimicry-killer ("The Parrot is
  Dead," Houmansadr et al. 2013): a parrot that mimics requests but cannot
  sustain the protocol's *responses and state machine* fails the probe.
- **C4 — Replay.** The censor may capture a client's opening packets and replay
  them (same or different server) to detect static/replayable gate-passes.
- **C5 — Decentralization.** Different ASes apply different mechanisms (packet
  injection, IP blocking, mid-connection dropping, protocol allowlisting)
  heterogeneously. A design must not assume one national model.
- **C6 — Post-admission statistical / volumetric analysis (assumed *latent*,
  see A.2.3).** The censor *can* in principle run flow-level ML on admitted
  flows (RU 2026 ML-DPI budget is real). We do **not** assume the
  first-N-packet classifier itself does this, but a serious design must survive
  a censor that later bolts post-admission analytics onto the gate.

### A.2.2 Censor limitations the design *relies on* (each is an assumption to test)

- **L1 — Inspection window is bounded at ~N packets (ASSUMPTION, HIGH RISK).**
  The entire premise. If the censor extends N to cover the whole handshake plus
  early application data, front-loading degenerates into full-session mimicry
  and the parrot critique (C3) reapplies. **This is the load-bearing assumption
  and it is an empirical, time-varying property of one specific adversary, not a
  law.** N is cheap for the censor to increase; the inspection budget is a
  policy knob, not a hard constraint.
- **L2 — Inspection is unidirectional, client→server only (ASSUMPTION, HIGH
  RISK).** The cited work reports the Iranian allowlist inspects *client→server*
  packets only. If true, the *server's* responses are not checked against the
  mimicked protocol — which is what makes a server that does not actually speak
  the mimicked protocol survivable, and is the *only* property that
  distinguishes this from a parrot. If the censor inspects server→client too, or
  runs C3 active probing, this collapses (A.4.2).
- **L3 — No real-time cross-flow correlation at admission.** We assume the gate
  decides per-flow without correlating opening bytes against a global
  rate/replay model in real time. Offline replay (C4) remains in scope.
- **L4 — Cleartext-SNI allowlist, not full-handshake validation (RU).** For the
  TSPU SNI variant we assume admission keys on the SNI *value*, not on the gate
  itself completing a real TLS session to the named host.

### A.2.3 Out of scope / explicitly conceded

- **Endpoint reachability.** Front-loaded mimicry does **nothing** to hide
  *where* the flow goes. If the destination IP is itself not allowlisted (and
  the RU SNI-allowlist plausibly admits by SNI *and* destination IP class), a
  byte-perfect ClientHello to a non-allowlisted IP is still dropped. This is the
  design's single biggest structural limitation (A.6).
- **Long-horizon post-admission ML (C6).** We *mitigate* but cannot *defeat*
  this within Idea A alone; it is the security boundary, not a solved problem.

---

## A.3 Mechanism and protocol design

### A.3.1 Core idea, stated precisely

Split the connection lifecycle into two regimes separated by the **inspection
horizon** H (the censor's window, ≈ first N client→server packets):

1. **Gate-pass regime (packets 1..N).** The client emits an opening that is a
   *byte-exact, timing-plausible* instance of a permitted client's protocol
   prologue — for RU, a TLS 1.3 ClientHello carrying an **allowlisted SNI** and
   a fingerprint indistinguishable from a real whitelisted app/browser; for the
   Iranian protocol-allowlist, a ClientHello matching the permitted-protocol
   signature. These bytes must withstand byte-level comparison against a
   reference capture of the *specific* permitted client.
2. **Growth regime (packets > N).** Once past H, the flow no longer has to
   *continue* being the mimicked protocol in a way the gate verifies — only in a
   way that survives the residual adversary (C6 post-admission ML and any
   server→client check that *does* exist). The covert tunnel's real key exchange
   and data transport run here, carried inside the structure the gate accepted.

The novelty-relevant claim (tested in A.4, not asserted here): front-loading is
*sound* rather than a parrot **iff L1 ∧ L2 hold**, because then the gate never
observes the part of the session where mimicry would fail (the server's protocol
responses, the long-horizon statistics). Front-loading is *strictly weaker* than
full-session mimicry in mimic fidelity but *strictly stronger* in that it does
not have to solve the unsolvable problem (perfectly impersonating a full
protocol stack including server behavior). It is **not** novel as "mimicry"; its
only defensible contribution is exploiting the *measured* shape of *this* gate.
If the gate's shape is mis-measured, there is no contribution.

### A.3.2 Choice of mimicked protocol and carrier

Two viable carriers, depending on the gate variant.

**(a) TLS-1.3-real carrier (recommended for RU SNI-allowlist).** The opening is
a *real* TLS 1.3 handshake to a *real, allowlisted* fronting host that the
censor admits. The client completes a genuine TLS session, so the server→client
bytes are genuine TLS — this is robust to bidirectional inspection *of the
handshake* (because the handshake is not mimicked, it is real) and to active
probing of the handshake. The covert channel lives in TLS *application data*
after the handshake. The catch: the named host must actually terminate the TLS,
which reintroduces domain fronting (SNI≠Host is dead since 2018;
Google/AWS/CF disabled server-side domain mismatch). So either (i) the
allowlisted host *is* our cooperating endpoint — it must be genuinely
allowlisted, which is rare and fragile — or (ii) we ride a refraction /
decoy-routing primitive (Conjure/TapDance/REDACT, out of Idea A's scope; see
the refraction design section). **Honest consequence: pure front-loaded mimicry
with a real-TLS carrier reduces, for RU, to "have an allowlisted endpoint,"
which is the hard part this idea does not solve.**

**(b) Synthetic-prologue carrier (only viable under strict L1 ∧ L2).** The
client emits N synthetic packets that are byte-exact to a permitted client's
*request* prologue (e.g. a captured ClientHello), but the server does **not**
implement the mimicked protocol's response state machine. After H both sides
switch to the covert protocol mid-flow. This variant is the only one where
"front-loading" is doing real work distinct from refraction — and it lives or
dies entirely on L2 (server responses unchecked) and C3 (no active probing). If
the censor ever probes the endpoint or inspects the downstream, the absence of a
real protocol response (a real ServerHello, a real SSH banner) is an immediate
tell. **This variant is honestly a parrot with a shorter neck; its only defense
is that the cited adversary does not currently look at the neck.**

### A.3.3 Detailed protocol — synthetic-prologue variant (the interesting case)

Notation: client C, server S, censor X. `||` is concatenation. KDF is HKDF-
SHA256. AEAD is AES-256-GCM (reusing ShadowLink's `core/` crypto).

**Pre-shared material (out-of-band, before any gated flow):**
- S's long-term X25519 static public key `S_pub` (ShadowLink already ships
  this — `-server-key` / handshake auth). Distributed to C via the existing
  signed config channel.
- A **mimic template** `T`: a byte-exact capture of the first N client→server
  packets of a *specific, currently-allowlisted* permitted client, plus its
  inter-packet timing distribution. For RU this is most cheaply a real
  ClientHello to an allowlisted SNI (see A.6 feasibility). `T` is versioned and
  rotated as the reference client updates.

**Phase 0 — Gate pass (packets 1..N, client→server, observed by X):**
1. C selects template `T` and an allowlisted SNI value `sni*` from a pool.
2. C constructs a TLS 1.3 ClientHello byte-identical to `T` except for fields
   that MUST vary per-connection in the real client too (random, key_share,
   session_id) — these are filled with values that are *individually*
   well-formed and *jointly* indistinguishable from the real client's
   distribution. Critically, **the covert key material is smuggled in exactly
   the field the real client also randomizes** — the 32-byte ClientHello
   `random` and/or the X25519 `key_share` — as `EphC_pub` (C's ephemeral
   X25519). This is the one place a covert payload can hide without altering the
   byte-distribution the gate matches, because the gate cannot distinguish a
   random nonce from an ephemeral pubkey (both are 32 uniform bytes). uTLS makes
   this field-level control available.
3. C sends the ClientHello (packet 1) and, if the template includes them, the N
   subsequent client→server records with matching sizes/timing (TLS does not
   normally send more client→server before ServerHello, so for TLS N is
   effectively 1 substantive packet plus TCP handshake — *this is itself a risk:
   if N=4 the censor may be counting TCP SYN + ClientHello segments, and a
   single-segment ClientHello may look different from a fragmented real one*).
4. **Gate decision happens here.** Under L1∧L2, X admits the flow on the basis
   of the ClientHello shape + (RU) the allowlisted SNI, and stops inspecting.

**Phase 1 — Covert key agreement (packets > N, post-horizon):**
5. S, which has been receiving these "ClientHellos," extracts `EphC_pub` from
   the agreed covert field. S does **not** send a real ServerHello (synthetic-
   prologue variant). Instead S derives `ss = X25519(S_static_priv, EphC_pub)`
   and a fresh ephemeral `EphS`, sends `EphS_pub` back disguised as
   server→client TLS application-data records (which the gate, under L2, never
   inspects), and both derive `K = HKDF(ss || X25519(EphC_priv, EphS_pub))`.
   This is a standard authenticated X25519 handshake (server authenticated by
   `S_static`; client optionally authenticated by ShadowLink's existing
   `authorized_clients` whitelist in the first covert frame).
6. From packet > N onward all traffic is AES-256-GCM under `K`, framed to *look
   like* TLS 1.3 application-data records (correct record header, plausible
   length distribution) — i.e. ShadowLink's existing record-shaping applies
   here, now in the *growth* regime where it is sufficient (it need only beat
   C6, not the gate).

**Phase 2 — Growth / data transport:** the covert tunnel multiplexes streams
(ShadowLink's WS-pool / yamux-style mux) inside the application-data frames.

**Key exchange soundness.** The handshake is a real authenticated DH; there is
no novel cryptography. The only subtlety is *channel*: covert bits ride in
fields the real protocol also fills with high-entropy bytes (ClientHello random
/ key_share, TLS app-data). This is sound *as a steganographic channel* exactly
when those fields are indistinguishable from random to X — true for the random
nonce and for X25519 public keys (uniform over the curve's encoding for X25519).
It is **not** sound if X validates that `key_share` corresponds to a key the
real reference client would have generated *and the real client's keygen is
non-uniform* (it is not, for X25519 — safe). It breaks if X requires the flow to
complete a *real* TLS handshake to the allowlisted host (then we are forced into
carrier (a) and the endpoint problem).

### A.3.4 Server-side participation

The server must (i) accept TCP connections that open with a ClientHello it will
*not* answer with a real ServerHello, (ii) demux covert key material from the
ClientHello field, (iii) for any connection that turns out to be a real client
or an active probe, **fail closed to a real decoy** — i.e. actually complete a
real TLS handshake and serve the decoy site (ShadowLink's existing
`failClosedToDecoy` + decoy server). This dual behavior is essential for active-
probing resistance (A.4.1): the server must be a real allowlisted-protocol
speaker to anyone who does not present valid covert material, and only diverge
for authenticated covert clients *after* the horizon. Note the tension: in the
synthetic-prologue variant the server **cannot** both (a) skip sending a real
ServerHello to covert clients and (b) send a real ServerHello to probes, unless
it can decide *before responding* whether the peer is covert — which it can,
because covert clients carry authenticated material in the ClientHello and
probes/replays do not. So the rule is: **respond with a real TLS ServerHello +
decoy by default; only switch to covert mode for a ClientHello whose covert
field decrypts/authenticates.** This makes carrier (b) actually *converge toward*
carrier (a): the safe server always speaks real TLS, which means the server→
client side is genuine even though we relied on L2 to not need it. That is a
feature — it removes the dependence on L2 for the *handshake* while keeping the
gate-pass cheap.

---

## A.4 Security analysis

### A.4.1 Active probing resistance (C3)

If the server **always completes a real TLS handshake** and serves a real decoy
to any peer lacking valid covert material (A.3.4), active probing sees a normal
allowlisted host: real ServerHello, real cert chain, real decoy content. The
covert divergence is gated on authenticated material the probe cannot forge
(it does not know `S_pub`'s matching private operations, and the covert field is
AEAD-bound to a key only legitimate clients derive). **This is the
TapDance/Conjure pattern applied at the endpoint** and is the strongest part of
the design. The synthetic-prologue "don't answer with a real ServerHello"
variant (A.3.3) is *abandoned* here in favor of always-real-TLS precisely
because it fails C3. **Conclusion: probing resistance requires the real-TLS
carrier; the pure synthetic-prologue variant does not survive an active prober
and should be treated as insecure against C3.**

### A.4.2 What if the censor extends N or inspects bidirectionally (L1/L2 fail)

- **N extended past the handshake into early app-data:** with the real-TLS
  carrier the handshake is genuine, so extending N over the handshake changes
  nothing; the covert data only appears in application-data records, which are
  AEAD ciphertext indistinguishable from real TLS app-data. The censor would
  have to do *content* analysis of encrypted app-data — i.e. C6, not C1. **The
  real-TLS carrier is robust to L1 failure for the handshake.** What it is *not*
  robust to: the censor requiring that the app-data correspond to a *plausible
  decoy interaction* (e.g. expecting an HTTP/2 exchange consistent with the
  named host). This pushes us toward making the growth regime mimic a real
  session with the decoy — expensive, and the open frontier.
- **Bidirectional inspection (L2 fails):** again, real-TLS carrier is fine for
  the handshake (server bytes are real TLS). Synthetic-prologue carrier dies
  immediately.

**Net:** the design's robustness to the two scariest assumptions (L1, L2)
failing comes *entirely* from using a real TLS handshake, which in turn requires
a genuinely-allowlisted endpoint or a refraction primitive. The "front-loading"
framing is therefore most honestly described as: **make the gate-pass cheap (one
real ClientHello to an allowlisted identity) and defer all covert behavior to
AEAD application-data** — which is *not materially different from what a
well-built domain-fronting or refraction client already does*. The distinct
contribution shrinks to near-zero once C3 forces real TLS.

### A.4.3 Replay resistance (C4)

The ClientHello carries per-connection ephemeral material (`EphC_pub` in
random/key_share). A replayed ClientHello presents an `EphC_pub` for which the
attacker does not hold `EphC_priv`; the server completes a real TLS handshake
(replays are just normal-looking clients) and serves the decoy — the replay
learns nothing and cannot derive `K`. Covert clients must also bind the first
covert frame to a server-provided freshness value (the real ServerHello random,
which is fresh per connection) to prevent a captured *full* exchange from being
replayed to extract data. **Replay resistance is adequate provided the covert
frame is bound to the server's fresh handshake nonce.** A pure synthetic-
prologue server (no real ServerHello, no fresh server nonce visible pre-covert)
is weaker — another reason to prefer real-TLS.

### A.4.4 Statistical detectability of post-window traffic (C6)

This is the residual, unsolved adversary. Once admitted, the flow's volume,
timing, burst structure, and duration are observable. ShadowLink's existing
Phase-2/Phase-3 work (log-normal session lifetimes, jittered keepalives, Pareto
`next_poll`, decoupled padding distributions, ACK jitter) is exactly the right
toolkit for this regime and is *complementary* to Idea A — front-loading gets
through the gate, the mimicry engine survives post-admission ML. **But:** the
honest weakness is that a real allowlisted host (say a banking app) has a
*specific, learnable* post-handshake behavior, and our growth-regime traffic
must match *that host's* behavior, not generic-analytics behavior. Matching the
gate's identity in the handshake but not in the body is a **cluster signal**
(cf. the project's own "decoy must match baseline stack" finding): SNI says
"BankApp," payload statistics say "bulk tunnel." This mismatch is detectable by
exactly the ML the RU 2026 budget funds. Mitigation requires the growth regime
to mimic *the specific allowlisted application's* traffic profile, which is far
harder than mimicking generic analytics.

### A.4.5 Per-AS heterogeneity (C5)

Because admission is per-AS and heterogeneous, a single template/SNI pool will
pass some ASes and be dropped/injected-against by others. The design must
maintain *per-AS* templates and detect-and-fail-over (ShadowLink's nascent DPI-
detection direction). This is operational complexity, not a security hole, but
it materially raises the maintenance burden (A.5/A.6).

---

## A.5 Honest failure modes (when this breaks)

1. **No allowlisted endpoint (the dominant failure).** If neither a genuinely
   allowlisted host terminates our TLS nor a refraction primitive is available,
   a perfect ClientHello to a non-allowlisted destination IP is dropped by any
   gate that checks destination (RU SNI-allowlist plausibly does). Front-loaded
   mimicry **cannot manufacture an allowlisted destination.** This is the
   single biggest weakness.
2. **C3 active probing with a synthetic-prologue server.** Dies immediately;
   forces real-TLS, which collapses the novelty into refraction/fronting.
3. **L1 extended into app-data + body-consistency check.** If the censor
   requires admitted flows to *behave* like the named protocol/host (not just
   open like it), the growth regime must mimic the specific host — unsolved.
4. **SNI-allowlist + ECH unavailability.** If we try to hide the real
   destination with ECH, RU TSPU directly blocks ECH (Nov 2024); the
   TCP-seg + TLS-record-frag evasion is *fragile and possibly already patched*
   (TSPU has gained reassembly). China/Iran neutralize ECH by censoring
   encrypted DNS so the client cannot fetch the ECH config. So we cannot
   reliably hide which allowlisted-or-not host we name.
5. **Template staleness.** The byte-exact reference client updates (Chrome
   ships a new ClientHello every ~6 weeks; the whitelisted banking app updates).
   A stale template becomes a *minority fingerprint* — itself an anomaly. This
   mirrors the project's existing uTLS-Chrome-133-maintenance burden: the
   fingerprint is deliberately pinned and must chase upstream.
6. **First-N counting mismatch.** If N counts TCP-level segments and the real
   client fragments its ClientHello in a characteristic way (or sends it in one
   segment) and we differ, we mismatch on packetization even with byte-identical
   payload. The template must capture segmentation, not just bytes.
7. **Replay/correlation if covert frame not bound to fresh server nonce.**
   Addressed by binding to ServerHello random, but only available in the
   real-TLS carrier.

---

## A.6 Feasibility for the user's situation (RU mobile allowlist + ShadowLink)

**What the existing stack already provides (genuine assets):**
- **uTLS Chrome-133 ClientHello with MLKEM768 key_share** (`client/
  split_transport_tls.go`, `ws_transport.go`, `skins/browser/fingerprint.go`,
  `LockedChromeMajor = 133`). This is exactly the field-level ClientHello
  control Phase 0 needs — including the ability to place 32 covert bytes in the
  `random`/`key_share` field. The four-surface lockstep (uTLS JA4, bogdanfinn
  H2 SETTINGS, UA, sec-ch-ua) means the gate-pass packet is already a
  high-fidelity browser instance.
- **X25519 + AES-256-GCM handshake and `authorized_clients` auth** (`core/`,
  `server/ratelimit.go`) — directly reusable as the covert key agreement.
- **`failClosedToDecoy` + real decoy server** (`server/handler.go`,
  per-persona decoy templates) — directly reusable as the always-real-TLS,
  probe-resistant default behavior (A.3.4).
- **Post-admission mimicry engine** (Phase 2/3 distributions, jitter) — the
  right tool for the C6 growth-regime problem (A.4.4).

**What is missing / hard for the user:**
- **The allowlisted identity.** ShadowLink today opens TLS to *its own CDN
  domain* (`datacanvases.com` / arbitrary foreign TLD via Cloudflare). Against
  the RU SNI-allowlist that domain is **not on the ~720-domain whitelist**, so
  the gate-pass fails at the SNI check regardless of ClientHello perfection.
  The user has no banking-app SNI to legitimately terminate. Carrier (a)
  therefore is not available without either (i) getting an allowlisted domain
  fronted on a CDN that still permits SNI≠Host (largely dead since 2018), or
  (ii) a refraction/decoy-routing partner on an RU-transit path (the user has
  none — this is the very deployment limitation that dogs Conjure).
- **Mobile-only, drill-only gate.** Critically, the RU allowlist is **mobile-
  network, regional-drill, not-yet-permanent-fixed-line**. So for the user's
  fixed-line РФ users *today*, the allowlist gate is **not active**, and
  ShadowLink's existing analytics-mimicry remains adequate against the
  *blocklist* DPI that is active. Front-loaded mimicry is a *contingency design
  for when/if the mobile drills become permanent and spread to fixed-line* —
  not a present-day necessity.

**Honest verdict for the user.** The parts of Idea A that are *sound* (real-TLS
carrier + probe-resistant decoy + AEAD growth regime) reduce, on the RU
allowlist, to "speak real TLS to a genuinely-allowlisted endpoint." ShadowLink
can supply a perfect ClientHello but **cannot supply an allowlisted
destination**, and that — not the ClientHello — is what the RU gate checks.
Therefore front-loaded mimicry is **not a complete answer** for the user; it is
a useful *component* (the gate-pass mechanics, reusing uTLS + the X25519
handshake + the decoy server) that only becomes a circumvention *system* when
combined with an allowlisted-identity primitive the user does not currently
possess (refraction partner, or a surviving fronting CDN, or membership in the
720-domain set). The synthetic-prologue variant that *would* be novel is the one
that dies to active probing and to any L2 failure, so it cannot be recommended
as the security foundation. The recommendation is: **build the gate-pass +
probe-resistant-decoy mechanics now (cheap, reuses existing code, hardens
against the SNI variant the moment an allowlisted identity becomes available),
but do not represent front-loaded mimicry as defeating the RU allowlist on its
own — it does not solve the destination-allowlisting problem, and naive
HTTPS-mimicry (which is what ShadowLink is today) remains provably insufficient
against a true allowlist.**

---

## A.7 Summary of load-bearing assumptions (for the evaluation section)

| ID | Assumption | Risk | If false |
|----|-----------|------|----------|
| L1 | Inspection window bounded ~N packets | HIGH | Degenerates to full-session mimicry → parrot (C3) |
| L2 | Inspection unidirectional (client→server) | HIGH | Synthetic-prologue dies; only real-TLS survives |
| L3 | No real-time cross-flow correlation | MED | Replay/rate signals admitted |
| L4 | RU gate keys on SNI value, not full handshake | MED | Forces completing real TLS to named host |
| — | An allowlisted destination identity is obtainable | **CRITICAL** | Entire design unusable for RU; no gate-pass possible |

The design is *cryptographically* sound and *probing-resistant* only in its
real-TLS form, at which point its distinctiveness from refraction/fronting is
marginal; its synthetic-prologue form is the only genuinely distinct variant and
is insecure against C3/L2. The binding constraint for the user is not mimic
fidelity (solved by uTLS) but destination allowlisting (unsolved).
