# Red-Team Report — Idea B ("Refraction-lite without a Cooperating ISP")

*Adversarial review. Reviewer posture: trying to KILL idea B. Cross-checked against the
June-2026 verified ground truth (RU TSPU SNI-allowlist drills; Iran per-AS protocol
allowlist with unidirectional first-~4-packet inspection; Conjure/TapDance refraction
needing an on-path cooperating operator; REDACT SIGCOMM CCR 2021 data-center-border PoC;
ECH TSPU block + reassembly; domain fronting dead since 2018; refuted "wrap-in-HTTPS
defeats allowlist" hallucination).*

**Target document:** `section-design-B.md`
**Verdict: DEAD.** The design itself reaches the correct negative result; my job was to
find an escape hatch it missed. There is none that survives. Below I (1) confirm the
design's kill is structurally sound, (2) attack the two places where the design is
*generous to itself* and show the idea is in fact *more* dead than written, and (3)
mount a novelty attack vs the prior art to show there is nothing salvageable.

---

## 0. Bottom line for the impatient

Idea B is three designs wearing one trenchcoat. Each leg dies:

- **B-1 (edge-tenant relay)** → renting whitelisted RU compute. The service terminates
  TLS and *is* the endpoint. Deanon-by-KYC-payment + single-tenant RKN takedown.
  *In-jurisdiction makes it strictly worse than Western CDN tunneling, not better.*
- **B-2 (covert tag to a non-cooperating decoy)** → the only genuinely refraction-shaped
  leg, and it is **non-instantiable**: there is no defender-controlled, secret-holding,
  flow-diverting box on the censor's path, and putting one there *is* the cooperation the
  premise forbids.
- **B-3 (SNI≠Host fronting)** → textbook domain fronting, dead since 2018, plus KYC-exposed.

The single load-bearing invariant the design correctly identifies: **refraction's
unblockability (G3) is produced by an on-path entity inside a network the censor won't
block; a non-cooperating rendezvous removes exactly that entity.** I could not break this
invariant. I *could* show the design under-states the damage in two places.

---

## 1. (a) The session-secret question — where does the station get the secret?

This is the crux the task demands I force. The design answers it correctly but politely.
Let me make it brutal and airtight.

**Refraction's diversion is a two-capability requirement.** To pull a covert flow out of a
flow that *looks like* traffic to a white decoy, the diverting box must:

1. **Recognize** the flow as covert — read a tag that is unforgeable and unobservable to
   the censor (Conjure/TapDance: elligator-encoded point in the ClientHello, decryptable
   only with the refraction master secret).
2. **Divert/relay** — terminate or hijack the flow and speak to the hidden destination,
   which for TapDance means *spoofing the decoy's side of the TCP/TLS session* (the
   station must be able to inject segments that the client accepts as coming from the
   decoy IP — only possible if the station is **on-path** and can see/spoof the
   sequence/ack state).

Now enumerate every candidate for "the box" on the RU client→white-service path, and ask
where each gets the secret AND the on-path position:

| Candidate box | Has refraction secret? | On-path to spoof/divert? | Verdict |
|---|---|---|---|
| White service itself (its TLS terminator) | Only if *we gave it to them* = cooperation | Yes (it's the endpoint) | **= cooperation; excluded by premise. And it's the endpoint, not a station → Trap ii** |
| RU transit router between client and service | Only if operator deployed our station = cooperation | Yes | **= classic refraction w/ cooperating RU transit; in RU that operator is TSPU-adjacent (the adversary) → impossible** |
| A box *we* control on the path | We hold the secret | **No — we control no on-path router** | **Can't divert. To get on-path we'd have to be a transit/ISP operator = the cooperation we disclaimed** |
| The client itself | Yes | It is the *origin*, not on-path between itself and the service | **A client can't be its own decoy-router; this is just "client opens TLS to endpoint" = Trap ii again** |

**There is no fifth candidate.** The secret is not the binding constraint — *position* is.
Even if we magically handed the secret to a willing third party, that party would still
need to be on-path and able to spoof the decoy's TCP state, which is precisely the
on-path-station property only a cooperating transit operator (or the endpoint) has.

So the forced dichotomy holds with no slack:

> Without the service's cooperation, the on-path station's secret has **nowhere to come
> from that also gives it diversion capability**. Therefore the scheme needs either
> (i) the service's cooperation — then the service is the endpoint (Trap ii), not a
> refraction station; or (ii) a separate channel to carry the rendezvous/secret — and
> **that separate channel is not whitelisted** (it's the same allowlist problem one level
> down: how does the client reach the station to register? If via the white service, the
> white service is back in the loop = Trap ii; if via anything else, it's dropped by A1).

The "separate channel" recursion is the cleanest kill and the design under-emphasizes it:
**any out-of-band registration/secret-exchange channel itself faces the allowlist.** You
cannot bootstrap a covert rendezvous over a channel the censor already default-drops. The
only channel that passes is "traffic to the white service" — which collapses you straight
back into B-1/Trap-ii.

**Reviewer note on the Iran unidirectional-inspection open question.** The task flags that
*if* inspection is unidirectional client→server first-4-packets-only, then "server-side
tagging like TapDance can satisfy the check." This is the one place an optimist could push.
I kill it: TapDance/Conjure server-side satisfaction of a unidirectional check **still
requires the on-path station to be the thing answering** in the decoy's stead. A
non-cooperating white service will answer the ClientHello *itself* (it's a real service),
completing a real handshake to a real white endpoint — there is no station intercepting to
"satisfy the check" on behalf of a hidden destination. Unidirectional inspection makes the
*censor's* job cheaper to evade for systems that *already have a station*; it does nothing
to *create* a station where there is none. So the open question, even resolved in the
optimist's favor, does not rescue B-2.

---

## 2. (b) Does it collapse into fronting, or into renting whitelisted compute?

**Both — depending on the leg — and the design's mapping is correct. I strengthen it:**

### 2.1 B-3 is fronting, and "fronting is dead" is even firmer in RU than globally

The design says SNI≠Host is dead since 2018 (Google/AWS/CF server-side mismatch rejection).
Additional kill shots specific to RU the design only gestures at:

- **RU CDNs have positive incentive + legal compulsion (A4) to enforce SNI/Host
  consistency**, which is a *cheap stateless check* — not even DPI, just a server-side
  string compare. RKN can mandate it by directive. There is no economic cost to the CDN.
- Even the residual case ("some RU CDN still allows same-CDN fronting") **does not yield
  refraction** — it yields a co-tenant backend that is a registered, KYC'd, takedownable
  endpoint. So B-3's best case *degrades into B-1/Trap-ii anyway.* B-3 has no independent
  survival mode; it's strictly dominated.

### 2.2 B-1 is renting whitelisted compute, and the in-jurisdiction twist is a force-multiplier the design under-prices

The design correctly says B-1 = "run a proxy on Yandex/VK Cloud," defeated by A4. I add
three sharper edges:

1. **TLS termination = plaintext exposure inside the fabric (G2 dies *behind* the
   censor's view).** B-1's whole premise is the white service terminates TLS so the SNI is
   genuinely white. But that means the *provider* sees plaintext at its edge. Under A4 (or
   its own AUP / lawful-intercept obligation under SORM), the in-fabric plaintext is
   available to the adversary **without the censor ever touching the wire.** This is not a
   refraction property failing — it's *worse*: refraction never exposes plaintext to the
   decoy. B-1 exposes it to a domestic, compellable provider. The design says this; it
   should say it is **categorically disqualifying**, because it means even a *perfect*
   on-wire G2 yields zero confidentiality against this adversary.

2. **SORM / data-localization makes deanon turnkey, not just "possible."** RU cloud/CDN
   providers operate under SORM lawful-intercept and 152-FZ data-localization. The
   tenant→payment→identity chain isn't merely "domestically compellable" — it is
   *already logged and retained* by mandate. Deanon latency is a subpoena, not an
   investigation.

3. **Per-tenant burn is sub-IP and collateral-free for the censor.** RKN removing one
   tenant endpoint costs the white service nothing and the censor nothing — the exact
   inverse of refraction's economics, where blocking the proxy means blocking the whole
   ISP. The design states this; the reviewer-grade phrasing is: **B-1 inverts the sign of
   the property that defines refraction.** It is not "refraction-lite," it is
   "anti-refraction" — maximally easy to block without collateral.

**Conclusion (b):** Idea B does not "collapse into" one trap — its three legs occupy all
three traps, with no leg escaping. Fronting (dead) for B-3, renting-domestic-compute
(deanon+takedown) for B-1, non-instantiable for B-2.

---

## 3. (c) RU-specific kill shots (compulsion / payment / abuse-detection)

The design covers these; I rank them by lethality and add the ones it missed.

1. **SORM + 152-FZ retention (design missed the specific legal instruments).** Not just
   "RKN can compel" — the logs *already exist by law*. KYC payment (RU card / SIM /
   Gosuslugi linkage) + mandatory retention = identity is pre-collected. There is no
   anonymous tenancy of a major RU service.
2. **Single-tenant takedown granularity.** RKN removes the specific bucket/function/origin;
   white service untouched; G3 falls for free. (design ✓)
3. **Provider's own abuse detection independent of the censor.** Object-storage /
   serverless / CDN as a full-duplex high-throughput long-lived tunnel violates standard
   ToS and trips egress-volume + connection-longevity heuristics that *every* cloud runs
   for cost/abuse reasons — the provider burns you to protect its own margins, no censor
   required. (design ✓, under-weighted: this fires even if RKN never looks.)
4. **In-fabric plaintext (re-stated as a kill, see §2.2.1).** The provider terminates TLS;
   compulsion or AUP exposes payload. Disqualifying for a confidentiality goal.
5. **Bootstrap deanon.** To *register/pay* you must already transact with the RU provider
   from an identity — the act of acquiring the rendezvous is itself a KYC event inside the
   jurisdiction. There is no clean-room way to stand up the channel.

---

## 4. (d) Novelty attack vs Conjure / REDACT / Snowflake / CDN-tunneling

The claimed novelty is "refraction without a cooperating router." I attack each prior-art
neighbor to show B is either a known thing or a known-impossible thing.

- **vs Conjure/TapDance.** B-2 *is* the TapDance/Conjure primitive minus the one component
  that makes it work (the on-path cooperating station). Removing the station does not
  produce a new design; it produces a non-design. **No novelty — it's Conjure with the
  load-bearing wall deleted.**
- **vs REDACT (SIGCOMM CCR 2021).** REDACT's contribution was precisely to *relax* the
  cooperation requirement — relocating the station to a multi-tenant **data-center border
  router** and using **TLS session resumption** to share the session secret with the
  station. Crucially REDACT **still requires the data-center operator to deploy the
  station** (still cooperation) and is **Mininet-PoC only, never deployed.** Idea B claims
  to go *further* (zero cooperating operator) — but that is strictly *harder* than the
  unsolved-in-production REDACT, and B offers **no mechanism** (no resumption-secret trick,
  nothing) to hand an uncooperative on-path box the diversion capability. **B is "REDACT
  but harder and with no mechanism" — anti-novelty: it claims the stronger result while
  providing less machinery than the weaker, undeployed prior art.**
- **vs Snowflake.** Snowflake's "rendezvous without a fixed blockable endpoint" works
  because volunteer browser proxies are (i) numerous, (ii) outside the censor's
  jurisdiction, (iii) reached via a separate (domain-fronted/AMP-cache) signaling channel.
  B has none of these: its rendezvous is a single in-jurisdiction provider, and its
  signaling channel (how you reach the rendezvous) is *the white service itself* = circular
  (Trap ii) or *something else* = dropped by the allowlist. **B is Snowflake without the
  collateral-freedom, the jurisdictional distance, or a working signaling channel.**
- **vs CDN-tunneling (meek/obfs4-over-CDN).** B-1 at the wire *is* meek-over-CDN, but
  pointed at a **domestic** CDN. Ground truth: naive HTTPS-mimicry through a CDN survives
  the SNI check but is **not proven to survive a true allowlist** once shape analysis +
  active per-tenant probing apply; and the censor can *itself* become a tenant and probe
  the exact rendezvous URL/host to sub-IP-blocklist it. So B-1 inherits every meek weakness
  **plus** domestic deanon. **No novelty over meek; strictly worse threat model.**

**Novelty verdict:** zero. Every leg is either an existing technique relocated into the
censor's jurisdiction (worse) or an existing technique with its essential component deleted
(non-functional). There is no new primitive.

---

## 5. Where the design was too generous to itself (reviewer corrections, all *strengthening* the kill)

1. The design grants B-1 "G2 holds against passive on-path analysis." True at the wire, but
   it should immediately note G2 **dies in-fabric** (provider sees plaintext) — so B-1
   never had confidentiality against *this* adversary at all. The on-wire G2 is a red
   herring.
2. The design treats the "separate channel" only implicitly. The explicit recursion —
   *any registration/secret-exchange channel is itself subject to the allowlist* — is the
   cleanest single-sentence kill and deserves top billing.
3. The design entertains the unidirectional-inspection open question as possibly favorable.
   It is not favorable to B: unidirectional inspection helps systems that *already have a
   station*; it cannot manufacture one. The open question is irrelevant to B's survival.

None of these rescue any leg; all three make the negative result firmer.

---

## 6. Final verdict

**DEAD.** Not wounded — dead, and the design's own conclusion is correct. Idea B is not a
single circumventable scheme with a patchable flaw; it is a category error. "Refraction
without a cooperating router" deletes the entity that *is* refraction. What remains is
fronting (dead since 2018), a domestic-cloud endpoint (deanon + single-tenant RKN takedown,
plaintext-exposed in-fabric), or a non-instantiable tag with no box to read it. The RU
white-by-IP property buys *allowlist passage* — but allowlist passage is the part
refraction does *not* solve; **unblockability-without-cooperation is the part it solves, and
an in-jurisdiction non-cooperating rendezvous structurally cannot provide it.**

**Recommendation:** keep Idea B in the whitepaper exactly as the author proposes — as a
clean, defensible **negative result**, with the §1 separate-channel recursion and §2.2.1
in-fabric-plaintext disqualifier promoted to the front of the kill. Do not pursue any
variant. The only paths that touch the white-IP property and survive require either a
witting RU operator (= classic refraction, politically infeasible in RU) or accepting a
takedownable domestic endpoint (= Trap ii, defeated by A4 + SORM).
