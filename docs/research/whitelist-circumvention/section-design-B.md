# Design Section B — "Refraction-lite without a Cooperating ISP": Using a Genuinely-Whitelisted Third-Party RU Service as a Covert Rendezvous

*Status: design treatment + ruthless feasibility verdict. Whitepaper DESIGN section.*

## B.0 Summary of the Claim Under Test

Classic refraction networking (TapDance, Conjure) defeats endpoint-blocking by placing the proxy function **inside a cooperating transit network**: a "decoy router" on the path between client and an innocuous "decoy host" observes a covert tag in the client's TLS handshake and silently begins relaying to a hidden destination. The censor cannot block the proxy without blocking the entire ISP's address space, because the proxy *is* the path. This is its strength and, simultaneously, its central deployment limitation — it requires a witting ISP/transit operator to deploy the station.

**Idea B asks:** in the Russian context, where traffic to whitelisted services (Yandex, VK, Gosuslugi, RU CDNs such as Mail.ru/VK Cloud edges, Yandex Cloud edges) is *white by destination IP* under the TSPU SNI-allowlist, can we manufacture a refraction-like rendezvous using a legitimate, whitelisted RU service whose operator is **not** a witting accomplice — by abusing its multi-tenant / user-content / edge behavior to carry tagging and/or data, such that the on-path TSPU sees only white traffic to a white IP?

The novelty claim is: *"refraction without a cooperating router."* The task is to determine whether this claim survives, or collapses into one of three known traps:

- **Trap (i):** classic domain fronting (SNI ≠ Host on shared CDN) — dead since 2018.
- **Trap (ii):** renting whitelisted compute — a cloud/CDN tenant tunnel where the service *is* effectively the endpoint (deanonymizable, RKN-takedownable).
- **Trap (iii):** requires a session secret the on-path station cannot obtain without cooperation — i.e. the refraction primitive itself is non-instantiable here.

The verdict (stated up front, defended below): **the idea does not survive as novel refraction. Depending on which sub-variant is chosen it collapses into Trap (ii) or Trap (iii), and a third sub-variant collapses into Trap (i). The structural reason is a single invariant — refraction requires an on-path entity to read a covert tag, and a non-cooperating whitelisted service places no readable, controllable entity on the censor's path that is distinct from the service's own (TLS-terminating, logged, takedownable) endpoint.**

---

## B.1 Threat Model

We adopt a model consistent with the verified June-2026 ground truth and make every adversary assumption explicit.

### B.1.1 Adversary capabilities

- **A1 — Allowlist default-drop at the SNI/IP layer.** The TSPU operates an SNI-allowlist on the relevant access network (mobile, during regional drills; the analysis assumes the drill model generalizes to a permanent fixed-line allowlist, which is the conservative case). A flow is permitted iff its destination resolves to a whitelisted service *and* the cleartext TLS SNI (and, where inspected, the QUIC Initial SNI) names a whitelisted domain. Everything else is silently dropped. Default action is **drop, not allow**.
- **A2 — On-path passive + active inspection.** The TSPU is on-path for the client↔white-service segment. It can read cleartext ClientHello SNI, observe packet sizes/timing, perform TCP reassembly (TSPU has demonstrated TLS-record reassembly capability against ECH fragmentation — "worrying"), inject RSTs, and drop. It does **not** hold the white service's TLS private keys and cannot read TLS-encrypted application data to the white service.
- **A3 — IP-granularity blocking is the censor's lever.** The censor can add/remove individual IPs and SNIs from the allowlist. It will not blanket-block a major RU national service (Yandex/VK/Gosuslugi) — that is the whole premise that makes these IPs "white." This collateral-freedom property is what Idea B tries to exploit, exactly as refraction exploits ISP-block collateral.
- **A4 — Legal/operational reach inside RU.** The adversary (RKN + operators + FSB-adjacent legal process) can compel the white RU service to disclose tenant identity, terminate accounts, and remove content/endpoints (RKN takedown). Payment for any rented resource is KYC'd (RU card / SIM / Gosuslugi-linked). This is a *qualitatively stronger* adversary than the Western-CDN refraction threat model, because the rendezvous provider is **inside the censor's jurisdiction**.
- **A5 — First-packet / unidirectional inspection (open question, treated both ways).** Per the Iran model and the RU open question, the inspector may examine only the first ~4 client→server packets unidirectionally. We analyze the design under both "bidirectional full inspection" (conservative) and "unidirectional first-packets-only" (favorable) and flag where the latter would change the conclusion.

### B.1.2 Defender (us) capabilities

- We control the client and a hidden destination (the real proxy / decoy-station, located **outside** RU on non-white IP space).
- We are an *ordinary tenant/user* of the white RU service: we can create accounts, upload user content, call public APIs, use the service's edge/CDN exactly as a normal customer can, subject to ToS and KYC.
- We do **not** control any router on the client↔white-service path. We do **not** have the white service's TLS keys. The white service is **not cooperating** and is assumed hostile-on-compulsion (A4).

### B.1.3 Security goals

- **G1 (reachability):** client can move bytes to/from the hidden destination despite the allowlist.
- **G2 (unobservability):** the TSPU sees only white traffic to a white IP with a white SNI; the covert channel is not distinguishable from legitimate use of the white service by passive/active on-path analysis.
- **G3 (unblockability without collateral):** the censor cannot kill the channel without either (a) blocking the white service (politically/economically unacceptable — the refraction property) or (b) compelling the white service to act (the jurisdiction problem).
- **G4 (registration secrecy):** the act of "tagging"/registering a covert session is itself indistinguishable from white traffic.

Idea B lives or dies on whether G3 can hold against an **in-jurisdiction** rendezvous. Refraction's G3 holds because the decoy router is in a *foreign cooperating* ISP. We will show G3 is the load-bearing failure.

---

## B.2 Mechanism — Detailed Construction and Variants

A refraction system has three logical roles:
1. **Decoy host** — the innocuous, whitelisted destination the censor sees (here: the RU white service).
2. **Station** — the on-path entity that reads the covert tag and diverts/relays flows to the hidden destination. *(In classic refraction this is inside the cooperating ISP.)*
3. **Hidden destination / proxy** — where covert traffic actually goes.

The entire question is: **what plays the role of the Station when the white service is not cooperating?** Three structurally different attempts follow; each maps to one of the three traps.

### Variant B-1 — "Edge-tenant relay" (white service's multi-tenant edge as the data path)

**Construction.** We become a tenant of the white service's edge/compute that is reachable on its *white IP space*: e.g. a function/object on Yandex Cloud edge, a VK Cloud bucket/function, a public RU CDN origin we register, or a user-content endpoint (an uploadable serverless handler, an object-storage path with a serverless trigger, etc.). The client opens TLS with SNI = a white domain that the service genuinely serves on a white IP, and inside the encrypted channel it speaks to *our* tenant logic, which forwards to the hidden destination.

**Data path.** `client → TLS(SNI=white, IP=white) → white-service edge terminates TLS → our tenant code on the edge → egress to hidden destination → back`.

**What the censor sees.** Cleartext SNI = white; destination IP = white; TLS encrypted body. By A1/A2 this passes the allowlist. G2 holds against passive on-path analysis (modulo traffic-shape, see B.3).

**Where the Station lives.** The "station" is *our tenant code running on the white service's infrastructure*. The white service's TLS terminator hands the plaintext to our code. **There is no on-path tag-reading happening — there is in-fabric application-layer forwarding.**

This is **not refraction**. It is a CDN/cloud-tenant tunnel. See Trap (ii), B.4.2.

### Variant B-2 — "Covert tag in the handshake to a non-cooperating decoy" (true refraction primitive)

**Construction (the only variant that is genuinely refraction-shaped).** The client sends a normal-looking TLS ClientHello to the white service with SNI = white, but embeds a covert refraction **tag** — e.g. an elligator-encoded point in the ClientHello key share / random / session ticket, decryptable only by a station holding the refraction master secret (exactly as TapDance/Conjure do). The intent: an on-path station recognizes the tag and diverts the flow to the hidden destination *before/instead of* the white service's reply, so the client never actually completes a session with the white service for covert data — the white service is just the cover destination.

**Data path (intended).** `client → ClientHello(SNI=white, tag) → STATION on path reads tag → STATION relays to hidden destination`. The white service receives either nothing (TapDance-style asymmetric flow where station spoofs the white service's side) or an aborted handshake.

**What the censor sees.** A ClientHello to a white SNI/IP. Passes A1. G2 holds *if* the tag is indistinguishable (elligator/Conjure tagging is, by construction).

**Where the Station lives — the fatal question.** For this to work there must be **an entity on the client→white-service path that (a) holds the refraction secret and (b) can read+divert the flow.** Options:
- **(2a)** The white service itself is the station → requires its cooperation → **excluded by premise** (and would just be Conjure-with-an-RU-ISP, plus A4 jurisdiction).
- **(2b)** A transit router between client and white service is the station → that is **classic refraction with a cooperating transit operator** → also excluded by premise, and in RU that operator is TSPU-adjacent (the adversary), so impossible.
- **(2c)** Some third on-path box we control → we do **not** control any on-path router (defender model). We cannot inject a station onto the censor's path without being a transit/ISP operator, which is the very cooperation we claimed to avoid.

There is **no fourth option**. A tag is only useful if something on the path can read it and divert. A non-cooperating white service places no such readable, defender-controlled entity on the path. See Trap (iii), B.4.3.

### Variant B-3 — "SNI fronting / Host-header indirection on the white CDN"

**Construction.** Use a white RU CDN that hosts many tenants behind one IP/SNI. Set TLS SNI = white front domain, but inner HTTP `Host:` (or HTTP/2 `:authority`) = a covert/hidden backend co-tenant on the same CDN, expecting the CDN to route by inner Host to our backend, which egresses to the hidden destination.

**Data path.** `client → TLS(SNI=white-front) → CDN routes by inner Host → our co-tenant backend → hidden destination`.

**What the censor sees.** SNI = white. Passes A1. The inner Host is encrypted.

**Why this is just domain fronting.** This is the textbook SNI≠Host construction. It is **dead since 2018**: Google/AWS/Cloudflare disabled domain-mismatch server-side; major CDNs reject requests where SNI and Host disagree across tenants. RU CDNs have every incentive (legal A4, and simple SNI/Host consistency checks) to do the same, and RKN can mandate it. Even where a single RU CDN still allows same-CDN fronting, our "backend" is a registered, KYC'd, takedownable tenant — so it also inherits Trap (ii). See Trap (i), B.4.1.

---

## B.3 Security Analysis (assuming a variant got G1/G2 at the network layer)

Even granting the most favorable case (Variant B-1, which *does* pass the allowlist), the covert channel faces analysis beyond simple SNI matching:

- **Traffic analysis / behavioral fingerprint.** A legitimate Yandex/VK edge tenant serves recognizable workloads (object fetches, API JSON, web assets). A full-duplex, long-lived, high-throughput tunnel through a serverless object endpoint is a behavioral outlier. The censor need not decrypt: flow duration, bidirectional byte symmetry, and request cadence distinguish "tunnel" from "browsing Yandex." This is the same statistical-side-channel pressure that meek/obfs4-over-CDN already faces, and per ground truth, **naive HTTPS-mimicry through a CDN is *not* proven to survive a true allowlist** — it survives the *SNI check* but remains exposed to shape analysis and to active probing.
- **Active probing of the rendezvous endpoint.** The censor can itself become a tenant/visitor of the white service and probe the specific edge object/function/URL our clients use. If our endpoint behaves like a proxy (responds to tunnel handshakes, relays arbitrary bytes), it is identifiable and individually addable to a *sub-IP* blocklist via the white service's own path semantics (e.g. URL/SNI-host blocking where the CDN exposes per-tenant hostnames). This breaks G3 *without* blocking the whole white service.
- **TLS fingerprint of the client.** The client's uTLS/ClientHello must match a real client of the white service (a Yandex app, a browser). Mismatch is a distinguisher. This is solvable (it is what ShadowLink already attempts) but does not address G3.
- **Replay/registration observability (G4).** In Variant B-1 there is no covert "tag" at all — registration is just "open TLS to our tenant endpoint." That endpoint URL/host is the secret, and it is enumerable/probeable (above). In Variant B-2 the tag is unobservable but the variant is non-instantiable (no station). So G4 is either trivially-met-but-useless (B-1) or moot (B-2).

**Net:** the only variant that *passes the allowlist* (B-1) does not provide refraction's G3 and is subject to per-tenant identification and takedown; the only variant with genuine refraction unobservability (B-2) cannot be instantiated.

---

## B.4 The Three Traps — Ruthless Verdict per Trap

### B.4.1 Trap (i): Classic Domain Fronting — **Variant B-3 falls squarely in.**

- **Does it avoid it? No.** Variant B-3 *is* domain fronting (SNI = white front, inner Host = covert co-tenant). It inherits the exact death cause: server-side SNI/Host consistency enforcement (deployed by all major CDNs since 2018; RU CDNs can be compelled under A4). Where any RU CDN still permits same-CDN fronting, it additionally falls into Trap (ii) because our backend is a KYC'd tenant.
- **Verdict:** B-3 = dead-on-arrival, reduces to known-dead domain fronting. No novelty.

### B.4.2 Trap (ii): Renting Whitelisted Compute (the service IS the endpoint) — **Variant B-1 falls squarely in.**

- **Does it avoid it? No, and this is the key admission.** In B-1 the white service **terminates TLS** and runs **our tenant code**; the "rendezvous" is just compute we rent on whitelisted IP space. The service *is* effectively the endpoint: it sees plaintext at the edge (it terminates TLS), it knows our tenant identity (KYC payment, A4), and it can be compelled to disclose/terminate us (RKN takedown of a single tenant). This is **not** refraction's collateral-freedom — the censor does not need to block Yandex; it needs to compel Yandex to drop one abusive tenant, which RU jurisdiction makes trivial.
- **Why it is *worse* than Western-CDN renting.** Western refraction/meek deployments rent CDN compute *outside* the censor's jurisdiction; takedown requires international legal friction. Here the rented compute is *inside RU*. Deanonymization-via-payment and RKN takedown are domestic, fast, and routine.
- **Verdict:** B-1 = "renting whitelisted RU compute." The service is the endpoint. Falls fully into Trap (ii), and the in-jurisdiction twist makes G3 strictly weaker than ordinary CDN tunneling. No novelty over "run a proxy on Yandex/VK Cloud" — which is just censored-circumvention-by-domestic-cloud, defeated by A4.

### B.4.3 Trap (iii): Requires a Session Secret the On-Path Station Can't Get Without Cooperation — **Variant B-2 falls squarely in.**

- **Does it avoid it? No — this is the structural impossibility.** Refraction's diversion requires an on-path entity that (a) holds the refraction secret to read the tag and (b) can read+divert the TLS flow. Reading the tag and acting on it *is* a station function. The only on-path entities are: the white service (cooperation excluded), a transit operator (cooperation excluded; in RU it is the adversary), or a defender-controlled router (we have none — that would be the cooperation we disclaimed). To extract the covert flow, *some* on-path box must possess the session-relevant secret and divert — and obtaining that capability on a non-cooperating service's path **is exactly cooperation**.
- **Connection to REDACT.** REDACT (SIGCOMM CCR 2021) tries to relocate the station to a *data-center border router* and uses TLS session resumption to share the session secret with the station — but REDACT still requires the **data-center operator to deploy the station** (cooperation), and it is Mininet-PoC-only, not deployed. Idea B is strictly harder: we have *no* cooperating operator at all. There is no resumption-secret-sharing trick that hands an *uncooperative* on-path box the ability to divert.
- **Verdict:** B-2 = the genuine refraction shape, and it is **non-instantiable without cooperation, by construction.** This is the clean "cannot work because Y" outcome: refraction needs a station; a non-cooperating service provides none.

---

## B.5 Feasibility, Legal & Operational Fragility (RU-specific)

Even setting aside the structural verdict, the in-jurisdiction rendezvous is operationally fatal:

- **Deanonymization via payment (A4).** Any rented RU cloud/CDN resource requires KYC payment (RU bank card, SIM, frequently Gosuslugi-linked). The operator → tenant → human identity chain is short and domestically compellable. Operators of the channel are personally exposed.
- **RKN takedown granularity.** RKN can remove a single tenant endpoint/account without touching the white service, defeating G3 cheaply (no collateral cost to the censor). This is the opposite of refraction's economics.
- **ToS / abuse detection.** Using object storage / serverless / CDN as a general bidirectional tunnel violates standard ToS and trips abuse heuristics (egress volume, connection longevity). Domestic providers cooperate with takedown requests by default.
- **Active in-fabric inspection.** The provider terminates TLS (B-1) and can, under compulsion or its own AUP, inspect plaintext at its edge — collapsing G2 *inside the fabric* even though the on-path censor saw only white traffic.
- **Sustainability.** Each identified endpoint is individually burnable; the defender is in a per-tenant whack-a-mole against a domestic adversary with subpoena power — strictly worse than the IP-rotation arms race meek/obfs4 already loses against a determined censor.

---

## B.6 Conclusion / Verdict

Idea B does **not** survive as a novel "refraction without a cooperating router." It is not one design but three, each of which reduces to a known trap:

- **Variant B-3 (SNI-fronting) → Trap (i):** plain domain fronting, dead since 2018, additionally KYC-exposed.
- **Variant B-1 (edge-tenant relay) → Trap (ii):** renting whitelisted RU compute; the service terminates TLS and *is* the endpoint; deanonymizable + RKN-takedownable; the in-jurisdiction location makes its unblockability property *worse* than ordinary CDN tunneling, not better.
- **Variant B-2 (covert tag to non-cooperating decoy) → Trap (iii):** the only genuinely refraction-shaped variant, and it is **provably non-instantiable**: refraction requires an on-path station that reads a covert tag and diverts; a non-cooperating whitelisted service places no readable, defender-controlled station on the censor's path. Giving any on-path box that capability *is* cooperation.

**The load-bearing impossibility is a single invariant:** *refraction's collateral-freedom (G3) comes from the diversion happening on-path inside a network the censor will not block; "non-cooperating rendezvous" removes precisely the on-path, secret-holding, diverting entity that makes refraction refraction.* What remains is either fronting (dead) or a domestic cloud tenant (the endpoint, takedownable). The RU "white-by-IP" property does grant allowlist passage at the SNI/IP layer — but allowlist passage is *not* the hard part refraction solves; **unblockability-without-cooperation is**, and that is exactly what a non-cooperating in-jurisdiction service cannot provide.

**Recommendation for the whitepaper:** present Idea B as a *negative result* — a clean demonstration that the "refraction without a cooperating operator" goal is unattainable via a non-cooperating rendezvous, because the station role is irreducible. The only way the white-IP property yields real value is if a witting RU operator deploys an actual station (= classic refraction with an RU cooperating operator, which RU jurisdiction makes politically infeasible), or if one accepts a takedownable domestic-cloud endpoint (= Trap ii, defeated by A4). Note also that this connects to and is strictly harder than REDACT, which still required a cooperating data-center operator and remains undeployed. Naive HTTPS-mimicry through the white service (which is all B-1 ultimately is at the wire) is, consistent with verified ground truth, **insufficient against a true allowlist** once shape analysis and per-tenant active probing are applied.
