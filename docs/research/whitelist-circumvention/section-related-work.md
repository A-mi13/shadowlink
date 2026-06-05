# Related Work and Novelty Positioning

*Survey / related-work section for the whitelist-circumvention whitepaper, in the
tradition of FOCI and PETS systematization sections. Verified June-2026 ground
truth is cited inline; speculative or time-varying adversary properties are
flagged. This section positions two candidate designs — **Idea A** (front-loaded
mimicry against a unidirectional first-N-packet allowlist) and **Idea B**
(refraction without a cooperating ISP, via a non-witting whitelisted RU service
rendezvous) — against the literature, and assigns each an explicit novelty
verdict: genuinely-novel / incremental / reduces-to-known.*

---

## 1. Scope and the axis that reorganizes the literature

Most of the circumvention literature was written for a **blocklist** adversary:
the censor enumerates what is forbidden (by IP, by SNI, by protocol fingerprint,
by flow statistics) and a tunnel survives by *not matching* any prohibited
signature. The 2024–2026 measurement record documents a qualitatively different
adversary in the threat landscape this whitepaper targets — the **allowlist
(default-drop)** censor, which enumerates what is *permitted* and silently drops
the residual. This inverts the design objective: a tunnel no longer wins by
looking like nothing in particular; it must *affirmatively match a permitted
class*. We therefore organize the prior art along the axis of **what each
technique presents to the gate**, because that is the property an allowlist
actually tests:

1. **Mimicry / shape-matching** — make the flow *look like* a permitted protocol
   (FTE, SkypeMorph, StegoTorus, Geneva-evolved strategies, and naive
   HTTPS-wrapping, which is the class ShadowLink occupies today).
2. **Tunneling through an allowed service** — ride a destination the censor will
   not block (domain fronting/meek, Snowflake/WebRTC, media-tunneling such as
   DeltaShaper/Protozoa/CovertCast).
3. **Refraction / decoy routing** — relocate the proxy function *onto the network
   path* inside a network the censor cannot afford to block (TapDance, Conjure,
   Slitheen, REDACT).

A central, adversarially-confirmed result frames everything below: **no published
work supports the claim that generic HTTPS-wrapping defeats a true allowlist.**
Wrapping a tunnel in TLS to an arbitrary CDN domain survives a blocklist (the body
is opaque) but is exactly the residual class an SNI/protocol allowlist drops. This
is the refuted "wrap-in-HTTPS / obfs4 / meek defeats the allowlist" hallucination,
and it is the reason ShadowLink's analytics-over-HTTPS persona — however well its
*body* statistics are calibrated — is *insufficient by construction* against the
allowlist threat: its *opening* is generic TLS to a non-allowlisted identity,
which is precisely what the gate inspects.

---

## 2. The 2024–2026 allowlist measurement record (the ground this builds on)

Both ideas are responses to a specific, measured adversary, not to a folklore one.
The load-bearing measurement results:

- **Iran per-AS protocol allowlist (Alaraj & Wustrow, "Proxies as Sensors," ACM
  AsiaCCS 2025; arXiv:2507.14183).** Inspection examines only the **first ~4
  packets client→server, unidirectionally**, matching them against a
  permitted-protocol signature (a real TLS ClientHello shape, an SSH signature);
  non-matching openings (OpenVPN UDP/1194, SSH/22, generic TCP/UDP) are silently
  dropped. Two properties are doing all the work for Idea A: **bounded inspection
  window** and **unidirectionality** — and the survey treats both as
  time-varying adversary policy knobs, not laws.
- **Decentralized, per-AS heterogeneity.** Censorship is *not* one national model;
  different Iranian ASes apply packet injection, IP blocking, mid-connection
  dropping, and protocol allowlisting heterogeneously. Any design must survive a
  per-AS adversary, not a monolith.
- **Russia TSPU SNI-allowlist (Tor blog 2025).** A ~720-domain whitelist observed
  on **mobile networks during regional drills, late 2025 — not yet permanent
  fixed-line.** This keys on cleartext SNI *value* inside a real TLS ClientHello
  (a distinct gate from Iran's protocol-signature match), and plausibly admits by
  SNI *and* destination-IP class.
- **TSPU ECH block (Cloudflare/FOCI-line work, Nov 2024).** TSPU drops the
  ClientHello when outer SNI = `cloudflare-ech.com` AND destination = Cloudflare
  IP. Circumvented by **combining TCP segmentation + TLS record fragmentation**,
  but TSPU has demonstrated **reassembly capability** — the evasion is fragile and
  may already be patched. China/Iran neutralize ECH *indirectly* by censoring
  encrypted DNS (DoH/DoT/DoQ) so the client cannot fetch the ECH config. ECH reach
  is further capped by Cloudflare's near-monopoly on deployment and a static,
  distinguishable outer SNI.
- **GFW QUIC decryption at scale (USENIX Security 2025).** Since April 2024 the
  GFW derives QUIC Initial keys from the cleartext DCID + salt to read SNI at
  scale. Evaded by (a) a first Initial with an *unknown* QUIC version
  (undecryptable payload) followed by the real handshake, or (b) ECH-over-QUIC with
  an unblocked outer SNI.
- **IRBlock (USENIX Security 2025).** Iran actively disrupts UDP at **5.4M-IP
  scale** — UDP transports face **active interference**, not merely default-drop.
  This is why neither idea below leans on a UDP carrier.

These results jointly define the open questions the two ideas exploit or
respect: *(i)* does TCP-seg+TLS-frag still beat the TSPU ECH block (reassembly is
"worrying"); *(ii)* is the unidirectional client→server-only first-packet
inspection still true (if so, server-side tagging à la TapDance can satisfy the
check); *(iii)* is the RU allowlist expanding from mobile drills to permanent
fixed-line.

---

## 3. Mimicry and its critiques — the lineage Idea A must clear

### 3.1 The parrot critique (the field's settled negative result)

Houmansadr, Brubaker & Shmatikov, **"The Parrot is Dead: Observing Unobservable
Network Communications" (IEEE S&P 2013)**, is the result every mimicry proposal
must answer. It showed that systems imitating a protocol's *requests* —
SkypeMorph (CCS 2012), StegoTorus (CCS 2012), CensorSpoofer (CCS 2012) — fail
because faithfully reproducing a protocol's full state machine, its *responses*,
its error/dependency behavior, and its side-channel timing is intractable. A
censor with **active probing** (connect to the endpoint and check it *responds*
like the protocol it claims) and **bidirectional/stateful inspection** trivially
unmasks a one-sided parrot. The follow-on **"Seeing through Network-Protocol
Obfuscation" (Wang et al., CCS 2015)** generalized the detector side empirically.

**FTE (Dyer et al., "Protocol Misidentification Made Easy with Format-Transforming
Encryption," CCS 2013/2014)** is the most rigorous mimicry point: it forces traffic
to match a target protocol's *regex/DPI signature* by construction, defeating
regex-based DPI. But FTE explicitly matches the *classifier's signature*, not the
protocol's *behavior* — it is precisely as strong as the classifier is shallow,
and collapses under active probing or stateful analysis. FTE is the honest
upper bound on "mimic the gate's check and nothing more."

### 3.2 Where Idea A sits in this lineage, and its delta

Idea A ("front-loaded mimicry") makes a single, narrow bet: that the *measured*
gate (Iran's first-~4-packet, unidirectional classifier) is so shallow and so
temporally bounded that a tunnel need only be a perfect mimic **for the inspection
window**, then "grow" the covert channel *after* the gate stops looking. Stated
against the lineage:

- **What is borrowed:** essentially all of the mimicry machinery. Byte-exact
  ClientHello reproduction is uTLS (ShadowLink already pins Chrome-133 with
  MLKEM768 key_share); the "match the classifier signature, not the full
  behavior" stance is FTE's; the X25519 + AES-256-GCM covert handshake reuses
  ShadowLink's `core/`. None of this is new.
- **What is (claimed) new:** the *temporal* framing — exploiting **boundedness
  (L1)** and **unidirectionality (L2)** of *this specific measured gate* so that a
  mimic that is perfect only for packets 1..N is *sound* rather than a parrot,
  because the gate never observes the part of the session where mimicry would fail
  (the server's protocol responses, the long-horizon statistics).
- **Why the delta is fragile, per the lineage:** the parrot critique reapplies the
  instant the gate (a) extends N into the handshake/early app-data, or (b)
  inspects bidirectionally, or (c) actively probes the endpoint (C3). The design's
  own security analysis concedes this: under active probing the synthetic-prologue
  server (which does *not* speak the mimicked protocol's responses) dies
  immediately, forcing the **real-TLS carrier** — at which point the handshake is
  *genuine* TLS to a *real* allowlisted host, and "front-loading" has silently
  become **fronting/refraction**, contributing nothing beyond those known classes.
  The only variant where front-loading does work *distinct* from refraction is the
  synthetic-prologue variant, and that is "a parrot with a shorter neck": it
  survives *only* while the cited adversary does not look at the neck (no C3, no
  L2 failure). The cost-asymmetry is wrong-way — extending N is cheap for the
  censor, catastrophic for the mimic — which is the exact structural error the
  parrot critique buried.

**Idea A is, at its core, the FTE/parrot question re-asked against a freshly
measured, unusually shallow gate.** Its contribution is empirical (it is correct
*for this gate, today*), not a new evasion primitive.

---

## 4. Tunneling through an allowed service — the "ride a white destination" class

### 4.1 Domain fronting and meek

**Domain fronting** (SNI ≠ Host on a shared CDN; Fifield et al., "Blocking-
Resistant Communication through Domain Fronting," PETS 2015) and its Tor transport
**meek** were the canonical "ride a white destination" technique. They are
**largely dead since 2018**: Google, AWS, and Cloudflare disabled server-side
domain-mismatch. Tor still ships some fronting configs in 2025, but under
sustained pressure. Against an allowlist, meek's *SNI* passes (it names a white
CDN), but the technique remains exposed to **shape analysis** and **active probing
of the rendezvous**, and the fronting trick that hid the *real* Host is gone.

### 4.2 Snowflake / WebRTC and media-tunneling

**Snowflake** (WebRTC-based, ephemeral volunteer proxies; the rendezvous is a
hard-to-block broker, the data path is WebRTC/DTLS) rides an *allowed real-time
media* primitive. **CovertCast** (Privacy Enhancing Technologies 2016; tunneling
through live-streaming platforms), **DeltaShaper** (PoPETs 2017) and **Protozoa**
(CCS 2020) tunnel through *real WebRTC media sessions* by modulating the encoded
media — Protozoa in particular replaces encoded video frames to achieve high
throughput while preserving the genuine media flow's statistics. These are the
strongest "allowed-service" designs because the carrier is a *real* session of the
allowed service (not a mimic of one), so they survive active probing of the
*carrier*. Their relevance here: they show the *right* shape for "ride a white
service" — **a genuine session of the service, not a parrot of it** — and they set
the bar Idea B's variants must clear (and mostly fail to).

### 4.3 Where Idea B sits in this class, and its delta

Idea B asks whether the RU "white-by-IP" property of national services (Yandex,
VK, Gosuslugi, RU CDN edges) can be turned into a refraction-like rendezvous
*without* a witting operator. Mapped against this class, its three sub-variants
reduce to known traps:

- **Variant B-3 (SNI-front / inner-Host indirection on a white RU CDN)** *is*
  domain fronting (§4.1) — dead since 2018, and additionally KYC-exposed because
  the co-tenant backend is a registered, takedownable RU tenant. **Reduces to
  known-dead.**
- **Variant B-1 (edge-tenant relay: our code on the white service's multi-tenant
  edge)** is *renting whitelisted compute* — the white service **terminates TLS**
  and runs *our* tenant code; the service *is* the endpoint. This is the
  CDN/cloud-tenant tunnel, **not** refraction. Crucially it is *not even as strong*
  as the media-tunneling class of §4.2: those carry a *genuine* media session, while
  B-1's tenant endpoint is a behavioral outlier (long-lived, full-duplex,
  high-throughput) that fails shape analysis and per-tenant active probing — and,
  being **in RU jurisdiction**, is deanonymizable by KYC payment and removable by
  single-tenant RKN takedown *without* blocking the white service. The
  in-jurisdiction location makes its unblockability *strictly worse* than ordinary
  Western-CDN tunneling. **Reduces to a takedownable domestic-cloud endpoint.**

Idea B's only *refraction-shaped* sub-variant (B-2) belongs in the refraction
discussion below, where its impossibility is made precise.

---

## 5. Refraction / decoy routing — the class both ideas orbit

Refraction networking is, per the verified ground truth, **the strongest surviving
class**: the proxy function lives *inside a cooperating ISP/transit network* (a
"decoy router" on-path), not at a blockable endpoint, so the censor cannot block
the proxy without blocking the cooperating network's entire address space.

- **TapDance (Wustrow et al., USENIX Security 2014)** introduced *end-to-middle*
  refraction: the client embeds a covert **tag** in a TLS handshake to an
  innocuous decoy host; an on-path station recognizes the tag and relays to the
  hidden destination, *without* completing a normal connection to the decoy
  (asymmetric "incomplete-flow" trick). The station shares a secret with clients;
  the decoy is non-witting but the *transit operator hosting the station* is
  witting.
- **Conjure (Frolov et al., CCS 2019)** generalized the decoy from a single host to
  the ISP's *entire unused IP space* ("phantom" addresses), vastly enlarging the
  anti-blocking surface. Conjure is the production reference point cited in the
  ground truth: **1M+ users, 800M+ connections from Iran (Jul 2023–Feb 2025) via
  Psiphon.** Its central, oft-criticized limitation is exactly its strength's
  precondition: **it requires a cooperating network operator on-path.**
- **Slitheen (Bocovich & Goldberg, CCS 2016)** is the *defense-grade* refraction
  point: it replaces *leaf content* in a genuine HTTPS page byte-for-byte so the
  covert flow is *traffic-analysis-resistant* (identical shape to a real page
  load), defeating the body-consistency check that ordinary refraction does not
  address. Its relevance: it is the standard for "the growth-regime traffic must
  match the carrier's *own* statistics," which is exactly the residual problem
  Idea A's post-window regime cannot solve generically.
- **REDACT (Wails et al., ACM SIGCOMM CCR 2021)** relocates the station to a
  *multi-tenant data-center border router* and uses **TLS session resumption** to
  share the session secret with the station — a partial answer to "where can a
  station live other than an ISP backbone." But REDACT **still requires the
  data-center operator to deploy the station** (cooperation) and is **Mininet-PoC /
  design-only, not deployed.** It is the closest prior art to Idea B and the
  benchmark against which Idea B must be measured.

### 5.1 Idea A's relationship to refraction

Idea A's *probing-resistant* form (the server always completes a real TLS handshake
and serves a real decoy to anyone lacking authenticated covert material, diverging
to covert mode only for a ClientHello whose covert field decrypts) **is the
TapDance/Conjure endpoint-tagging pattern applied at the endpoint** rather than
on-path. This is the part of Idea A that is *sound* — and it is precisely the part
that is *not new*: it is refraction's tagging discipline relocated to a cooperating
*endpoint* the operator controls. Once C3 forces this real-TLS form, Idea A's
distinctiveness from refraction/fronting "shrinks to near-zero," and its binding
constraint becomes refraction's own deployment limitation in disguise: **it needs
a genuinely allowlisted destination identity, which it does not provide.**

### 5.2 Idea B's relationship to refraction (the impossibility)

Idea B's only genuinely refraction-shaped sub-variant, **B-2** (embed a Conjure-style
elligator-encoded tag in a ClientHello to a non-cooperating white RU service), is
**non-instantiable by construction.** Refraction requires an on-path entity that
(a) holds the refraction secret to read the tag and (b) can read+divert the flow.
The only on-path entities on the client→white-service path are: the white service
itself (cooperation — excluded by premise), a transit operator (cooperation —
excluded, and in RU it *is* the adversary, TSPU), or a defender-controlled router
(we have none — possessing one *is* the cooperation we disclaimed). There is no
fourth option. **REDACT is the sharpest contrast:** even REDACT's resumption-secret
trick required a *cooperating data-center operator* to run the station; Idea B has
*no* cooperating operator at all, so it is **strictly harder than the
undeployed REDACT** and cannot be instantiated. The invariant: refraction's
collateral-freedom comes from diversion happening *on-path inside a network the
censor will not block*; a non-cooperating rendezvous removes exactly the on-path,
secret-holding, diverting entity that makes refraction *be* refraction.

---

## 6. Automated evasion (Geneva) and why neither idea is a Geneva-class result

**Geneva (Bock et al., "Geneva: Evolving Censorship Evasion Strategies," CCS 2019;
and follow-ons)** uses a genetic algorithm to *automatically discover*
packet-manipulation strategies (segmentation, reordering, TCB-teardown, injected
control packets) that defeat *stateful DPI* — the TCP-seg + TLS-record-frag family
that the TSPU ECH evasion belongs to. Geneva is the state of the art for
**blocklist/DPI** evasion and for finding the *implementation bugs* in a censor's
reassembly logic (directly relevant to open question (i): does TSPU's reassembly
patch the seg+frag ECH evasion). Neither Idea A nor Idea B is a Geneva-class
contribution: Geneva attacks the censor's *parsing/state-machine bugs* to slip a
*forbidden* signature past a blocklist; the allowlist threat both ideas target has
no forbidden signature to hide — it has a *permitted* signature to *affirmatively
produce*. Geneva is the right tool against the residual **blocklist DPI** that is
active on RU fixed-line *today* (where ShadowLink's existing analytics-mimicry
remains adequate), and is **complementary** to, not competitive with, either idea.
It is included here to delimit the boundary: automated mutation defeats
default-allow DPI, not default-drop allowlists.

---

## 7. Novelty deltas — explicit per-idea accounting

### 7.1 Idea A — front-loaded mimicry

| Component | Borrowed from | New here? |
|---|---|---|
| Byte-exact ClientHello / field-level control | uTLS; FTE's "match the signature" stance | No |
| Covert key bits in ClientHello random/key_share | TapDance/Conjure tagging (elligator/uniform-bytes channel) | No |
| Always-real-TLS + decoy, divert only on auth'd material | TapDance/Conjure endpoint discipline; ShadowLink `failClosedToDecoy` | No |
| Post-window shape survival | Slitheen (carrier-consistent shaping); ShadowLink Phase 2/3 mimicry | No |
| **Temporal exploitation of bounded + unidirectional gate (L1∧L2) so a window-only mimic is sound** | — | **Yes, but empirical & fragile** |

The one genuinely-new element (window-only mimicry as *sound* rather than parrot)
holds **iff L1 ∧ L2 hold and no C3 probing occurs** — exactly the conditions the
parrot critique says a capable censor removes cheaply. Under active probing the
design must adopt the real-TLS carrier, which reduces it to known
refraction/fronting and re-exposes the unsolved hard part it does not address
(obtaining an allowlisted destination identity).

### 7.2 Idea B — refraction without a cooperating ISP

| Sub-variant | Reduces to | Prior art |
|---|---|---|
| B-3 (SNI-front on white RU CDN) | Domain fronting | Fifield PETS 2015 — dead since 2018 |
| B-1 (edge-tenant relay) | Renting whitelisted (domestic) compute; service *is* endpoint | CDN/cloud tunneling; *weaker* than Protozoa/DeltaShaper (no genuine carrier session); in-jurisdiction → KYC-deanon + RKN takedown |
| B-2 (covert tag to non-cooperating decoy) | The true refraction shape — **non-instantiable** (no on-path station without cooperation) | TapDance/Conjure (need witting operator); REDACT (need witting DC operator; PoC-only) |

There is no salvageable novel core. The white-by-IP property grants **allowlist
passage** at the SNI/IP layer — but allowlist passage is *not* the hard part
refraction solves; **unblockability-without-cooperation is**, and an
in-jurisdiction non-cooperating service cannot provide it.

---

## 8. Novelty verdicts

- **Idea A — front-loaded mimicry: INCREMENTAL (genuinely-novel only in its
  unsound form).** The single new idea — exploiting the *measured* boundedness and
  unidirectionality of Iran's first-N-packet gate so a window-only mimic is sound —
  is a real, correct *empirical* observation about one specific 2025–2026
  adversary, but it is fragile by exactly the cost-asymmetry the "Parrot is Dead"
  lineage identified, and its only variant that is *distinct* from
  refraction/fronting (synthetic-prologue) is unsound against active probing (C3)
  and bidirectional inspection (L2). Its sound form (real-TLS + probe-resistant
  decoy + AEAD growth regime) **reduces to known refraction/endpoint-fronting** and
  does not solve the binding constraint (an allowlisted destination identity).
  Best framed as a *gate-pass component* and an *empirical contribution* about the
  shallowness of a measured gate — not a new evasion primitive.

- **Idea B — refraction without a cooperating ISP: REDUCES-TO-KNOWN (a clean
  negative result).** Each sub-variant collapses: B-3 → dead domain fronting; B-1 →
  takedownable in-jurisdiction cloud tenant (strictly *worse* than Western-CDN
  tunneling and weaker than genuine-carrier media tunneling); B-2 → the genuine
  refraction shape, **provably non-instantiable** without an on-path cooperating
  station (strictly harder than the undeployed REDACT). The contribution worth
  publishing is the *impossibility argument itself* — that the station role is
  irreducible and a non-cooperating rendezvous cannot supply it — not a working
  system.
