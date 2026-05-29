# TELLTALE — Design Notes & Roadmap

*A working journal of what we built, why it works, how an attacker would try to
beat it, and where we go next. Read this as the technical companion to the
[README](README.md): the README sells the idea, this document defends it.*

---

## Part I — What we built

### The one-sentence thesis

The endpoint is the attacker's home field (they're root, they self-destruct,
forensics are post-mortem and lossy). The wire is not. An implant **must**
eventually beacon and exfiltrate, and the moment it does it crosses a boundary it
doesn't own — where a handful of invariants become observable no matter how clean
the phone looks. **Move the observer to the chokepoint and make those invariants
testify.**

### Capability matrix (today)

| Capability | Status | Where |
|---|---|---|
| Metadata-only flow model (no payload, ever) | ✅ done | [`model.py`](telltale/model.py) |
| Threat intel: couriers, ASN reputation, domain provenance | ✅ done | [`intel.py`](telltale/intel.py) |
| Behavioral baseline: known-dst set + diurnal rhythm | ✅ done | [`baseline.py`](telltale/baseline.py) |
| Six detection signals (S1–S6) | ✅ done | [`signals.py`](telltale/signals.py) |
| Cumulative Trickle Exfil Budget (S4) | ✅ done | [`signals.py`](telltale/signals.py) |
| Noisy-OR scorer + corroboration gate | ✅ done | [`scorer.py`](telltale/scorer.py) |
| Explainable incident report + "the tale" | ✅ done | [`narrator.py`](telltale/narrator.py) |
| Zero-click kill-chain simulator + decoys | ✅ done | [`sim.py`](telltale/sim.py) |
| Adaptive Red-Team Fuzzing Engine | ✅ done | [`adversary.py`](telltale/adversary.py) |
| Real pcap ingestion (SNI + spec-correct JA3) | ✅ done | [`pcap_source.py`](telltale/pcap_source.py) |
| CLI: `demo` / `sim` / `analyze` (+ JSON, exit codes) | ✅ done | [`cli.py`](telltale/cli.py) |
| Behavioral test suite (6/6) | ✅ done | [`tests/`](tests/test_detection.py) |
| Edge deployment guide + bpftrace sensor sketch | ✅ done | [`deploy/`](deploy/README.md) |
| Live streaming analysis | ✅ done | [`stream.py`](telltale/stream.py) |
| QUIC / HTTP3 ClientHello parsing | ✅ done | [`quic_crypto.py`](telltale/quic_crypto.py) |
| Per-network learned rarity (JA3/ASN), GeoIP enrichment | ✅ done | [`enrich.py`](telltale/enrich.py) |
| Statistical / ML baselining | ✅ done | [`baseline.py`](telltale/baseline.py) |
| Cross-device graph correlation | ⛔ roadmap | Phase 2 |
| Endpoint+wire fusion (MVT/iVerify) | ⛔ roadmap | Phase 3 |

### The six signals, and what each one *actually* costs the attacker

| # | Signal | Invariant | Attacker cost to evade |
|---|---|---|---|
| S1 | `trigger_correlation` | inbound push → novel outbound in ~2 min | must decouple exploit delivery from first contact (delay/queue beacon) |
| S2 | `novelty` | unknown / DGA / burned-ASN destination | must pre-age domains and rent reputable hosting |
| S3 | `beacon` | low-jitter heartbeat | must randomize cadence *and* break autocorrelation |
| S4 | `exfil` | steep upstream burst | must trickle below a moving budget |
| S5 | `diurnal` | traffic with no human awake | must piggyback only on real user activity |
| S6 | `tls_blindspot` | handshake that won't name itself | must mimic a popular, named TLS profile |

The scoring philosophy is the product, not any one signal: **noisy-OR** combines
independent witnesses, and a **corroboration gate** refuses to escalate on
identity alone. That single rule is why the *"got a text, then tapped a link"*
confound stays at WATCH while the real implant pins at 100/100 — they are
identical at the packet level and only separable by *behavior*.

### What the demo proves

`python3 -m telltale demo` builds a synthetic-but-realistic world and shows:

1. **Sensitivity** — the full kill chain (push → raw-IP contact → 60s beacon →
   2 MB upstream → silence) is caught and *narrated*.
2. **Specificity** — a nocturnal APNs keepalive (periodic + at 3am, the classic
   false positive) is explicitly *suppressed*, and the link-tap confound is held
   at WATCH.

A detector that only did #1 would be useless in production. #2 is the hard part,
and it's the part most "anomaly detection" demos quietly skip.

### Honest limitations (current build)

- **Static intel.** ASN reputation and known-good suffixes are hand-curated lists.
  They're a thumb on the scale, not learned per-network (yet).
- **No volume model for known-good.** We suppress beacons to allowlisted hosts
  wholesale; a C2 *relayed through* a legitimate CDN would currently hide there.
- **DNS/SNI dependence.** S1/S6 lean on seeing DNS names or plaintext SNI. DoH and
  Encrypted ClientHello (ECH) erode that visibility (see Part II).
- **Threshold-based exfil.** A fixed 256 KB / 80%-upstream trigger is trivially
  undercut by low-and-slow trickle.
- **Single-device, file-at-a-time.** No streaming, no cross-device graph yet.

These aren't embarrassments — they're the roadmap.

---

## Part II — Threat model & evasion analysis (think red)

This is the section that matters. A detector is only as good as its answer to
*"what does a competent operator do when they know TELLTALE is watching?"* For
each evasion we name the signal it defeats and the countermeasure it forces.

### A1 — Infrastructure laundering (defeats S2)
**Move:** pre-age domains for months, rent reputable ASNs (or relay through
Cloudflare Workers / a hijacked first-party site) so novelty + ASN reputation read
clean.
**Counter:** shift novelty from *static lists* to *per-network first-party
modeling* — "this device has never spoken to this CDN tenant before" is novel even
inside Cloudflare. Add passive-DNS age and certificate-transparency freshness as
features. Volume/behavior anomalies survive even when reputation is clean.

### A2 — TLS fingerprint mimicry (defeats S6)
**Move:** use uTLS / a real Safari/Chrome stack so JA3 matches the herd; rely on
GREASE + randomized extension order to make JA3 itself unstable.
**Counter:** migrate JA3 → **JA4/JA4+** (order-insensitive, far harder to spoof in
bulk), weight **JA3S** (server side is harder to randomize), and treat the *match*
itself as weak — let behavior carry the verdict. A perfect Safari fingerprint on a
flow with no Safari-shaped traffic around it is still anomalous.

### A3 — Encrypted ClientHello / DoH (erodes S1, S6)
**Move:** ECH hides SNI; DNS-over-HTTPS hides resolutions. The "novel domain after
a text" and "no SNI" signals lose their raw inputs.
**Counter:** detect **the presence of ECH/DoH** as a feature in its own right,
pivot from *names* to *IP/endpoint novelty + timing*, and model the DoH resolver
relationship (a resolution still *happened*; we just time it instead of reading
it). This is a visibility arms race we plan for, not pretend away.

### A4 — Beacon de-synchronization (defeats S3)
**Move:** randomize cadence (uniform/poisson jitter), add cover traffic, beacon
only on a schedule tied to user activity.
**Counter:** autocorrelation/FFT over **long horizons** (bounded randomness still
leaves spectral structure), plus the orthogonal question S3 can't be tricked out
of: *was there an app reason for any of these connections at all?* Regularity is
one tell; **causelessness** is the deeper one.

### A5 — Low-and-slow exfil (defeats S4)
**Move:** trickle data in small chunks spread over days, each below threshold.
**Counter (✅ Implemented):** replaced the fixed threshold with a **cumulative sliding window budget**, tracking total novel upstream across all unknown IPs simultaneously. 20 KB to 10 rotating Hetzner IPs every hour all night, summed together, now breaches the cumulative S4 threshold and catches the entire complicit cluster.

### A6 — Activity piggybacking (defeats S5, the hardest)
**Move:** beacon and exfil *only* while the user is actively using apps, hiding in
the diurnal peak.
**Counter:** this is where single-signal detection ends and **per-app/per-flow
attribution** + **graph correlation** begin. Novelty (S2) and the trigger
silhouette (S1) still hold; and on a host sensor, process context (`comm`) answers
"foreground app?" directly. Honest assessment: a patient, activity-gated implant
is the residual risk TELLTALE shrinks but does not eliminate.

### A7 — C2 over the messenger's own channel
**Move:** exfil *through* iMessage/WhatsApp servers themselves — perfect blending.
**Counter:** very hard from the wire alone. Look for **volumetric anomalies on the
messaging channel** (sustained upload to APNs/WA infra is abnormal for a chat app)
and fuse with endpoint signals (Part III, Phase 3). This is the strongest argument
for *not* treating the wire as the only sensor.

> **Design takeaway:** every evasion above trades stealth for *cost, latency, or
> bandwidth*. TELLTALE's job is not to make hiding impossible — it's to make it
> expensive and slow enough that the operator's economics break. That is the
> realistic win condition for a passive detector.

---

## Part III — Roadmap

### Phase 1 — Sharpen the edge (near-term)
- **Packet Length Sequence (PLS) Analysis.** Beyond QUIC/HTTP3 Initial packets, profile the size and direction of the first 10-15 packets of a flow. Even under Encrypted ClientHello (ECH), the "handshake geometry" of Safari differs from `curl` or a custom C2 implant.
- **eBPF Process Context Fusion (Companion App).** A lightweight companion app on the endpoint that merely broadcasts UDP syslogs of outbound process metadata (`PID`, `Comm`) to the wire sensor. Correlates wire activity directly to legitimate foreground apps (WhatsApp, Safari) versus isolated background anomalies.

### Phase 2 — From rules to models (mid-term)
- **Time-Series Autocorrelation (FFT / Lomb-Scargle).** Upgrade the beacon detector (S3) beyond simple coefficient of variation (CV). Use signal processing to find rhythmic "spikes" in the frequency spectrum, defeating adversaries who inject artificial Poisson jitter into their heartbeats.
- **Causelessness Model (Defeating Piggybacking).** Detect implants that only beacon while the user actively browses (A6 Piggybacking). Model the "ecosystem profile" of apps (e.g., WhatsApp traffic should strictly go to Meta ASNs). Flag asymmetric flows to unknown VPS ASNs that occur *concurrently* with legitimate app usage.
- **Cross-device "Guilt by Association".** Correlate device behavior across the home network. If 3 phones are asleep at 03:00, but only *one* is reaching out to a novel, unverified destination, exponentially increase its risk score. Use the clean herd to expose the infected outlier.

### Phase 3 — Fusion & Active Hunting (long-term)
- **"C2 over Messenger" Detection.** Defeat attackers exfiltrating data directly through WhatsApp/iMessage servers (A7). Baseline the volumetric geometry of the messaging channel (short up, short down). Trigger alerts on sustained 95% upstream ratios to known-good couriers during idle hours.
- **Zero-Trust Cellular Tunneling (Always-On VPN).** Eliminate the cellular blindspot. Route all mobile DNS and metadata (headers only) via WireGuard/IPsec back to the TELLTALE chokepoint when the device leaves the Wi-Fi boundary.
- **Endpoint+wire fusion.** Ingest MVT / iVerify / iShutdown findings and fuse with wire incidents.

---

## Part IV — Engineering hardening (cross-cutting)

- **Packaging:** `pyproject.toml`, `pip install telltale`, console entry point.
- **Quality:** type hints + `mypy`, `ruff`, CI (GitHub Actions running the test
  suite + a lint gate) on every push.
- **Performance:** validate flow assembly at line rate on realistic captures;
  profile the scorer for 10⁶+ flows/day.
- **Sensor hardening:** run the analyzer off-device; baseline on read-only media;
  signed flow logs for IR (see [`deploy/`](deploy/README.md)).
- **Data hygiene:** explicit retention limits; metadata-only is the contract,
  enforce it in code (no payload field exists, by design).

---

## Part V — How we'll know it works (evaluation)

A roadmap without a scoreboard is a wishlist. We will measure:

- **Detection rate (TPR)** against an evasion-laddered corpus (A1→A7 difficulty),
  not just the easy kill chain.
- **False-positive rate (FPR)** against long benign captures — the number that
  decides whether anyone keeps the tool running.
- **ROC / AUC** as thresholds move, and **time-to-detect** from first beacon.
- **Explainability audit:** every escalation must produce a human-readable cause
  (the "tale"); an alert nobody can act on is noise.
- A reusable, **labeled benchmark dataset** (synthetic-first via `sim.py`, then
  real captures) so progress is comparable across versions.

Target posture: maximize TPR on A1–A5 while holding FPR low enough for an
unattended home/SOC deployment; treat A6/A7 as explicitly *fusion-dependent* and
report them honestly rather than overclaim.

---

## Part VI — Non-goals (what TELLTALE will never be)

- **Not an offensive tool.** No exploit, no implant, no C2. A shield only.
- **Not an IOC feed.** Provenance and behavior over perishable indicator lists.
- **Not a payload inspector.** Metadata-only is a feature, not a limitation — it's
  what makes the tool deployable without becoming a wiretap.
- **Not a silver bullet.** It raises the attacker's cost; it does not make
  mercenary spyware impossible. Honesty about that is part of the design.

---

*The endpoint lies. The wire remembers. This document is how we make sure it keeps
remembering as the attacker adapts.*
