# TELLTALE

**Passive zero-click / Pegasus-class implant detection for the wire.**

> *The endpoint lies. The wire remembers.*

TELLTALE moves the observation boundary off the compromised endpoint and onto the
network chokepoint — a home router, a DNS box, a passive tap — where a mercenary
implant's *unavoidable* acts leave invariants it cannot fully erase. It then makes
six weak signals testify together and **tells the tale** of what happened while the
phone showed you a clean home screen.

---

## Why the endpoint is the wrong place to look

On the device, you are losing before you start:

- **The attacker is root; you are not.** Pegasus-class implants run with more
  privilege than any user-space defender.
- **They self-destruct.** After exfiltration the implant tears itself down,
  leaving minimal forensic residue.
- **The best tools are post-mortem and lossy.** Amnesty's **MVT** and Kaspersky's
  **iShutdown** (the "sticky processes" left in `Shutdown.log`) are forensic
  autopsies — they tell you, days later, that you *were* infected, by reading
  artifacts the implant didn't bother to scrub. They cannot watch in real time,
  and a careful implant can starve them of evidence.

The endpoint is the attacker's home field. So don't play there.

## The pivot: one thing the implant cannot hide

An implant exists to **beacon** and to **exfiltrate**. Eventually it *must* talk.
And the moment it talks, it crosses a boundary it does not control — the wire —
where a few facts become observable no matter how clean the endpoint looks:

- **TLS traffic with no foreground cause** — bytes leaving while, by every
  behavioral measure, no human and no app had reason to send them.
- **A message, then a stranger** — a never-before-seen domain contacted seconds
  after an inbound iMessage/WhatsApp push. That is the literal silhouette of
  *deliver → exploit → beacon*.
- **Metronomic micro-bursts at odd hours** — a heartbeat too regular for a human
  hand, at 3am, to a host that isn't a CDN.
- **Bytes flowing the wrong way** — a steep *upstream* burst to an unnamed host.

The endpoint can lie about all of this. The wire can't — not completely.

## What TELLTALE is

A self-contained **red/blue closed loop** you can run on a laptop in one command:

- a **kill-chain simulator** that synthesizes a realistic diurnal phone *and* a
  full zero-click attack (push → novel raw-IP contact → beacon → exfil → silence),
  plus the nasty decoys that fool naive detectors;
- a **passive detection engine** that works purely on **flow metadata** — it
  never decrypts a payload — and reasons about *shape and provenance*, not
  perishable IOC lists;
- a **narrator** that renders the verdict as both a structured incident report and
  a plain-language *tale* an analyst (or a worried human) can actually read.

The same engine ingests real `.pcap` captures and JSONL flow logs from an edge
sensor (see [`deploy/`](deploy/)).

---

## Quickstart

No dependencies. No install. Just Python 3.9+:

```bash
cd TELLTALE
python3 -m telltale demo            # generate a world with a hidden implant, then hunt it
python3 -m telltale.adversary       # run the AI-driven red-team fuzzing engine to train against evasions
python3 -m telltale demo --no-implant   # same world, clean — watch the false-positive rate
python3 -m telltale demo --json     # machine-readable output for a SIEM
```

Work with real or exported data:

```bash
python3 -m telltale watch --baseline base.jsonl          # continuous streaming mode from stdin (e.g. tail -f sensor.jsonl | telltale watch)
python3 -m telltale sim --out traffic.jsonl              # export synthetic flows
python3 -m telltale analyze traffic.jsonl --baseline traffic.baseline.jsonl
python3 -m telltale analyze capture.pcap --pcap          # real capture (needs scapy)
python3 -m telltale analyze day.jsonl --train-frac 0.6   # auto time-split baseline
```

Exit code is `2` if any **CRITICAL** incident is found, `1` for **HIGH**, `0`
otherwise — drop it straight into a cron job or CI gate.

---

## The six signals

No single one convicts. A new domain is not a crime; a 60-second heartbeat is not
a crime; being awake at 3am is not a crime. TELLTALE combines them.

| # | Signal | The invariant it watches |
|---|--------|--------------------------|
| **S1** | `trigger_correlation` | an inbound messaging push, then a **novel** outbound contact within ~2 min — the zero-click silhouette |
| **S2** | `novelty` | destination provenance: never-seen, DGA-shaped, or parked on a repeatedly-burned ASN |
| **S3** | `beacon` | metronomic timing — low-jitter heartbeat (coefficient of variation under threshold) |
| **S4** | `exfil` | directional asymmetry — a steep **upstream** byte burst, or a cumulative "low-and-slow" trickle across multiple novel hosts |
| **S5** | `diurnal` | traffic during a window where the learned human rhythm says **nobody is awake** |
| **S6** | `tls_blindspot` | a handshake that refuses to name itself — no SNI / raw-IP, plus a rare JA3 |

### How they're scored

Findings combine with a **noisy-OR** (each independent witness chips away at the
probability of innocence), followed by a **corroboration gate**:

> A destination that is merely *novel* — even a novel host contacted right after a
> text — is damped to a **WATCH**. To escalate, TELLTALE demands *behavioral*
> proof (beacon / exfil / idle-timing / blind handshake). It refuses to raise an
> alarm it cannot explain.

This is what separates the implant from the **"you got a text, then tapped a
link"** confound — a sequence that looks identical to a zero-click at the packet
level, and which TELLTALE correctly leaves at WATCH while pinning the real implant
at 100/100. (Run the demo and read incidents #1 vs #2.)

### Specificity, on purpose

The demo includes a 24/7 **APNs keepalive** — periodic *and* nocturnal, the exact
profile a naive beacon detector screams about every night. TELLTALE lists it under
*"beacons I chose to ignore."* Catching the attack is easy; *not* crying wolf on
the honest infrastructure is the hard part, and the whole point.

---

## Architecture

```
   ┌─────────────────────────── the chokepoint ───────────────────────────┐
   │  router span port · DNS box · passive tap · Linux gateway (eBPF)      │
   └───────────────┬───────────────────────────────────────────────────────┘
                   │  flow metadata only (5-tuple, timing, sizes, SNI, JA3, DNS)
                   ▼
   capture/        pcap_source.py  ──►  read_pcap()  ─┐         sim.py  (the range)
   ingest                                              │            │ benign + kill chain
                                                       ▼            ▼
                                        ┌──────────  FlowRecord[]  ──────────┐
                                        ▼                                    ▼
                              baseline.py  (learn the human)        signals.py  (S1–S6)
                              · cast of known destinations          · each a single invariant
                              · diurnal rhythm (distinct dsts/hr)             │
                                        └───────────────┬────────────────────┘
                                                        ▼
                                              scorer.py  (noisy-OR + corroboration gate)
                                                        ▼
                                                  Incident[]  (ranked, explainable)
                                                        ▼
                                       narrator.py  ──►  report + "the tale"  /  --json
```

Everything is **metadata-only**. TELLTALE never sees, stores, or needs the
contents of your messages — only the *shape* of the conversation.

---

## What this is — and isn't

- **It is** a leverage-shifting *detector*: a tripwire on the one boundary the
  attacker doesn't own. It is strongest at flagging the *behavior* of an active
  implant (beaconing, exfil, post-message contact).
- **It is not** a magic oracle. A patient implant that beacons only inside busy
  daytime traffic, mimics a CDN's JA3, rides a reputable ASN, and trickle-exfils
  below the radar will raise less. TELLTALE *raises the cost* of staying hidden;
  it does not make hiding impossible.
- **It is not** an IOC blocklist. Those rot in days. TELLTALE reasons about shape
  and provenance, which an operator cannot rent away overnight.
- **Defensive only.** This is a tool to detect spyware on devices you are
  authorized to protect, from a vantage point you own. It contains no exploit, no
  implant, and no offensive capability.

## Roadmap

- JA3/JA3S and ASN rarity learned per-network rather than from static lists
- QUIC/HTTP3 ClientHello (Initial packet) parsing
- per-device baselines on multi-device home networks
- IPFIX/NetFlow and conntrack ingestion for off-the-shelf routers

The full plan — including a red-team **evasion analysis** (how a competent
operator would try to beat each signal, and the countermeasure it forces) and a
phased roadmap with an evaluation framework — lives in **[ROADMAP.md](ROADMAP.md)**.

## The name

A **telltale** is the betraying sign — Poe's heart beneath the floorboards, the
heartbeat the murderer could not silence. And **Dede Korkut**, the *ozan*, is the
teller of the true tale: the silence tried to bury the deed; the bard tells it
true. TELLTALE is both — it listens for the beat the implant cannot still, and
then it tells you what happened.

---

*Run `python3 -m telltale demo` and read the tale.*
