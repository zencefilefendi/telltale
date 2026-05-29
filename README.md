# TELLTALE

**Passive zero-click / Pegasus-class implant detection for the wire.**

> *The endpoint lies. The wire remembers.*

TELLTALE moves the observation boundary off the compromised endpoint and onto the network chokepoint — a home router, a DNS box, a passive tap, or a Zero-Trust Cellular Tunnel — where a mercenary implant's *unavoidable* acts leave invariants it cannot fully erase. 

It fuses network metadata, on-device forensic logs, and cross-device graph correlation to make eight weak signals testify together. It then **tells the tale** of what happened while the phone showed you a clean home screen.

---

## Why the endpoint is the wrong place to look

On the device, you are losing before you start:

- **The attacker is root; you are not.** Pegasus-class implants run with more privilege than any user-space defender.
- **They self-destruct.** After exfiltration, the implant tears itself down, leaving minimal forensic residue.
- **The best tools are post-mortem and lossy.** Amnesty's **MVT** and Kaspersky's **iShutdown** are forensic autopsies — they tell you, days later, that you *were* infected. They cannot watch in real time, and a careful implant can starve them of evidence.

The endpoint is the attacker's home field. So don't play there.

## The Arsenal: Intelligence-Grade Detection

TELLTALE is a completely self-contained, dependency-free (standard library only) intelligence platform. It has evolved to counter Advanced Persistent Threats (APTs) through a series of advanced architectures:

- **Robust Statistical Baselining (MAD):** Discards static thresholds (e.g., 256KB limits) in favor of dynamically learned Median Absolute Deviation (MAD). The network learns its own standard upload distributions, preventing attackers from poisoning the baseline with massive legitimate uploads to hide their exfiltration.
- **Cross-Device Graph Correlation (Herd Logic):** TELLTALE doesn't view a single phone; it views the ecosystem. It applies **Herd Immunity** (damping alerts for destinations accessed by multiple devices simultaneously) and **Herd Isolation** (amplifying alerts when a single device acts anonymously while the rest of the house sleeps).
- **Endpoint + Wire Fusion:** Ingests forensic timelines (like MVT/iShutdown). If a suspicious unnamed daemon is active on the phone at the exact second a network anomaly occurs, the two signals fuse into a definitive `CRITICAL` alert, killing "Piggybacking" evasions.
- **QUIC / HTTP3 Decryption:** Automatically derives AES-GCM keys from public Destination Connection IDs (DCID) to decrypt QUIC Initial packets over UDP/443, extracting TLS CRYPTO frames to reveal hidden SNI and JA3 fingerprints.
- **Zero-Dependency GeoIP & Network Rarity:** Downloads a lightweight TSV snapshot and uses native Binary Search (`bisect`) for lightning-fast, offline IP-to-ASN mapping. It learns what ASNs and JA3s are *statistically rare for your specific network*.

---

## The Eight Signals (S1-S8)

No single signal convicts. A new domain is not a crime; a 60-second heartbeat is not a crime; being awake at 3am is not a crime. TELLTALE combines them using a **Noisy-OR scorer** and a **Corroboration Gate**.

| # | Signal | The invariant it watches | Evasion Countermeasure |
|---|--------|--------------------------|------------------------|
| **S1** | `trigger_correlation` | An inbound messaging push, then a **novel** outbound contact within ~2 min. The zero-click silhouette. | N/A (Crown Jewel) |
| **S2** | `novelty` | Destination provenance. DGA-shaped, or parked on an ASN that is *statistically rare for this specific network*. | Defeats Infrastructure Laundering. |
| **S3** | `beacon` | Metronomic timing. Low-jitter heartbeat using frequency/autocorrelation. | Defeats artificial Poisson jitter. |
| **S4** | `exfil` | **Cumulative Sliding Window Bucket**. Tracks low-and-slow trickles across multiple rotating IPs using MAD thresholds. | Defeats 250KB threshold gaming. |
| **S5** | `diurnal` | Causeless traffic. Network activity during a window where the learned human rhythm says **nobody is awake**. | Defeats naive scheduling. |
| **S6** | `tls_blindspot` | A handshake that refuses to name itself (no SNI / raw-IP / QUIC decryption). | Defeats basic ECH/QUIC masking. |
| **S7** | `herd_isolation` | Only ONE device on the network is active at a highly idle hour, contacting a unique novel destination. | Proves non-human automation. |
| **S8** | `c2_over_messenger` | Extreme volumetric anomaly (e.g., 95% upstream burst) to a trusted messaging channel (APNs, WhatsApp) at idle hours. | Defeats C2 tunneled through Apple/Meta. |

---

## Quickstart & Usage

No heavy dependencies (Scapy is only required for reading raw PCAPs). Requires Python 3.9+.

```bash
# 1. Run the AI-driven red-team fuzzing engine to watch the attacker adapt
python3 -m telltale.adversary       

# 2. Generate a synthetic world with a hidden implant, then hunt it
python3 -m telltale demo            

# 3. Continuous streaming mode from stdin (Live Analysis)
tail -f sensor.jsonl | python3 -m telltale watch --baseline base.jsonl

# 4. Analyze exported flows with Endpoint Fusion (MVT)
python3 -m telltale analyze traffic.jsonl --endpoint-log mvt_timeline.json

# 5. Analyze real raw network captures
python3 -m telltale analyze capture.pcap --pcap          
```

Exit code is `2` if any **CRITICAL** incident is found, `1` for **HIGH**, `0` otherwise — perfect for CI/CD gates or Cron jobs.

---

## Red-Team Fuzzing Engine (`adversary.py`)

TELLTALE includes a built-in genetic algorithm (`telltale/adversary.py`) acting as a highly adaptive APT implant. It constantly mutates its own configuration (trigger delays, beacon intervals, domain masking, and exfiltration chunking) to try and beat the scorer. 

This **Adversarial Training** loop ensures that as the attacker adapts, TELLTALE's thresholds and logic remain mathematically sound. Run it to watch an implant try—and fail—to keep its score below the radar.

---

## Deployment: Eliminating the Cellular Blindspot

When a target drops off Wi-Fi and connects to 5G, the network chokepoint is lost. TELLTALE solves this with a **Zero-Trust Cellular Tunneling** architecture.

Inside the `deploy/` folder is `vpn_tunnel.sh`, an automated WireGuard deployment script. It generates an "Always-On" VPN profile for iOS/Android that forcibly routes **only DNS and traffic metadata (headers)** back to the TELLTALE sensor, while the payloads are NAT'd directly to the internet for privacy. 

```bash
cd deploy
chmod +x vpn_tunnel.sh
./vpn_tunnel.sh <YOUR_SERVER_PUBLIC_IP> 51820
```

*The endpoint lies. The wire remembers.*
