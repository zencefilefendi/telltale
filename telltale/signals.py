"""
TELLTALE — the six detectors.

Each detector watches a single invariant the implant cannot rent or root its way
out of. Alone, each is weak and false-positive-prone. The scorer's job is to make
them testify together; this module's job is to make each one honest.

  S1  trigger_correlation  an inbound message, then a never-seen outbound seconds
                           later — the deliver -> exploit -> beacon silhouette.
  S2  novelty              the destination's provenance: unknown, DGA-shaped, or
                           parked on a repeatedly-burned ASN.
  S3  beacon               metronomic timing — a heartbeat with low jitter.
  S4  exfil                bytes flowing the wrong way: a steep upstream burst.
  S5  diurnal              traffic with no human awake to cause it.
  S6  tls_blindspot        a handshake that refuses to name itself (no SNI, rare JA3).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .baseline import Baseline
from .intel import asn_trust, domain_novelty_features
from .model import Finding, FlowRecord, clamp, coefficient_of_variation

# --- tunables (documented so an operator can reason about each) ---------------
TRIGGER_WINDOW_S = 120.0      # zero-click contact usually lands within ~2 min
BEACON_MIN_HITS = 4           # need a few beats before "rhythm" means anything
BEACON_CV_MAX = 0.35          # std/mean below this = suspiciously regular
EXFIL_UP_RATIO = 0.80         # 80%+ of bytes going *up* is the wrong direction
EXFIL_TRICKLE_WINDOW_S = 4 * 3600 # 4-hour sliding window to catch slow, multi-IP exfiltration
IDLE_ALARM = 0.60             # diurnal idle score above which "nobody's awake"


# ---------------------------------------------------------------------------
def cluster_by_dst(flows: List[FlowRecord]) -> Dict[str, List[FlowRecord]]:
    clusters: Dict[str, List[FlowRecord]] = defaultdict(list)
    for f in flows:
        clusters[f.dst_key()].append(f)
    for k in clusters:
        clusters[k].sort(key=lambda x: x.ts)
    return clusters


# --- S1: trigger correlation -------------------------------------------------
def trigger_correlations(flows: List[FlowRecord], baseline: Baseline) -> List[dict]:
    """Find inbound pushes immediately followed by a novel outbound flow.

    This is the crown jewel: it converts two innocent-looking events into one
    guilty story. The push is normal. The novel flow is suspicious. The *causal
    proximity* between them is the zero-click fingerprint.
    """
    pushes = sorted(
        (f for f in flows if f.inbound_push), key=lambda x: x.ts
    )
    novel_out = sorted(
        (f for f in flows if not f.inbound_push and baseline.is_novel(f)),
        key=lambda x: x.ts,
    )
    links: List[dict] = []
    for nf in novel_out:
        best = None
        for p in pushes:
            dt = nf.ts - p.ts
            if 0.0 <= dt <= TRIGGER_WINDOW_S:
                if best is None or dt < best[1]:
                    best = (p, dt)
            elif p.ts > nf.ts:
                break
        if best:
            p, dt = best
            links.append({
                "push": p, "novel": nf, "dt": dt,
                "service": p.push_service or "unknown courier",
            })
    return links


# --- S2: novelty (provenance) ------------------------------------------------
def novelty_findings(clusters: Dict[str, List[FlowRecord]],
                     baseline: Baseline) -> Dict[str, Finding]:
    out: Dict[str, Finding] = {}
    for key, fl in clusters.items():
        f0 = fl[0]
        if not baseline.is_novel(f0):
            continue
        score, reasons = 0.0, []
        score += 0.40
        reasons.append("destination never seen during the baseline window")

        feats = domain_novelty_features(f0.domain, f0.dst_ip)
        if feats["dga_like"]:
            score += 0.30
            reasons.append(f"DGA-like name (entropy {feats['entropy']}, vowel-poor)")

        t = asn_trust(f0.asn)
        if t <= 0.15:
            score += 0.35
            reasons.append(f"parked on a repeatedly-burned ASN "
                           f"(AS{f0.asn} {f0.asn_name or ''})".strip())
        elif t <= 0.40:
            score += 0.15
            reasons.append(f"generic VPS/colo hosting (AS{f0.asn} {f0.asn_name or ''})".strip())
        elif baseline.is_rare_asn(f0.asn):
            score += 0.20
            reasons.append(f"hosted on an ASN previously unseen on this network "
                           f"(AS{f0.asn} {f0.asn_name or ''})".strip())

        out[key] = Finding(
            signal="novelty", dst=key, weight=clamp(score),
            reason="; ".join(reasons), ts=f0.ts,
            evidence={"asn": f0.asn, "domain": f0.domain, "ip": f0.dst_ip},
        )
    return out


# --- S3: beacon (temporal regularity) ---------------------------------------
def beacon_scan(clusters: Dict[str, List[FlowRecord]]) -> Dict[str, dict]:
    """Return periodicity stats for every cluster (known-good included).

    The scorer alarms on regular beats to *unknown* hosts; the narrator uses the
    known-good ones to prove TELLTALE isn't naive (e.g. nocturnal APNs keepalive).
    """
    info: Dict[str, dict] = {}
    for key, fl in clusters.items():
        if len(fl) < BEACON_MIN_HITS:
            continue
        ts = [f.ts for f in fl]
        deltas = [b - a for a, b in zip(ts, ts[1:]) if b > a]
        if len(deltas) < BEACON_MIN_HITS - 1:
            continue
        cv = coefficient_of_variation(deltas)
        deltas_sorted = sorted(deltas)
        period = deltas_sorted[len(deltas_sorted) // 2]  # median, jitter-robust
        regular = cv <= BEACON_CV_MAX
        from .intel import is_known_good
        info[key] = {
            "period": period, "cv": round(cv, 3), "hits": len(fl),
            "regular": regular, "known_good": is_known_good(fl[0]),
        }
    return info


def beacon_findings(beacons: Dict[str, dict]) -> Dict[str, Finding]:
    out: Dict[str, Finding] = {}
    for key, b in beacons.items():
        if not b["regular"] or b["known_good"]:
            continue
        # tighter rhythm + more beats => more confidence
        weight = clamp(0.55 + (BEACON_CV_MAX - b["cv"]) + 0.03 * (b["hits"] - 4))
        out[key] = Finding(
            signal="beacon", dst=key, weight=weight,
            reason=(f"metronomic heartbeat every ~{b['period']:.0f}s "
                    f"(jitter CV={b['cv']}, {b['hits']} beats)"),
            evidence=b,
        )
    return out


# --- S4: exfil (directional asymmetry) --------------------------------------
def exfil_findings(clusters: Dict[str, List[FlowRecord]],
                   baseline: Baseline) -> Dict[str, Finding]:
    out: Dict[str, Finding] = {}
    
    # 1. Traditional single-burst detection
    for key, fl in clusters.items():
        if not baseline.is_novel(fl[0]):
            continue
        top = max(fl, key=lambda f: f.bytes_up)
        if top.bytes_up >= baseline.exfil_threshold and top.up_ratio >= EXFIL_UP_RATIO:
            size_factor = clamp((top.bytes_up - baseline.exfil_threshold) / (4 * 1024 * 1024))
            weight = clamp(0.5 + 0.3 * (top.up_ratio - 0.5) / 0.5 + 0.2 * size_factor)
            mb = top.bytes_up / (1024 * 1024)
            out[key] = Finding(
                signal="exfil", dst=key, weight=weight,
                reason=(f"{mb:.2f} MB pushed UPSTREAM ({top.up_ratio*100:.0f}% of bytes) "
                        f"in a single burst to a novel host — the wrong direction for a download"),
                ts=top.ts, evidence={"bytes_up": top.bytes_up, "bytes_down": top.bytes_down, "type": "burst"},
            )

    # 2. Cumulative "Trickle" Exfil detection across ALL novel hosts
    novel_flows: List[FlowRecord] = []
    for fl in clusters.values():
        if fl and baseline.is_novel(fl[0]):
            novel_flows.extend(fl)
    novel_flows.sort(key=lambda f: f.ts)
    
    window_start = 0
    cumul_up = 0
    cumul_down = 0
    
    # Track which clusters participated in a trickle breach, and the max bucket size they saw
    trickle_complicity: Dict[str, dict] = {}
    
    for i, f in enumerate(novel_flows):
        cumul_up += f.bytes_up
        cumul_down += f.bytes_down
        
        while window_start <= i and (f.ts - novel_flows[window_start].ts) > EXFIL_TRICKLE_WINDOW_S:
            cumul_up -= novel_flows[window_start].bytes_up
            cumul_down -= novel_flows[window_start].bytes_down
            window_start += 1
            
        cumul_ratio = cumul_up / max(1, cumul_up + cumul_down)
        
        # If the window overall breaches the exfil threshold
        if cumul_up >= baseline.exfil_threshold and cumul_ratio >= EXFIL_UP_RATIO:
            # All novel flows within this window are complicit
            unique_hosts = len({novel_flows[k].dst_key() for k in range(window_start, i + 1)})
            for j in range(window_start, i + 1):
                complicit_key = novel_flows[j].dst_key()
                # Skip if already caught by the single-burst detector
                if complicit_key in out:
                    continue
                if complicit_key not in trickle_complicity or cumul_up > trickle_complicity[complicit_key]["cumul_up"]:
                    trickle_complicity[complicit_key] = {
                        "cumul_up": cumul_up,
                        "ratio": cumul_ratio,
                        "ts": f.ts,
                        "hosts": unique_hosts
                    }

    # Generate findings for clusters caught only by the trickle detector
    for key, stats in trickle_complicity.items():
        cumul_up = stats["cumul_up"]
        mb = cumul_up / (1024 * 1024)
        size_factor = clamp((cumul_up - baseline.exfil_threshold) / (4 * 1024 * 1024))
        weight = clamp(0.4 + 0.3 * (stats["ratio"] - 0.5) / 0.5 + 0.2 * size_factor)
        out[key] = Finding(
            signal="exfil", dst=key, weight=weight,
            reason=(f"participated in a {mb:.2f} MB cumulative trickle-exfil "
                    f"({stats['ratio']*100:.0f}% up) spread across {stats['hosts']} novel hosts"),
            ts=stats["ts"], evidence={"cumul_bytes_up": cumul_up, "type": "trickle"}
        )

    return out


# --- S5: diurnal (no human awake) -------------------------------------------
def diurnal_findings(clusters: Dict[str, List[FlowRecord]],
                     baseline: Baseline) -> Dict[str, Finding]:
    out: Dict[str, Finding] = {}
    for key, fl in clusters.items():
        if not baseline.is_novel(fl[0]):
            continue
        worst = max(fl, key=lambda f: baseline.idle_score(f.ts))
        idle = baseline.idle_score(worst.ts)
        if idle < IDLE_ALARM:
            continue
        out[key] = Finding(
            signal="diurnal", dst=key, weight=clamp(idle),
            reason=(f"activity at an idle hour (idle score {idle:.2f}) — the "
                    f"diurnal baseline says no human is generating traffic now"),
            ts=worst.ts, evidence={"idle_score": idle},
        )
    return out


# --- S7: herd_isolation (cross-device graph correlation) -------------------
def herd_findings(clusters: Dict[str, List[FlowRecord]],
                  all_flows: List[FlowRecord],
                  baseline: Baseline) -> Dict[str, Finding]:
    out: Dict[str, Finding] = {}
    devices_present = {f.device for f in all_flows if f.device}
    if len(devices_present) < 2:
        return out # Herd logic requires at least 2 distinct devices

    for key, fl in clusters.items():
        if not baseline.is_novel(fl[0]):
            continue

        touching_devices = {f.device for f in fl if f.device}
        if len(touching_devices) > 1:
            continue # Handled by Herd Immunity dampener in scorer.py

        dev = list(touching_devices)[0] if touching_devices else "?"
        
        worst = max(fl, key=lambda f: baseline.idle_score(f.ts))
        idle = baseline.idle_score(worst.ts)

        if idle < IDLE_ALARM:
            continue

        # Check if other devices were active in a +/- 15 minute window
        window_start = worst.ts - 900
        window_end = worst.ts + 900

        active_in_window = {
            f.device for f in all_flows
            if window_start <= f.ts <= window_end and not baseline.is_known_good(f) and f.device
        }

        # If this device is the ONLY one doing non-background/novel things
        if active_in_window == {dev}:
            out[key] = Finding(
                signal="herd_isolation", dst=key, weight=0.35,
                reason=(f"herd isolation — '{dev}' is the only device active on the network "
                        f"during an idle hour, contacting a unique novel destination"),
                ts=worst.ts, evidence={"idle_score": idle, "total_network_devices": len(devices_present)}
            )
    return out
def tls_findings(clusters: Dict[str, List[FlowRecord]],
                 baseline: Baseline) -> Dict[str, Finding]:
    out: Dict[str, Finding] = {}
    for key, fl in clusters.items():
        if not baseline.is_novel(fl[0]):
            continue
        f0 = fl[0]
        is_tls = f0.dport in (443, 5223, 8443) or f0.proto == "quic"
        if not is_tls:
            continue
        score, reasons = 0.0, []
        if not f0.has_sni and f0.domain is None:
            score += 0.5
            reasons.append("TLS ClientHello carries no SNI (anonymous destination)")
        if baseline.is_rare_ja3(f0.ja3):
            score += 0.4
            reasons.append(f"rare TLS client fingerprint (JA3 {(f0.ja3 or '')[:12]}…)")
        if not reasons:
            continue
        out[key] = Finding(
            signal="tls_blindspot", dst=key, weight=clamp(score),
            reason="; ".join(reasons), ts=f0.ts,
            evidence={"sni": f0.sni, "ja3": f0.ja3},
        )
    return out
