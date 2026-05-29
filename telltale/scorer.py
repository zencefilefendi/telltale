"""
TELLTALE — the scorer: making weak witnesses testify together.

No single signal convicts. A new domain is not a crime; a 60-second heartbeat is
not a crime; an upstream burst is not a crime; being awake at 3am is not a crime.
The scorer combines them with a noisy-OR — each independent witness chips away at
the probability of innocence — and then demands *corroboration*: an identity-only
hit (just a novel name) is damped to a WATCH, because TELLTALE refuses to raise an
alarm it cannot explain with behavior.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .baseline import Baseline
from .model import Finding, FlowRecord, Incident, clamp
from .signals import (
    TRIGGER_WINDOW_S,
    beacon_findings,
    beacon_scan,
    cluster_by_dst,
    diurnal_findings,
    exfil_findings,
    herd_findings,
    novelty_findings,
    tls_findings,
    trigger_correlations,
)

# Behavioral/identity evidence that a contact is machine-driven. The trigger
# correlation is a powerful *amplifier* but deliberately NOT a corroborator: a
# benign iMessage you read, then a link you tapped, is also "push -> novel host."
# Only beacon/exfil/diurnal/tls-blindspot/herd_isolation prove the contact had no human shape.
CORROBORATING = {"beacon", "exfil", "diurnal", "tls_blindspot", "herd_isolation"}


@dataclass
class AnalysisResult:
    incidents: List[Incident]
    suppressed: List[dict] = field(default_factory=list)
    stats: dict = field(default_factory=dict)


def _combine(findings: List[Finding]) -> float:
    """Noisy-OR over independent witnesses, with a corroboration gate."""
    prod = 1.0
    for f in findings:
        prod *= (1.0 - clamp(f.weight))
    raw = 1.0 - prod
    corroboration = len({f.signal for f in findings} & CORROBORATING)
    if corroboration == 0:
        # No behavioral proof — just a novel name (possibly after a push). Damp
        # hard: this is the "tapped a link after a text" confound, not an implant.
        raw *= 0.40
    return round(min(100.0, raw * 100.0), 1)


def _incident_id(dst: str) -> str:
    return "INC-" + hashlib.sha1(dst.encode()).hexdigest()[:6].upper()


def _build_timeline(inc: Incident, flows: List[FlowRecord],
                    beacon: Optional[dict], link: Optional[dict],
                    exfil: Optional[Finding]) -> None:
    if link:
        p = link["push"]
        inc.mark(p.ts, "INBOUND PUSH",
                 f"{link['service']} delivery to device — innocuous in isolation")
    if flows:
        first = flows[0]
        asn = f"AS{first.asn} {first.asn_name or ''}".strip()
        ip_part = "" if inc.dst == first.dst_ip else f"{first.dst_ip}, "
        inc.mark(first.ts, "NOVEL CONTACT",
                 f"first-ever outbound to {inc.dst} ({ip_part}{asn})")
    if beacon and beacon.get("regular") and not beacon.get("known_good"):
        inc.mark(flows[0].ts + beacon["period"], "BEACON",
                 f"heartbeat established · ~{beacon['period']:.0f}s cadence · "
                 f"{beacon['hits']} beats · jitter CV {beacon['cv']}")
    if exfil:
        inc.mark(exfil.ts, "EXFIL", exfil.reason)
    if flows:
        detail = ("destination falls quiet — the shape of post-exfil cleanup"
                  if exfil else "last seen — destination goes quiet")
        inc.mark(flows[-1].ts, "SILENCE", detail)
    inc.timeline.sort(key=lambda x: x[0])


def analyze(baseline: Baseline, flows: List[FlowRecord]) -> AnalysisResult:
    flows = sorted(flows, key=lambda f: f.ts)
    clusters = cluster_by_dst(flows)

    nov = novelty_findings(clusters, baseline)
    beacons = beacon_scan(clusters)
    bfind = beacon_findings(beacons)
    exf = exfil_findings(clusters, baseline)
    diu = diurnal_findings(clusters, baseline)
    tls = tls_findings(clusters, baseline)
    herd = herd_findings(clusters, flows, baseline)

    links = trigger_correlations(flows, baseline)
    link_by_dst: Dict[str, dict] = {}
    for l in links:
        k = l["novel"].dst_key()
        if k not in link_by_dst or l["dt"] < link_by_dst[k]["dt"]:
            link_by_dst[k] = l

    candidates = set(nov) | set(bfind) | set(exf) | set(diu) | set(tls) | set(link_by_dst) | set(herd)
    incidents: List[Incident] = []

    for k in candidates:
        fl = clusters.get(k, [])
        findings: List[Finding] = []
        for src in (nov, bfind, exf, diu, tls, herd):
            if k in src:
                findings.append(src[k])

        link = link_by_dst.get(k)
        if link:
            dt = link["dt"]
            w = clamp(0.60 + 0.30 * (1.0 - dt / TRIGGER_WINDOW_S))
            findings.append(Finding(
                signal="trigger_correlation", dst=k, weight=w,
                reason=(f"novel contact only {dt:.0f}s after an inbound "
                        f"{link['service']} push — the zero-click silhouette"),
                ts=link["novel"].ts,
                evidence={"dt": dt, "service": link["service"]},
            ))

        if not findings:
            continue

        score = _combine(findings)
        
        # Herd Immunity Dampener
        touching_devices = {f.device for f in fl if f.device}
        shared_by = len(touching_devices)
        if shared_by > 1 and score > 0:
            score = round(score * 0.30, 1) # Dampen risk heavily if shared across network
            
        inc = Incident(
            incident_id=_incident_id(k),
            device=", ".join(sorted(touching_devices)) if touching_devices else "?",
            dst=k, score=score, findings=findings,
        )
        if link:
            inc.trigger_ts = link["push"].ts
            inc.trigger_service = link["service"]
        _build_timeline(inc, fl, beacons.get(k), link, exf.get(k))
        
        if shared_by > 1:
            inc.mark(fl[0].ts, "HERD IMMUNITY", f"destination accessed independently by {shared_by} distinct devices on this network; risk heavily damped")
            inc.timeline.sort(key=lambda x: x[0])
            
        incidents.append(inc)

    incidents.sort(key=lambda i: -i.score)

    suppressed = [
        {"dst": k, **b}
        for k, b in beacons.items()
        if b.get("regular") and b.get("known_good")
    ]

    stats = {
        "total_flows": len(flows),
        "destinations": len(clusters),
        "novel_destinations": sum(1 for k in clusters if baseline.is_novel(clusters[k][0])),
        "incidents": len(incidents),
        "critical": sum(1 for i in incidents if i.verdict == "CRITICAL"),
        "suppressed_known_good": len(suppressed),
        "idle_profile": baseline.profile_sparkline(),
    }
    return AnalysisResult(incidents=incidents, suppressed=suppressed, stats=stats)
