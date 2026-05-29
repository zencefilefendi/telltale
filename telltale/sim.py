"""
TELLTALE — the range: a synthetic world to prove detection on.

You cannot download a Pegasus pcap from a vendor, and you should not need to. The
behaviors TELLTALE keys on are structural, so we can *generate* them: a realistic
diurnal phone, an honest 24/7 APNs keepalive (the nocturnal-but-benign decoy), a
couple of benign "new domains" a person legitimately visits, the notorious
"text-then-tapped-a-link" confound, and — on the detection day — a full zero-click
kill chain: inbound push -> novel raw-IP contact -> metronomic beacon -> upstream
exfil -> silence.

A detector that lights up on the kill chain while staying calm on the decoys is a
detector you can trust on real wire.
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import List, Tuple

from .model import FlowRecord

# Honest, well-known infrastructure (domain, asn, asn_name).
KNOWN = [
    ("instagram.com", 32934, "Meta"),
    ("scontent.cdninstagram.com", 32934, "Meta"),
    ("www.google.com", 15169, "Google"),
    ("googleapis.com", 15169, "Google"),
    ("gateway.icloud.com", 714, "Apple"),
    ("p25-content.icloud.com", 714, "Apple"),
    ("g.whatsapp.net", 32934, "Meta"),
    ("api.spotify.com", 16509, "Amazon"),
    ("nflxvideo.net", 2906, "Netflix"),
    ("youtubei.googleapis.com", 15169, "Google"),
]
APNS = ("courier.push.apple.com", 714, "Apple")

# A small set of ordinary TLS client fingerprints, well-represented in baseline.
NORMAL_JA3 = ["t13d1516h2_8daaf6152771", "t13d1517h2_5b57614c22b0",
              "t13d1715h2_5b57614c22b0"]

# Human attention curve (relative session volume per clock hour).
DIURNAL = {0: .05, 1: .03, 2: .02, 3: .02, 4: .02, 5: .04, 6: .12, 7: .35,
           8: .65, 9: .85, 10: .9, 11: .9, 12: 1.0, 13: .9, 14: .85, 15: .8,
           16: .8, 17: .85, 18: .95, 19: 1.0, 20: 1.0, 21: .92, 22: .65, 23: .3}

DEVICE = "iphone-15-pro:a4:cf:12:9e:7b:01"


def _epoch(y: int, mo: int, d: int, h: int, mi: int, s: int = 0) -> float:
    return datetime(y, mo, d, h, mi, s).timestamp()


def _web_flow(rng: random.Random, ts: float, domain: str, asn: int, name: str,
              interactive: bool = True) -> FlowRecord:
    down = rng.randint(40_000, 3_000_000) if interactive else rng.randint(2_000, 40_000)
    up = rng.randint(3_000, 60_000)
    return FlowRecord(
        ts=ts, device=DEVICE, dst_ip=f"17.{rng.randint(0,253)}.{rng.randint(0,253)}."
        f"{rng.randint(1,253)}", dport=443, proto="tcp",
        duration=rng.uniform(0.4, 25.0), domain=domain, sni=domain,
        ja3=rng.choice(NORMAL_JA3), ja3s="t13d_srv_common", asn=asn, asn_name=name,
        bytes_up=up, bytes_down=down, pkts_up=rng.randint(8, 80),
        pkts_down=rng.randint(20, 400), service=name,
    )


def _benign_day(rng: random.Random, y: int, mo: int, d: int) -> List[FlowRecord]:
    flows: List[FlowRecord] = []

    # Human sessions, shaped by the diurnal curve.
    for hour, weight in DIURNAL.items():
        n_sessions = int(round(weight * 6))
        for _ in range(n_sessions):
            minute = rng.randint(0, 59)
            base = _epoch(y, mo, d, hour, minute, rng.randint(0, 59))
            domain, asn, name = rng.choice(KNOWN)
            for _ in range(rng.randint(1, 4)):
                flows.append(_web_flow(rng, base + rng.uniform(0, 90),
                                       domain, asn, name))

    # 24/7 APNs keepalive — periodic, nocturnal, and entirely benign.
    # This is the decoy: a naive beacon detector would alarm on it every night.
    t = _epoch(y, mo, d, 0, 0, 0)
    end = _epoch(y, mo, d, 23, 59, 0)
    while t < end:
        flows.append(FlowRecord(
            ts=t + rng.uniform(-12, 12), device=DEVICE, dst_ip="17.57.144." +
            str(rng.randint(2, 12)), dport=5223, proto="tcp", duration=rng.uniform(0.1, 2),
            domain=APNS[0], sni=APNS[0], ja3=NORMAL_JA3[0], asn=APNS[1],
            asn_name=APNS[2], bytes_up=rng.randint(200, 700),
            bytes_down=rng.randint(120, 900), pkts_up=rng.randint(2, 6),
            pkts_down=rng.randint(2, 8), service="apns-keepalive",
        ))
        t += 900 + rng.uniform(-30, 30)  # ~15 min cadence

    # Nightly iCloud backup ~02:35 (known good, low distinct-count at night).
    for k in range(3):
        flows.append(_web_flow(rng, _epoch(y, mo, d, 2, 35, k * 7),
                               "p25-content.icloud.com", 714, "Apple", interactive=True))
    return flows


def _kill_chain(rng: random.Random, y: int, mo: int, d: int) -> List[FlowRecord]:
    """The zero-click implant: deliver -> contact -> beacon -> exfil -> silence."""
    flows: List[FlowRecord] = []
    C2_IP = "185.220.101.47"          # raw IP, never named
    C2_ASN, C2_NAME = 9009, "M247"    # repeatedly-burned colo
    IMPLANT_JA3 = "t13d_IMPLANT_3f9ac1b07e22"  # unique, unseen in baseline

    t0 = _epoch(y, mo, d, 3, 14, 3)   # dead of night

    # 1) Inbound push — the doorway. Looks like any other APNs delivery.
    flows.append(FlowRecord(
        ts=t0, device=DEVICE, dst_ip="17.57.144.7", dport=5223, proto="tcp",
        duration=0.6, domain=APNS[0], sni=APNS[0], ja3=NORMAL_JA3[0], asn=714,
        asn_name="Apple", bytes_up=320, bytes_down=2600, pkts_up=3, pkts_down=5,
        inbound_push=True, push_service="apns", service="apns",
    ))

    # 2) Novel contact + 3) metronomic beacon to the raw-IP C2.
    beat = t0 + 4.0
    period = 60.0
    n_beats = 13
    for i in range(n_beats):
        ts = beat + i * period + rng.uniform(-8, 8)  # low jitter
        flows.append(FlowRecord(
            ts=ts, device=DEVICE, dst_ip=C2_IP, dport=443, proto="tcp",
            duration=rng.uniform(0.2, 1.1), domain=None, sni=None,
            ja3=IMPLANT_JA3, ja3s="t13d_srv_selfsigned", asn=C2_ASN, asn_name=C2_NAME,
            bytes_up=rng.randint(800, 1600), bytes_down=rng.randint(400, 1000),
            pkts_up=rng.randint(4, 9), pkts_down=rng.randint(3, 7), service=None,
        ))

    # 4) Exfil: a steep upstream burst to the same silent host.
    exfil_ts = beat + n_beats * period + 30
    flows.append(FlowRecord(
        ts=exfil_ts, device=DEVICE, dst_ip=C2_IP, dport=443, proto="tcp",
        duration=41.0, domain=None, sni=None, ja3=IMPLANT_JA3,
        ja3s="t13d_srv_selfsigned", asn=C2_ASN, asn_name=C2_NAME,
        bytes_up=2_201_000, bytes_down=31_000, pkts_up=1680, pkts_down=210,
        service=None,
    ))
    # 5) silence — no further beats (cleanup).
    return flows


def _benign_confounds(rng: random.Random, y: int, mo: int, d: int) -> List[FlowRecord]:
    """Daytime traps that *look* a little like an implant but are not."""
    flows: List[FlowRecord] = []

    # (a) A brand-new domain the user simply visited in the afternoon. Novel,
    #     but named, on ordinary hosting, downstream-heavy, no beacon, no exfil.
    flows.append(_web_flow(rng, _epoch(y, mo, d, 12, 41, 8),
                           "shop-deals-tr.com", 20473, "Vultr"))

    # (b) The classic confound: an iMessage arrives, then 25s later the user
    #     taps a link to a never-seen news site. push -> novel host, by daylight.
    push_ts = _epoch(y, mo, d, 14, 5, 0)
    flows.append(FlowRecord(
        ts=push_ts, device=DEVICE, dst_ip="17.57.144.9", dport=5223, proto="tcp",
        duration=0.5, domain=APNS[0], sni=APNS[0], ja3=NORMAL_JA3[0], asn=714,
        asn_name="Apple", bytes_up=300, bytes_down=2100, pkts_up=3, pkts_down=4,
        inbound_push=True, push_service="apns", service="apns",
    ))
    for k in range(2):
        flows.append(_web_flow(rng, push_ts + 25 + k * 6,
                               "yenihaber-portal.com", 20473, "Vultr"))
    return flows


def generate(seed: int = 1337, baseline_days: int = 3,
             with_implant: bool = True) -> Tuple[List[FlowRecord], List[FlowRecord]]:
    """Return (baseline_flows, detection_flows).

    Baseline = several quiet days used to learn the human's rhythm and cast.
    Detection = one day containing benign traffic, benign confounds, and (by
    default) the zero-click kill chain.
    """
    rng = random.Random(seed)
    baseline: List[FlowRecord] = []
    # Baseline days: 2026-05-25 .. 05-27
    for d in range(25, 25 + baseline_days):
        baseline += _benign_day(rng, 2026, 5, d)

    # Detection day: 2026-05-28
    detection = _benign_day(rng, 2026, 5, 28)
    detection += _benign_confounds(rng, 2026, 5, 28)
    if with_implant:
        detection += _kill_chain(rng, 2026, 5, 28)

    baseline.sort(key=lambda f: f.ts)
    detection.sort(key=lambda f: f.ts)
    return baseline, detection
