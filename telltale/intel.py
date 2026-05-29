"""
TELLTALE — threat intel & ground truth.

A passive detector is only as good as its sense of "normal." This module encodes
the small, durable facts about the legitimate mobile ecosystem: who the messaging
couriers are (the delivery vector for zero-click), which ASNs belong to the big
honest CDNs, and how to smell a throwaway C2 domain. None of this is a blocklist
of "known Pegasus IOCs" — those rot in days. We reason about *shape and provenance*,
which the attacker cannot rent away.
"""

from __future__ import annotations

import math
from typing import Optional

from .model import FlowRecord


# --- Messaging couriers: the doorway a zero-click exploit arrives through. ----
# A push delivered here, immediately followed by a novel outbound flow, is the
# canonical zero-click silhouette: deliver -> exploit -> beacon.
COURIERS = {
    "apns": ("apple", ("push.apple.com", "courier.push.apple.com", "apple-dns.net")),
    "whatsapp": ("whatsapp", ("whatsapp.net", "g.whatsapp.net", "whatsapp.com")),
    "telegram": ("telegram", ("telegram.org", "t.me", "telegram-cdn.org")),
    "signal": ("signal", ("signal.org", "whispersystems.org")),
    "messenger": ("facebook", ("facebook.com", "fbcdn.net", "messenger.com")),
}

# --- Reputable ASNs for the big, boring, honest infrastructure. ---------------
TRUSTED_ASNS = {
    714: "Apple",
    6185: "Apple",
    2906: "Netflix",
    15169: "Google",
    36492: "Google",
    13335: "Cloudflare",
    16509: "Amazon",
    14618: "Amazon",
    20940: "Akamai",
    16625: "Akamai",
    54113: "Fastly",
    32934: "Meta",
    63293: "Meta",
    8075: "Microsoft",
}

# A handful of hosting/colo ASNs repeatedly burned for throwaway C2 and
# "bulletproof" rental. Not proof of guilt — a thumb on the scale of suspicion.
LOW_TRUST_ASNS = {
    9009: "M247",
    16276: "OVH",
    24940: "Hetzner",
    14061: "DigitalOcean",
    51852: "PlusServer",
    200651: "FlokiNET",
    49981: "WorldStream",
    206264: "Amarutu",
}

# Big honest domains an idle phone legitimately touches at all hours.
KNOWN_GOOD_SUFFIXES = (
    "apple.com", "icloud.com", "apple-dns.net", "mzstatic.com",
    "google.com", "googleapis.com", "gstatic.com", "ggpht.com",
    "instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net",
    "whatsapp.net", "whatsapp.com", "gvt2.com",
    "cloudflare.com", "akamai.net", "akamaiedge.net", "fastly.net",
    "amazonaws.com", "microsoft.com", "office.com", "spotify.com",
    "netflix.com", "nflxvideo.net", "doubleclick.net",
)


def push_service_for(domain: Optional[str]) -> Optional[str]:
    if not domain:
        return None
    d = domain.lower()
    for service, (_owner, suffixes) in COURIERS.items():
        if any(d == s or d.endswith("." + s) or d.endswith(s) for s in suffixes):
            return service
    return None


def asn_trust(asn: Optional[int]) -> float:
    """1.0 = blue-chip infrastructure, 0.1 = repeatedly-burned host, 0.4 = unknown."""
    if asn is None:
        return 0.35
    if asn in TRUSTED_ASNS:
        return 1.0
    if asn in LOW_TRUST_ASNS:
        return 0.12
    return 0.4


def is_known_good(flow: FlowRecord) -> bool:
    """Destinations an idle, healthy phone legitimately reaches around the clock.

    Critical for specificity: APNs keepalives are periodic *and* nocturnal, yet
    benign. Without this allowlist the beacon detector would cry wolf every night.
    """
    d = (flow.domain or flow.sni or "").lower()
    if d and any(d == s or d.endswith("." + s) for s in KNOWN_GOOD_SUFFIXES):
        return True
    if d and any(d.endswith(s) for s in KNOWN_GOOD_SUFFIXES):
        return True
    # A TLS flow with no domain at all (raw-IP SNI-less) is never "known good."
    return False


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def domain_novelty_features(domain: Optional[str], ip: str) -> dict:
    """Provenance smell test for a destination identity.

    Pegasus-class operators favor freshly-registered, low-character-content,
    high-entropy or simply *absent* domains (raw-IP TLS with no SNI). We score the
    shape, never a static IOC.
    """
    feats = {
        "raw_ip": domain is None,
        "entropy": 0.0,
        "label_len": 0,
        "digit_ratio": 0.0,
        "dga_like": False,
        "short_tld_host": False,
    }
    if domain is None:
        feats["entropy"] = 4.6  # treat raw IP as maximally "unnamed"
        return feats

    d = domain.lower().strip(".")
    labels = d.split(".")
    host = labels[0] if labels else d
    feats["label_len"] = len(host)
    feats["entropy"] = round(shannon_entropy(host), 3)
    digits = sum(ch.isdigit() for ch in host)
    feats["digit_ratio"] = round(digits / max(1, len(host)), 3)
    # DGA-ish: long, high-entropy, vowel-poor host label.
    vowels = sum(ch in "aeiou" for ch in host)
    vowel_ratio = vowels / max(1, len(host))
    feats["dga_like"] = (
        len(host) >= 10 and feats["entropy"] >= 3.5 and vowel_ratio < 0.30
    )
    feats["short_tld_host"] = len(labels) >= 2 and len(host) <= 4
    return feats


def novelty_score(domain: Optional[str], ip: str, asn: Optional[int],
                  has_sni: bool, ja3_rare: bool) -> tuple[float, list[str]]:
    """0..1 provenance suspicion with human-readable reasons."""
    feats = domain_novelty_features(domain, ip)
    score = 0.0
    reasons: list[str] = []

    if feats["raw_ip"] or not has_sni:
        score += 0.45
        reasons.append("raw-IP TLS with no SNI (an unnamed destination)")
    if feats["dga_like"]:
        score += 0.30
        reasons.append(
            f"DGA-like host label (entropy {feats['entropy']}, vowel-poor)"
        )
    t = asn_trust(asn)
    if t <= 0.15:
        score += 0.35
        reasons.append(f"hosted on a repeatedly-burned ASN (AS{asn})")
    elif t <= 0.4:
        score += 0.15
        reasons.append(f"hosted on a generic VPS/colo ASN (AS{asn})")
    if ja3_rare:
        score += 0.20
        reasons.append("rare TLS client fingerprint (JA3 unseen on this network)")

    return min(1.0, score), reasons
