"""
TELLTALE — core data model.

Everything in TELLTALE operates on *flow metadata*. We never decrypt payloads.
The thesis: the endpoint lies (the attacker is root there), but the wire keeps
a handful of invariants the implant cannot fully hide — when it talks, how often,
in which direction the bytes flow, and to whom. These dataclasses are the alphabet
of that observable language.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple


def hhmmss(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def stamp(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class FlowRecord:
    """One bidirectional flow as seen from the chokepoint (router/tap/DNS box).

    Built purely from the unencrypted parts of the conversation: 5-tuple, timing,
    byte/packet counts per direction, DNS answers, and the TLS ClientHello
    (SNI + JA3). No payload is ever inspected.
    """

    ts: float                       # flow start, epoch seconds
    device: str                     # local device identity (MAC/lease/label)
    dst_ip: str
    dport: int
    proto: str = "tcp"              # tcp | udp | quic
    duration: float = 0.0

    domain: Optional[str] = None    # resolved via DNS answer or TLS SNI
    sni: Optional[str] = None
    ja3: Optional[str] = None       # client TLS fingerprint
    ja3s: Optional[str] = None      # server TLS fingerprint
    asn: Optional[int] = None
    asn_name: Optional[str] = None

    bytes_up: int = 0               # device -> internet
    bytes_down: int = 0             # internet -> device
    pkts_up: int = 0
    pkts_down: int = 0

    # Messaging-push annotation. A zero-click chain begins with an *inbound*
    # delivery (iMessage/WhatsApp/Signal). On the wire that is a downstream
    # burst on a long-lived connection to a known courier. We mark it here so
    # the trigger-correlation signal can anchor on it.
    inbound_push: bool = False
    push_service: Optional[str] = None

    service: Optional[str] = None   # resolved known-service tag, if any

    def dst_key(self) -> str:
        """Stable identity for a destination cluster."""
        return self.domain or self.dst_ip

    @property
    def total_bytes(self) -> int:
        return self.bytes_up + self.bytes_down

    @property
    def up_ratio(self) -> float:
        """Fraction of bytes flowing upstream. Exfiltration skews this high."""
        t = self.total_bytes
        return (self.bytes_up / t) if t else 0.0

    @property
    def has_sni(self) -> bool:
        return bool(self.sni)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        return d

    @staticmethod
    def from_dict(d: dict) -> "FlowRecord":
        allowed = FlowRecord.__dataclass_fields__.keys()
        return FlowRecord(**{k: v for k, v in d.items() if k in allowed})


@dataclass
class Finding:
    """A single detector's observation about a destination or flow."""

    signal: str          # which detector fired
    dst: str             # destination cluster key
    weight: float        # 0..1 contribution to the destination's risk
    reason: str          # human-readable justification
    ts: float = 0.0
    evidence: dict = field(default_factory=dict)


@dataclass
class Incident:
    """A correlated story: weak signals chained into a kill-chain conclusion.

    An Incident is the unit TELLTALE actually reports. A lone periodic flow or a
    lone novel domain is noise; an inbound push followed seconds later by a novel,
    beaconing, exfiltrating destination during an idle window is a story.
    """

    incident_id: str
    device: str
    dst: str
    score: float = 0.0               # 0..100
    findings: List[Finding] = field(default_factory=list)
    timeline: List[Tuple[float, str, str]] = field(default_factory=list)
    trigger_ts: Optional[float] = None
    trigger_service: Optional[str] = None

    @property
    def start_ts(self) -> float:
        ts = [t for t, _, _ in self.timeline]
        return min(ts) if ts else 0.0

    @property
    def end_ts(self) -> float:
        ts = [t for t, _, _ in self.timeline]
        return max(ts) if ts else 0.0

    @property
    def verdict(self) -> str:
        s = self.score
        if s >= 80:
            return "CRITICAL"
        if s >= 60:
            return "HIGH"
        if s >= 40:
            return "ELEVATED"
        if s >= 20:
            return "WATCH"
        return "BENIGN"

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def mark(self, ts: float, label: str, detail: str = "") -> None:
        self.timeline.append((ts, label, detail))


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def coefficient_of_variation(values: List[float]) -> float:
    """std/mean — low for a metronome (beacon), high for human bursts."""
    if len(values) < 2:
        return math.inf
    mean = sum(values) / len(values)
    if mean == 0:
        return math.inf
    var = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(var) / mean
