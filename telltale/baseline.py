"""
TELLTALE — behavioral baseline.

We cannot see the phone's screen, so we infer the human from the wire. Over a
training window the baseline learns two things:

  1. The *cast of characters* — which destinations and TLS fingerprints this
     device legitimately talks to. Anything outside it is novel by definition.
  2. The *rhythm of the human* — the diurnal curve of distinct destinations per
     hour. Keepalives hammer the same courier all night, so counting *distinct*
     destinations (not raw flows) cleanly separates "the person is awake and
     using apps" from "the device is idle and only machines are talking."

The second is the quiet superpower: it lets us ask the only question that matters
— "was there a human or app reason for this packet?" — without an agent on the box.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Set

from .intel import is_known_good
from .model import FlowRecord


class Baseline:
    def __init__(self) -> None:
        self.known_dst: Set[str] = set()
        self.dst_first_seen: Dict[str, float] = {}
        self.ja3_counts: Dict[str, int] = defaultdict(int)
        self.asn_counts: Dict[int, int] = defaultdict(int)
        self.hour_distinct: List[float] = [0.0] * 24   # avg distinct dsts / hour
        
        # Statistical Exfil Boundaries
        self.exfil_median: float = 0.0
        self.exfil_mad: float = 0.0
        self.exfil_threshold: int = 256 * 1024 # Default fallback
        
        self._trained = False
        self._days = 1
        self._total_flows = 0

    # ---- training -----------------------------------------------------------
    def train(self, flows: Iterable[FlowRecord]) -> "Baseline":
        flows = list(flows)
        self._total_flows += len(flows)
        per_hour_day: Dict[tuple, Set[str]] = defaultdict(set)
        days: Set[str] = set()
        up_bytes: List[int] = []

        for f in flows:
            if f.bytes_up > 0 and not self.is_known_dst(f.dst_key()):
                up_bytes.append(f.bytes_up)
                
            key = f.dst_key()
            self.known_dst.add(key)
            self.dst_first_seen.setdefault(key, f.ts)
            if f.ja3:
                self.ja3_counts[f.ja3] += 1
            if f.asn:
                self.asn_counts[f.asn] += 1
            dt = datetime.fromtimestamp(f.ts)
            day = dt.strftime("%Y-%m-%d")
            days.add(day)
            per_hour_day[(day, dt.hour)].add(key)

        self._days = max(1, len(days))
        
        # Learn Robust Statistical Baseline for Exfil (MAD)
        if len(up_bytes) > 5:
            self.exfil_median = statistics.median(up_bytes)
            # MAD = median(|x - median|)
            self.exfil_mad = statistics.median([abs(x - self.exfil_median) for x in up_bytes])
            # Sigma estimation for normal distribution = MAD * 1.4826
            sigma_est = self.exfil_mad * 1.4826
            # Threshold = Median + 5-Sigma (Bounded between 50KB and 5MB to avoid noise/extremes)
            raw_threshold = self.exfil_median + (5 * sigma_est)
            self.exfil_threshold = max(50 * 1024, min(5 * 1024 * 1024, int(raw_threshold)))
            
        # Average number of *distinct* destinations seen in each clock-hour.
        bucket_totals = [0.0] * 24
        bucket_counts = [0] * 24
        for (day, hour), dsts in per_hour_day.items():
            bucket_totals[hour] += len(dsts)
            bucket_counts[hour] += 1
        for h in range(24):
            self.hour_distinct[h] = (
                bucket_totals[h] / bucket_counts[h] if bucket_counts[h] else 0.0
            )
        self._smooth_profile()
        self._trained = True
        return self

    def _smooth_profile(self) -> None:
        # circular 3-point smoothing so a single quiet sample doesn't carve a
        # false "idle" notch into a busy part of the day.
        src = self.hour_distinct[:]
        for h in range(24):
            a, b, c = src[(h - 1) % 24], src[h], src[(h + 1) % 24]
            self.hour_distinct[h] = (a + 2 * b + c) / 4.0

    # ---- queries ------------------------------------------------------------
    @property
    def peak_activity(self) -> float:
        return max(self.hour_distinct) if self.hour_distinct else 1.0

    def is_known_dst(self, key: str) -> bool:
        return key in self.known_dst

    def is_novel(self, flow: FlowRecord) -> bool:
        if is_known_good(flow):
            return False
        return flow.dst_key() not in self.known_dst

    def is_rare_ja3(self, ja3: Optional[str]) -> bool:
        if not ja3:
            return False
        # Rare = seen at most once across the whole training window.
        return self.ja3_counts.get(ja3, 0) <= 1

    def is_rare_asn(self, asn: Optional[int]) -> bool:
        if not asn:
            return False
        # Rare = seen less than 3 times or makes up less than 0.01% of traffic
        count = self.asn_counts.get(asn, 0)
        if count < 3:
            return True
        if self._total_flows > 1000 and (count / self._total_flows) < 0.0001:
            return True
        return False

    def idle_score(self, ts: float) -> float:
        """0..1 — how *unexpected* it is for the human to be generating traffic now.

        1.0 = dead of night, the diurnal curve says nobody is awake. 0.0 = peak
        daytime activity. A novel flow at idle_score 0.9 has almost no innocent
        explanation; the same flow at 0.1 is just someone using their phone.
        """
        if not self._trained or self.peak_activity == 0:
            return 0.0
        hour = datetime.fromtimestamp(ts).hour
        activity_norm = self.hour_distinct[hour] / self.peak_activity
        return round(1.0 - activity_norm, 3)

    def profile_sparkline(self) -> str:
        bars = "▁▂▃▄▅▆▇█"
        peak = self.peak_activity or 1.0
        out = []
        for h in range(24):
            level = self.hour_distinct[h] / peak
            out.append(bars[min(len(bars) - 1, int(level * (len(bars) - 1)))])
        return "".join(out)
