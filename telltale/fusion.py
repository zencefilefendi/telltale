"""
TELLTALE — Endpoint + Wire Fusion (Phase 3)

The wire knows *who* the device talked to, *when*, and *how much*. 
The endpoint forensics (MVT, iShutdown) know *what process* was running.
This module fuses the two. If a network incident overlaps in time with a 
suspicious endpoint process event, the two weak signals combine into a 
definitive CRITICAL alert, cornering advanced Piggybacking (A6) implants.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List

from . import ui
from .model import Incident


@dataclass
class EndpointEvent:
    ts: float
    process: str
    description: str
    severity: str = "high"


def parse_endpoint_log(path: str) -> List[EndpointEvent]:
    """
    Parses generic JSONL endpoint logs or MVT timeline extracts.
    Expected format per line:
    {"ts": 1779915607.0, "process": "sysdiagnosed", "msg": "suspicious sticky process", "severity": "critical"}
    """
    events = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    data = json.loads(line)
                    if "timestamp" in data and "process" in data:
                        # MVT style
                        ts = float(data.get("timestamp", 0))
                        events.append(EndpointEvent(
                            ts=ts, process=data["process"],
                            description=data.get("message", "MVT timeline event"),
                            severity=data.get("severity", "high")
                        ))
                    elif "ts" in data and "process" in data:
                        # TELLTALE generic style
                        events.append(EndpointEvent(
                            ts=float(data["ts"]), process=data["process"],
                            description=data.get("msg", ""),
                            severity=data.get("severity", "high")
                        ))
                except json.JSONDecodeError:
                    pass # Ignore non-JSON lines (e.g. raw syslog)
    except Exception as e:
        print(ui.c(f"[-] Failed to read endpoint log {path}: {e}", "yellow"))
    
    return events


def fuse_incidents(incidents: List[Incident], endpoint_events: List[EndpointEvent], tolerance_s: float = 60.0) -> None:
    """
    Correlates network incidents with endpoint events.
    If an endpoint event occurs within `tolerance_s` of any part of an incident's
    timeline, the incident is heavily penalized and the forensic data is injected.
    """
    if not endpoint_events or not incidents:
        return

    # Sort events for faster scanning
    endpoint_events.sort(key=lambda e: e.ts)

    for inc in incidents:
        if not inc.timeline:
            continue
            
        incident_start = min(t[0] for t in inc.timeline) - tolerance_s
        incident_end = max(t[0] for t in inc.timeline) + tolerance_s
        
        # Find overlapping events
        overlaps = [e for e in endpoint_events if incident_start <= e.ts <= incident_end]
        
        if overlaps:
            for ev in overlaps:
                # Inject the forensic proof into the incident timeline
                inc.mark(ev.ts, "ENDPOINT FUSION", f"Process '{ev.process}' active: {ev.description}")
                
                # Boost the score dramatically since we now have process-level attribution
                inc.score = min(100.0, inc.score + 40.0)
            
            # Re-sort timeline to place the endpoint event chronologically
            inc.timeline.sort(key=lambda x: x[0])
