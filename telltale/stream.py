"""
TELLTALE — Live Streaming Analysis (Phase 1)

This module enables continuous, stateful threat hunting on a live stream of JSONL
flows (e.g., piped from `tail -f` or a network tap adapter). It uses a sliding window
approach, aging out old flows to maintain a steady memory footprint while keeping
the baseline continuously updated.
"""

from __future__ import annotations

import json
import sys
import time
from typing import TextIO

from . import ui
from .baseline import Baseline
from .model import FlowRecord
from .narrator import print_report, tale
from .scorer import analyze


def stream_analysis(
    stream: TextIO,
    baseline: Baseline,
    window_size_s: float = 3600 * 12, # 12 hour sliding window by default
    update_interval_s: float = 60.0   # How often to run the scorer
) -> int:
    """Continuously read flows, maintain a sliding window, and score periodically."""
    window = []
    reported_incident_ids = set()
    last_eval = 0.0
    highest_exit = 0
    
    print(ui.c(f"[*] TELLTALE Live Stream Analysis Started (Window: {window_size_s/3600:.1f}h)", "cyan"), file=sys.stderr)
    
    try:
        while True:
            line = stream.readline()
            if not line:
                # If stream is a pipe, readline() blocks. If it hits EOF, it returns empty string.
                # If we are reading from stdin and it closes, we exit.
                if stream.isatty() or stream.closed:
                    break
                time.sleep(0.1)
                continue
                
            line = line.strip()
            if not line:
                continue
                
            try:
                flow = FlowRecord.from_dict(json.loads(line))
            except Exception:
                continue # Skip malformed lines silently in production streaming
                
            from .enrich import enrich_flows
            enrich_flows([flow])
                
            window.append(flow)
            
            # Age out old flows
            latest_ts = flow.ts
            cutoff_ts = latest_ts - window_size_s
            
            while window and window[0].ts < cutoff_ts:
                window.pop(0)
                
            # Time to evaluate? 
            if len(window) > 10 and (flow.ts - last_eval) > update_interval_s:
                last_eval = flow.ts
                
                result = analyze(baseline, window)
                
                # Report NEW or ESCALATED incidents
                for inc in result.incidents:
                    if inc.incident_id not in reported_incident_ids:
                        if inc.verdict in ("CRITICAL", "HIGH", "ELEVATED"):
                            print(f"\n{ui.c('!!! NEW INCIDENT DETECTED !!!', 'white', 'b_red')}")
                            color = "bred" if inc.verdict == "CRITICAL" else ("byellow" if inc.verdict == "HIGH" else "yellow")
                            print(ui.c(f"[{inc.verdict}] {inc.dst} (Score: {inc.score})", color))
                            if inc.verdict in ("CRITICAL", "HIGH"):
                                print(tale(inc, baseline))
                            reported_incident_ids.add(inc.incident_id)
                            
                            if inc.verdict == "CRITICAL":
                                highest_exit = max(highest_exit, 2)
                            elif inc.verdict == "HIGH":
                                highest_exit = max(highest_exit, 1)
                                
    except KeyboardInterrupt:
        print(ui.c("\n[*] Stream terminated by user. Exiting.", "cyan"), file=sys.stderr)
        
    return highest_exit
