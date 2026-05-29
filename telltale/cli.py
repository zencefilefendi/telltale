"""
TELLTALE — command line.

  telltale demo                 generate a world (incl. a zero-click chain) and hunt it
  telltale demo --no-implant    same world, clean — prove the false-positive rate
  telltale sim --out f.jsonl    write synthetic baseline + detection flows
  telltale analyze f.jsonl --baseline b.jsonl
  telltale analyze cap.pcap --pcap --baseline base.pcap
  telltale analyze day.jsonl --train-frac 0.6      (auto time-split if no baseline)

Everything reads/writes flow *metadata* as JSONL or ingests pcap. No payloads.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __tagline__, __version__, ui
from .baseline import Baseline
from .model import FlowRecord
from .narrator import print_report, tale
from .scorer import AnalysisResult, analyze


# ---- IO ---------------------------------------------------------------------
def _looks_pcap(path: str) -> bool:
    return path.lower().endswith((".pcap", ".pcapng", ".cap"))


def load_source(path: str, force_pcap: bool = False) -> List[FlowRecord]:
    if force_pcap or _looks_pcap(path):
        from .pcap_source import read_pcap
        return read_pcap(path)
    flows: List[FlowRecord] = []
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if line:
                flows.append(FlowRecord.from_dict(json.loads(line)))
    return flows


def write_jsonl(path: str, flows: List[FlowRecord]) -> None:
    with open(path, "w") as fh:
        for f in flows:
            fh.write(json.dumps(f.to_dict()) + "\n")


def time_split(flows: List[FlowRecord], frac: float):
    flows = sorted(flows, key=lambda f: f.ts)
    if not flows:
        return [], []
    t0, t1 = flows[0].ts, flows[-1].ts
    cut = t0 + (t1 - t0) * frac
    return [f for f in flows if f.ts < cut], [f for f in flows if f.ts >= cut]


# ---- JSON report ------------------------------------------------------------
def result_to_json(result: AnalysisResult, baseline: Baseline) -> dict:
    ui.set_color(False)
    incidents = []
    for inc in result.incidents:
        incidents.append({
            "id": inc.incident_id, "dst": inc.dst, "device": inc.device,
            "score": inc.score, "verdict": inc.verdict,
            "start_ts": inc.start_ts, "end_ts": inc.end_ts,
            "trigger_service": inc.trigger_service,
            "signals": [{"signal": f.signal, "weight": round(f.weight, 3),
                         "reason": f.reason} for f in inc.findings],
            "timeline": [{"ts": ts, "event": label, "detail": detail}
                         for ts, label, detail in inc.timeline],
            "tale": tale(inc, baseline) if inc.verdict in ("CRITICAL", "HIGH") else None,
        })
    return {"tool": "TELLTALE", "version": __version__, "tagline": __tagline__,
            "stats": result.stats, "incidents": incidents,
            "suppressed": result.suppressed}


# ---- verbs ------------------------------------------------------------------
def run_pipeline(baseline_flows, detection_flows, as_json: bool) -> int:
    baseline = Baseline().train(baseline_flows)
    result = analyze(baseline, detection_flows)
    if as_json:
        print(json.dumps(result_to_json(result, baseline), indent=2))
    else:
        print_report(result, baseline)
    return 2 if result.stats.get("critical") else (1 if any(
        i.verdict == "HIGH" for i in result.incidents) else 0)


def cmd_demo(args) -> int:
    from .sim import generate
    baseline_flows, detection_flows = generate(
        seed=args.seed, baseline_days=args.days, with_implant=not args.no_implant)
    return run_pipeline(baseline_flows, detection_flows, args.json)


def cmd_sim(args) -> int:
    from .sim import generate
    baseline_flows, detection_flows = generate(
        seed=args.seed, baseline_days=args.days, with_implant=not args.no_implant)
    base_out = args.out.rsplit(".", 1)[0] + ".baseline.jsonl"
    write_jsonl(args.out, detection_flows)
    write_jsonl(base_out, baseline_flows)
    print(f"wrote {len(detection_flows)} detection flows -> {args.out}")
    print(f"wrote {len(baseline_flows)} baseline flows  -> {base_out}")
    return 0


def cmd_analyze(args) -> int:
    source = load_source(args.source, force_pcap=args.pcap)
    if args.baseline:
        baseline_flows = load_source(args.baseline, force_pcap=args.pcap)
        detection_flows = source
    else:
        baseline_flows, detection_flows = time_split(source, args.train_frac)
        if not baseline_flows:
            print("not enough data to form a baseline; use --baseline", file=sys.stderr)
            return 3
    return run_pipeline(baseline_flows, detection_flows, args.json)


def cmd_watch(args) -> int:
    from .stream import stream_analysis
    if not args.baseline:
        print("error: --baseline is required for watch mode", file=sys.stderr)
        return 3
        
    baseline_flows = load_source(args.baseline, force_pcap=False)
    baseline = Baseline().train(baseline_flows)
    
    stream = sys.stdin
    if args.source and args.source != "-":
        stream = open(args.source, "r")
        
    return stream_analysis(stream, baseline, window_size_s=args.window * 3600)

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="telltale",
        description="passive zero-click / Pegasus-class implant detection for the wire")
    p.add_argument("--version", action="version", version=f"TELLTALE {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("demo", help="generate a world and hunt the implant in it")
    d.add_argument("--seed", type=int, default=1337)
    d.add_argument("--days", type=int, default=3, help="baseline days to learn from")
    d.add_argument("--no-implant", action="store_true", help="clean world (FP check)")
    d.add_argument("--json", action="store_true")
    d.set_defaults(func=cmd_demo)

    s = sub.add_parser("sim", help="write synthetic flows to JSONL")
    s.add_argument("--out", default="telltale_traffic.jsonl")
    s.add_argument("--seed", type=int, default=1337)
    s.add_argument("--days", type=int, default=3)
    s.add_argument("--no-implant", action="store_true")
    s.set_defaults(func=cmd_sim)

    a = sub.add_parser("analyze", help="hunt in real flows (JSONL or pcap)")
    a.add_argument("source", help="detection flows (.jsonl or .pcap)")
    a.add_argument("--baseline", help="baseline flows (.jsonl or .pcap)")
    a.add_argument("--pcap", action="store_true", help="force pcap parsing")
    a.add_argument("--train-frac", type=float, default=0.6,
                   help="if no --baseline, fraction of timeline used to learn")
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_analyze)
    
    w = sub.add_parser("watch", help="continuous analysis on a live JSONL stream (e.g. tail -f)")
    w.add_argument("source", nargs="?", default="-", help="stream source (default: stdin)")
    w.add_argument("--baseline", required=True, help="baseline flows to use (.jsonl)")
    w.add_argument("--window", type=float, default=12.0, help="sliding window size in hours (default: 12)")
    w.set_defaults(func=cmd_watch)
    
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except RuntimeError as e:
        print(ui.c(f"error: {e}", "bred"), file=sys.stderr)
        return 4
    except FileNotFoundError as e:
        print(ui.c(f"error: file not found: {e.filename}", "bred"), file=sys.stderr)
        return 4
