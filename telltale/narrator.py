"""
TELLTALE — the narrator (the ozan).

A risk score is a number; a conviction is a story. The narrator does two jobs:
it renders the structured report (incidents, signals, timelines), and for the
loud cases it *tells the tale* — the plain-language account of what the wire saw
while the endpoint pretended nothing happened. This is the Dede Korkut function:
the silence tried to bury the deed; the ozan tells it true.
"""

from __future__ import annotations

from typing import List, Optional

from .baseline import Baseline
from .model import Finding, Incident, hhmmss, stamp
from .scorer import AnalysisResult
from . import ui

SIGNAL_LABEL = {
    "trigger_correlation": "S1 trigger",
    "novelty": "S2 novelty",
    "beacon": "S3 beacon",
    "exfil": "S4 exfil",
    "diurnal": "S5 diurnal",
    "tls_blindspot": "S6 tls-blind",
}

TIMELINE_GLYPH = {
    "INBOUND PUSH": ("✉", "cyan"),
    "NOVEL CONTACT": ("◆", "byellow"),
    "BEACON": ("♥", "bred"),
    "EXFIL": ("▲", "bred"),
    "SILENCE": ("·", "grey"),
}


def _get(inc: Incident, signal: str) -> Optional[Finding]:
    for f in inc.findings:
        if f.signal == signal:
            return f
    return None


def tale(inc: Incident, baseline: Baseline) -> str:
    """Compose the plain-language account from whatever evidence exists."""
    trg, nov = _get(inc, "trigger_correlation"), _get(inc, "novelty")
    bcn, exf, diu = _get(inc, "beacon"), _get(inc, "exfil"), _get(inc, "diurnal")

    parts: List[str] = []

    if inc.trigger_ts is not None and trg:
        idle = baseline.idle_score(inc.trigger_ts)
        sleeping = " while the device slept" if idle >= 0.6 else ""
        parts.append(
            f"At {ui.c(hhmmss(inc.trigger_ts), 'white', 'bold')}{sleeping} "
            f"(idle {idle:.2f}), an inbound {trg.evidence.get('service','message')} "
            f"push arrived — a message no eye had to see."
        )

    contact_ts = inc.start_ts
    ip = (nov.evidence.get("ip") if nov else None) or inc.dst
    asn = nov.evidence.get("asn") if nov else None
    dt = trg.evidence.get("dt") if trg else None
    when = f"{dt:.0f} seconds later" if dt is not None else f"At {hhmmss(contact_ts)}"
    asn_clause = f", on AS{asn}," if asn else ""
    ip_clause = "" if ip == inc.dst else f" ({ip})"
    parts.append(
        f"{when} the device reached out to "
        f"{ui.c(inc.dst, 'byellow')}{ip_clause}{asn_clause} a host it had never named before."
    )

    if bcn:
        parts.append(
            f"Then a heartbeat: every ~{bcn.evidence.get('period',0):.0f} seconds, "
            f"{bcn.evidence.get('hits','several')} times over, too steady for any human hand."
        )

    if exf:
        mb = exf.evidence.get("bytes_up", 0) / (1024 * 1024)
        parts.append(
            f"At {ui.c(hhmmss(exf.ts), 'white', 'bold')}, "
            f"{ui.c(f'{mb:.2f} MB', 'bred', 'bold')} climbed UPSTREAM to that silent host — "
            f"the wrong direction for anything you asked for."
        )

    if diu and inc.trigger_ts is None:
        parts.append("All of it happened in a window where the baseline says no one was awake.")

    parts.append(
        ui.c("The endpoint will show you a clean home screen. The wire shows you this.",
             "ital", "grey")
    )
    return " ".join(parts)


def _render_incident(inc: Incident, baseline: Baseline, rank: int) -> str:
    out: List[str] = []
    head = (f"{ui.badge(inc.verdict)}  {ui.c('#'+str(rank), 'grey')}  "
            f"{ui.c(inc.dst, 'bold', 'white')}   {ui.c(inc.incident_id, 'grey')}")
    out.append(head)
    out.append(f"  {ui.riskbar(inc.score)}  {ui.c(f'{inc.score:.0f}/100', 'bold')}"
               f"   device {ui.c(inc.device, 'cyan')}")
    if inc.start_ts:
        out.append(ui.c(f"  window {stamp(inc.start_ts)} → {hhmmss(inc.end_ts)}", "grey"))

    out.append("")
    out.append(ui.c("  signals", "grey"))
    for f in sorted(inc.findings, key=lambda x: -x.weight):
        label = SIGNAL_LABEL.get(f.signal, f.signal)
        out.append(f"    {ui.c(label.ljust(12), 'bcyan')} "
                   f"{ui.riskbar(f.weight*100, 10)} {f.reason}")

    if inc.timeline:
        out.append("")
        out.append(ui.c("  timeline", "grey"))
        for ts, label, detail in inc.timeline:
            glyph, style = TIMELINE_GLYPH.get(label, ("•", "white"))
            out.append(f"    {ui.c(hhmmss(ts), 'grey')}  {ui.c(glyph, style)} "
                       f"{ui.c(label.ljust(13), style)} {ui.c(detail, 'grey')}")

    if inc.verdict in ("CRITICAL", "HIGH"):
        out.append("")
        out.append(ui.c("  ┌─ the tale ", "grey") + ui.c("─" * 60, "grey"))
        narrative = tale(inc, baseline)
        for line in _wrap(narrative, 68):
            out.append(ui.c("  │ ", "grey") + line)
    out.append("")
    return "\n".join(out)


def _wrap(text: str, width: int) -> List[str]:
    # width-aware wrap that ignores ANSI escape length
    import re
    ansi = re.compile(r"\033\[[0-9;]*m")
    words = text.split(" ")
    lines, cur, curlen = [], [], 0
    for w in words:
        wlen = len(ansi.sub("", w))
        if curlen + wlen + (1 if cur else 0) > width and cur:
            lines.append(" ".join(cur))
            cur, curlen = [w], wlen
        else:
            cur.append(w)
            curlen += wlen + (1 if len(cur) > 1 else 0)
    if cur:
        lines.append(" ".join(cur))
    return lines


def render(result: AnalysisResult, baseline: Baseline) -> str:
    s = result.stats
    out: List[str] = [ui.banner(), ""]

    # headline verdict
    if s.get("critical"):
        verdict = ui.c(" IMPLANT BEHAVIOR DETECTED ", "onred", "bold")
    elif any(i.verdict == "HIGH" for i in result.incidents):
        verdict = ui.c(" SUSPICIOUS ACTIVITY ", "onyellow", "bold")
    else:
        verdict = ui.c(" NO IMPLANT BEHAVIOR OBSERVED ", "ongreen", "bold")
    out.append("  " + verdict)

    out.append(ui.section("baseline · learned rhythm of the human"))
    out.append(ui.kv("diurnal profile", ui.c(s.get("idle_profile", ""), "bcyan")
                     + ui.c("  (00h ─────────────── 23h · taller = busier)", "grey")))
    out.append(ui.kv("known dsts", f"{len(baseline.known_dst)} destinations, "
                     f"{len(baseline.ja3_counts)} TLS fingerprints learned"))

    out.append(ui.section("triage · what the wire saw"))
    out.append(ui.kv("flows analyzed", str(s.get("total_flows", 0))))
    out.append(ui.kv("destinations", f"{s.get('destinations',0)} "
                     f"({s.get('novel_destinations',0)} novel)"))
    out.append(ui.kv("incidents", f"{s.get('incidents',0)} "
                     f"({ui.c(str(s.get('critical',0))+' critical','bred')})"))
    out.append(ui.kv("suppressed", f"{s.get('suppressed_known_good',0)} benign "
                     f"periodic flows correctly ignored"))

    if result.incidents:
        out.append(ui.section("incidents · ranked by risk"))
        for i, inc in enumerate(result.incidents, 1):
            out.append(_render_incident(inc, baseline, i))

    if result.suppressed:
        out.append(ui.section("specificity · beacons TELLTALE chose to ignore"))
        out.append(ui.c("  Regular heartbeats to KNOWN-GOOD infrastructure. A naive "
                        "beacon detector would alarm on these; TELLTALE does not.", "grey"))
        for sp in result.suppressed:
            out.append(f"    {ui.c('♥ suppressed', 'green')}  {ui.c(sp['dst'], 'white')}"
                       f"  ~{sp['period']:.0f}s cadence, {sp['hits']} beats  "
                       f"{ui.c('(allowlisted courier — benign)', 'grey')}")
        out.append("")

    out.append(ui.hr("═"))
    out.append(ui.c("  the endpoint lies — the wire remembers.", "grey", "ital"))
    out.append("")
    return "\n".join(out)


def print_report(result: AnalysisResult, baseline: Baseline) -> None:
    print(render(result, baseline))
