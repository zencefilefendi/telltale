"""
TELLTALE — behavioral tests.

These assert the two things that actually matter: TELLTALE *catches the implant*
and TELLTALE *does not cry wolf* on the decoys engineered to fool it. Runs with
pytest, or standalone:  python3 tests/test_detection.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telltale.baseline import Baseline
from telltale.model import Finding
from telltale.scorer import _combine, analyze
from telltale.sim import generate

C2 = "185.220.101.47"
CONFOUND = "yenihaber-portal.com"
ALL_SIGNALS = {"trigger_correlation", "novelty", "beacon",
               "exfil", "diurnal", "tls_blindspot"}


def _run(with_implant=True):
    base_flows, det_flows = generate(seed=1337, with_implant=with_implant)
    baseline = Baseline().train(base_flows)
    return analyze(baseline, det_flows)


def test_implant_is_critical_with_full_kill_chain():
    res = _run(True)
    hit = [i for i in res.incidents if i.dst == C2]
    assert hit, "implant destination not surfaced at all"
    inc = hit[0]
    assert inc.verdict == "CRITICAL" and inc.score >= 80, inc.score
    sigs = {f.signal for f in inc.findings}
    assert ALL_SIGNALS <= sigs, f"missing signals: {ALL_SIGNALS - sigs}"


def test_benign_apns_keepalive_is_suppressed():
    res = _run(True)
    suppressed = {s["dst"] for s in res.suppressed}
    assert "courier.push.apple.com" in suppressed, suppressed


def test_text_then_link_confound_stays_watch():
    # push -> novel host by daylight, no behavioral proof: must NOT escalate.
    res = _run(True)
    conf = [i for i in res.incidents if i.dst == CONFOUND]
    assert conf, "confound not present"
    assert conf[0].score < 40, f"confound over-scored: {conf[0].score}"
    assert conf[0].verdict in ("WATCH", "BENIGN")


def test_clean_world_has_no_critical():
    res = _run(False)
    assert res.stats["critical"] == 0
    assert not any(i.dst == C2 for i in res.incidents)


def test_corroboration_gate_damps_identity_only():
    only_identity = [Finding("novelty", "x", 0.9, "novel")]
    assert _combine(only_identity) < 50, "identity-only finding was not damped"
    behavioral = [Finding("novelty", "x", 0.7, "novel"),
                  Finding("beacon", "x", 0.7, "beat")]
    assert _combine(behavioral) > 70, "corroborated finding under-scored"


def test_clienthello_parser_extracts_sni_and_ja3():
    try:
        from scapy.all import load_layer
        load_layer("tls")
        from scapy.layers.tls.handshake import TLSClientHello
        from scapy.layers.tls.record import TLS
        from scapy.layers.tls.extensions import (
            TLS_Ext_ServerName, ServerName,
            TLS_Ext_SupportedGroups, TLS_Ext_SupportedPointFormat)
    except Exception:
        print("  (skipped: scapy not installed)")
        return
    from telltale.pcap_source import parse_client_hello
    ch = TLSClientHello(
        ciphers=[0x1301, 0x1302, 0xc02b],
        ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=b"evil.example.com")]),
             TLS_Ext_SupportedGroups(groups=[29, 23]),
             TLS_Ext_SupportedPointFormat(ecpl=[0])])
    sni, ja3 = parse_client_hello(bytes(TLS(msg=[ch])))
    assert sni == "evil.example.com", sni
    assert ja3 and len(ja3) == 32, ja3


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {t.__name__}: {e}")
        except Exception as e:  # noqa
            failed += 1
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
