"""
TELLTALE — pcap ingestion (the real wire).

The simulator proves the logic; this turns it loose on actual captures. We read a
.pcap/.pcapng, assemble bidirectional flows, map IPs to names from DNS answers,
and — without decrypting anything — pull SNI and a spec-correct JA3 out of the
TLS ClientHello. The direction of bytes is decided by which endpoint is the local
(private) device, so the exfil signal works on real traffic too.

scapy is optional; if it is missing we say so plainly instead of crashing.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from .model import FlowRecord

FLOW_TIMEOUT = 120.0
TLS_PORTS = {443, 5223, 8443, 853}


def _is_grease(v: int) -> bool:
    return (v & 0x0f0f) == 0x0a0a


def parse_client_hello(payload: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Return (sni, ja3_md5) from a TLS ClientHello, or (None, None).

    Implements the JA3 spec: md5 of
    SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
    with GREASE values removed. No payload decryption — the ClientHello is plaintext.
    """
    try:
        if len(payload) < 6 or payload[0] != 0x16:      # handshake record
            return None, None
        # record: type(1) ver(2) len(2) | handshake: type(1) len(3) ...
        p = payload[5:]
        if not p or p[0] != 0x01:                        # client_hello
            return None, None
        hs_len = int.from_bytes(p[1:4], "big")
        body = p[4:4 + hs_len]
        i = 0
        client_version = int.from_bytes(body[i:i + 2], "big"); i += 2
        i += 32                                           # random
        sid_len = body[i]; i += 1 + sid_len
        cs_len = int.from_bytes(body[i:i + 2], "big"); i += 2
        ciphers = []
        for j in range(0, cs_len, 2):
            v = int.from_bytes(body[i + j:i + j + 2], "big")
            if not _is_grease(v):
                ciphers.append(v)
        i += cs_len
        comp_len = body[i]; i += 1 + comp_len

        sni: Optional[str] = None
        exts: List[int] = []
        curves: List[int] = []
        ecpf: List[int] = []
        if i + 2 <= len(body):
            ext_total = int.from_bytes(body[i:i + 2], "big"); i += 2
            end = i + ext_total
            while i + 4 <= end:
                etype = int.from_bytes(body[i:i + 2], "big")
                elen = int.from_bytes(body[i + 2:i + 4], "big")
                edata = body[i + 4:i + 4 + elen]
                i += 4 + elen
                if not _is_grease(etype):
                    exts.append(etype)
                if etype == 0x0000 and len(edata) >= 5:    # SNI
                    name_len = int.from_bytes(edata[3:5], "big")
                    sni = edata[5:5 + name_len].decode("utf-8", "ignore") or None
                elif etype == 0x000a and len(edata) >= 2:  # supported_groups
                    ln = int.from_bytes(edata[0:2], "big")
                    for j in range(0, ln, 2):
                        v = int.from_bytes(edata[2 + j:4 + j], "big")
                        if not _is_grease(v):
                            curves.append(v)
                elif etype == 0x000b and len(edata) >= 1:  # ec_point_formats
                    ln = edata[0]
                    ecpf = list(edata[1:1 + ln])

        ja3 = "{},{},{},{},{}".format(
            client_version,
            "-".join(map(str, ciphers)),
            "-".join(map(str, exts)),
            "-".join(map(str, curves)),
            "-".join(map(str, ecpf)),
        )
        return sni, hashlib.md5(ja3.encode()).hexdigest()
    except Exception:
        return None, None


def _device_side(a: str, b: str) -> Optional[str]:
    """Return whichever address is the local/private device, if exactly one is."""
    pa = ipaddress.ip_address(a).is_private
    pb = ipaddress.ip_address(b).is_private
    if pa and not pb:
        return a
    if pb and not pa:
        return b
    return None


def read_pcap(path: str) -> List[FlowRecord]:
    try:
        from scapy.all import DNS, DNSRR, IP, IPv6, TCP, UDP, rdpcap  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "pcap ingestion needs scapy.  pip install scapy   "
            f"(import failed: {e})"
        )

    packets = rdpcap(path)
    dns_map: Dict[str, str] = {}
    flows: Dict[tuple, dict] = {}

    def fkey(a, pa, b, pb, proto):
        return (frozenset(((a, pa), (b, pb))), proto)

    for pkt in packets:
        ts = float(pkt.time)
        ipl = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ipl is None:
            continue
        src, dst = ipl.src, ipl.dst

        if pkt.haslayer(DNS) and pkt.getlayer(DNS).ancount:
            dns = pkt.getlayer(DNS)
            qname = ""
            try:
                qname = dns.qd.qname.decode().rstrip(".") if dns.qd else ""
            except Exception:
                qname = ""
            for k in range(dns.ancount):
                rr = dns.an[k] if hasattr(dns, "an") else None
                if isinstance(rr, DNSRR) and rr.type in (1, 28):
                    try:
                        dns_map[rr.rdata if isinstance(rr.rdata, str)
                                else rr.rdata.decode()] = qname or rr.rrname.decode().rstrip(".")
                    except Exception:
                        pass
            continue

        l4 = pkt.getlayer(TCP) or pkt.getlayer(UDP)
        if l4 is None:
            continue
        proto = "tcp" if pkt.haslayer(TCP) else "udp"
        sport, dport = int(l4.sport), int(l4.dport)
        key = fkey(src, sport, dst, dport, proto)
        size = len(bytes(pkt))

        fl = flows.get(key)
        if fl is None or ts - fl["last"] > FLOW_TIMEOUT:
            fl = {"first": ts, "last": ts, "ep": {src, dst},
                  "bytes": defaultdict(int), "pkts": defaultdict(int),
                  "proto": proto, "ports": {src: sport, dst: dport},
                  "sni": None, "ja3": None}
            flows[key] = fl
        fl["last"] = ts
        fl["bytes"][src] += size
        fl["pkts"][src] += 1

        raw = bytes(l4.payload) if l4.payload else b""

        if proto == "tcp" and fl["sni"] is None and (dport in TLS_PORTS):
            if raw[:1] == b"\x16":
                sni, ja3 = parse_client_hello(raw)
                if sni or ja3:
                    fl["sni"], fl["ja3"] = sni, ja3
                    fl["server"] = dst
                    
        elif proto == "udp" and fl["sni"] is None and (dport == 443):
            # Try parsing as QUIC Initial packet
            if len(raw) >= 1200 and (raw[0] & 0xc0) == 0xc0:
                from .quic_crypto import extract_quic_crypto_frame
                crypto_frame = extract_quic_crypto_frame(raw)
                if crypto_frame:
                    # The crypto frame contains a TLS Handshake message
                    # We prepend the TLS record header so parse_client_hello can process it
                    # 0x16 = Handshake, 0x0303 = TLS 1.2+, then Length
                    length = len(crypto_frame)
                    tls_record = b"\x16\x03\x03" + length.to_bytes(2, "big") + crypto_frame
                    sni, ja3 = parse_client_hello(tls_record)
                    if sni or ja3:
                        fl["sni"], fl["ja3"] = sni, ja3
                        fl["server"] = dst
                        fl["proto"] = "quic"

    records: List[FlowRecord] = []
    for (eps, proto), fl in flows.items():
        a, b = [x for x in fl["ep"]]
        device = _device_side(a, b)
        if device is None:
            device = a  # fall back: treat first endpoint as local
        server = b if device == a else a
        domain = fl["sni"] or dns_map.get(server)
        # the server-side port is the service port (e.g. 443), not the ephemeral
        dport = fl["ports"].get(server) or fl["ports"].get(device) or 0
        records.append(FlowRecord(
            ts=fl["first"], device=device, dst_ip=server, dport=dport, proto=proto,
            duration=max(0.0, fl["last"] - fl["first"]),
            domain=domain, sni=fl["sni"], ja3=fl["ja3"], ja3s=None,
            asn=None, asn_name=None,
            bytes_up=fl["bytes"].get(device, 0), bytes_down=fl["bytes"].get(server, 0),
            pkts_up=fl["pkts"].get(device, 0), pkts_down=fl["pkts"].get(server, 0),
        ))
    records.sort(key=lambda r: r.ts)
    return records
