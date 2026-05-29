"""
TELLTALE — Offline GeoIP & ASN Enrichment

An ingenious, zero-dependency offline enrichment engine. Instead of requiring
heavy libraries like `maxminddb`, this module downloads a lightweight TSV snapshot
from iptoasn.com, caches it locally, and uses Python's native `bisect` module
to perform lightning-fast O(log N) IP-to-ASN lookups in memory.
"""

from __future__ import annotations

import bisect
import gzip
import ipaddress
import os
import time
import urllib.request
from typing import List, Optional, Tuple

from . import ui
from .model import FlowRecord

V4_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
CACHE_DIR = os.path.expanduser("~/.telltale")
V4_CACHE = os.path.join(CACHE_DIR, "ip2asn-v4.tsv.gz")
MAX_AGE_DAYS = 7


class ASNEnricher:
    def __init__(self):
        self.starts: List[int] = []
        self.ends: List[int] = []
        self.asns: List[int] = []
        self.ccs: List[str] = []
        self.names: List[str] = []
        self.loaded = False

    def _ensure_cache(self) -> None:
        os.makedirs(CACHE_DIR, exist_ok=True)
        need_download = True
        
        if os.path.exists(V4_CACHE):
            age = time.time() - os.path.getmtime(V4_CACHE)
            if age < (MAX_AGE_DAYS * 86400):
                need_download = False
                
        if need_download:
            print(ui.c("[*] Downloading fresh offline ASN/GeoIP database (3MB)...", "cyan"))
            try:
                urllib.request.urlretrieve(V4_URL, V4_CACHE)
            except Exception as e:
                print(ui.c(f"[-] Failed to download ASN database: {e}", "yellow"))

    def load(self) -> None:
        if self.loaded:
            return
            
        self._ensure_cache()
        if not os.path.exists(V4_CACHE):
            return

        try:
            with gzip.open(V4_CACHE, "rt", encoding="utf-8") as f:
                for line in f:
                    parts = line.split("\t")
                    if len(parts) >= 5:
                        self.starts.append(int(parts[0]))
                        self.ends.append(int(parts[1]))
                        self.asns.append(int(parts[2]))
                        self.ccs.append(parts[3])
                        self.names.append(parts[4].strip())
            self.loaded = True
        except Exception as e:
            print(ui.c(f"[-] Corrupt ASN cache, ignoring: {e}", "yellow"))

    def lookup(self, ip_str: str) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """Returns (ASN, CountryCode, ASN_Name)."""
        if not self.loaded:
            return None, None, None
            
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.version != 4:
                return None, None, None # Only IPv4 supported in this quick DB
                
            ip_int = int(ip_obj)
            # Find the rightmost start interval <= ip_int
            idx = bisect.bisect_right(self.starts, ip_int) - 1
            if idx >= 0 and ip_int <= self.ends[idx]:
                asn = self.asns[idx]
                if asn == 0:
                    return None, None, None
                return asn, self.ccs[idx], self.names[idx]
        except Exception:
            pass
            
        return None, None, None


_enricher = ASNEnricher()

def enrich_flows(flows: List[FlowRecord]) -> None:
    """Enriches flows in-place with real offline ASN/GeoIP data."""
    _enricher.load()
    if not _enricher.loaded:
        return
        
    for f in flows:
        # Only enrich if it doesn't already have it (sim data might have fake ASNs)
        if f.asn is None:
            asn, cc, name = _enricher.lookup(f.dst_ip)
            if asn:
                f.asn = asn
                f.asn_name = f"{name} ({cc})" if name and cc else name
