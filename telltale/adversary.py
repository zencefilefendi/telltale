"""
TELLTALE — Red-Team Fuzzing Engine (Adversary Simulator)

This module acts as an intelligent, adaptive APT implant. Its goal is to evade
TELLTALE's detection (keep the incident score below WATCH, < 20.0) while still
successfully executing a kill chain:
  1. Receiving a trigger (Push).
  2. Beaconing home to establish C2.
  3. Exfiltrating a payload.

It uses a genetic algorithm / fuzzing approach. It generates a batch of "implant
configurations" (genomes), runs them through the TELLTALE scorer against a clean
baseline, and iteratively mutates the ones that score the lowest to find the
blind spots in our defenses.
"""

from __future__ import annotations

import random
import time
from copy import deepcopy
from dataclasses import dataclass
from typing import List

from .baseline import Baseline
from .intel import TRUSTED_ASNS, LOW_TRUST_ASNS
from .model import FlowRecord
from .scorer import analyze
from .sim import _benign_day


# --- The DNA of an evasion attempt ---
@dataclass
class ImplantGenome:
    # S1 evasion
    trigger_delay_s: float       # How long to wait after the push to connect (S1 evasion)
    
    # S2 evasion
    domain_type: str             # "raw_ip", "dga", "short", "trusted_cdn_front"
    asn_choice: str              # "trusted", "low_trust", "unknown"
    use_valid_sni: bool
    
    # S3 evasion
    beacon_count: int
    beacon_interval_s: float
    beacon_jitter_pct: float     # Percentage of interval to randomize (poisson/uniform)
    
    # S4 evasion
    exfil_total_bytes: int
    exfil_chunk_count: int       # How many chunks to split the exfil into
    exfil_up_ratio: float        # How much "fake download" traffic to mix in
    
    # S5 evasion
    operate_during_idle: bool    # True = 3am, False = piggyback during day

    def mutate(self) -> "ImplantGenome":
        child = deepcopy(self)
        mutation_rate = 0.3
        
        if random.random() < mutation_rate:
            child.trigger_delay_s = max(0.0, child.trigger_delay_s + random.uniform(-60, 300))
        if random.random() < mutation_rate:
            child.domain_type = random.choice(["raw_ip", "dga", "short", "trusted_cdn_front"])
        if random.random() < mutation_rate:
            child.asn_choice = random.choice(["trusted", "low_trust", "unknown"])
        if random.random() < mutation_rate:
            child.use_valid_sni = not child.use_valid_sni
        if random.random() < mutation_rate:
            child.beacon_interval_s = max(30.0, child.beacon_interval_s + random.uniform(-100, 500))
        if random.random() < mutation_rate:
            child.beacon_jitter_pct = max(0.0, min(1.0, child.beacon_jitter_pct + random.uniform(-0.2, 0.2)))
        if random.random() < mutation_rate:
            child.exfil_chunk_count = max(1, child.exfil_chunk_count + random.randint(-5, 10))
        if random.random() < mutation_rate:
            child.exfil_up_ratio = max(0.1, min(0.99, child.exfil_up_ratio + random.uniform(-0.1, 0.1)))
        if random.random() < mutation_rate:
            child.operate_during_idle = not child.operate_during_idle
            
        return child


def generate_implant_flows(genome: ImplantGenome, start_ts: float) -> List[FlowRecord]:
    """Translates a genome into physical network flows."""
    flows = []
    device = "iphone-victim:00:11"
    
    # Domain & ASN setup
    domain = None
    sni = None
    if genome.domain_type == "dga":
        domain = "xkqjwqzvpymnt.com" # Vowel-poor, long
    elif genome.domain_type == "short":
        domain = "c2.ru"
    elif genome.domain_type == "trusted_cdn_front":
        domain = "cdn.cloudflare-tenant.com"
        
    if genome.use_valid_sni and domain:
        sni = domain
        
    asn = 50000
    asn_name = "Unknown ISP"
    if genome.asn_choice == "trusted":
        asn = random.choice(list(TRUSTED_ASNS.keys()))
        asn_name = TRUSTED_ASNS[asn]
    elif genome.asn_choice == "low_trust":
        asn = random.choice(list(LOW_TRUST_ASNS.keys()))
        asn_name = LOW_TRUST_ASNS[asn]
        
    # The Push (Trigger)
    trigger_ts = start_ts
    flows.append(FlowRecord(
        ts=trigger_ts, device=device, dst_ip="17.252.0.1", dport=5223,
        domain="courier.push.apple.com", sni="courier.push.apple.com",
        asn=714, asn_name="Apple", bytes_up=1500, bytes_down=8500,
        inbound_push=True, push_service="apns"
    ))
    
    # First Contact
    c2_ip = "198.51.100.42"
    first_contact_ts = trigger_ts + genome.trigger_delay_s
    flows.append(FlowRecord(
        ts=first_contact_ts, device=device, dst_ip=c2_ip, dport=443,
        domain=domain, sni=sni, asn=asn, asn_name=asn_name,
        bytes_up=1200, bytes_down=4500, ja3="771,4865...rare"
    ))
    
    # Beacons
    current_ts = first_contact_ts
    for i in range(genome.beacon_count):
        jitter = genome.beacon_interval_s * genome.beacon_jitter_pct
        current_ts += genome.beacon_interval_s + random.uniform(-jitter, jitter)
        flows.append(FlowRecord(
            ts=current_ts, device=device, dst_ip=c2_ip, dport=443,
            domain=domain, sni=sni, asn=asn, asn_name=asn_name,
            bytes_up=2500, bytes_down=1800, ja3="771,4865...rare"
        ))
        
    # Exfil
    chunk_size = genome.exfil_total_bytes // genome.exfil_chunk_count
    for i in range(genome.exfil_chunk_count):
        # Spread the exfil out
        current_ts += (3600 / genome.exfil_chunk_count) # Spread over an hour
        bytes_up = chunk_size
        bytes_down = int(bytes_up * ((1.0 - genome.exfil_up_ratio) / max(0.01, genome.exfil_up_ratio)))
        
        flows.append(FlowRecord(
            ts=current_ts, device=device, dst_ip=c2_ip, dport=443,
            domain=domain, sni=sni, asn=asn, asn_name=asn_name,
            bytes_up=bytes_up, bytes_down=bytes_down, ja3="771,4865...rare"
        ))
        
    return flows


def run_fuzzing_generation(generations: int = 20, pop_size: int = 15):
    print("=========================================================")
    print(" TELLTALE RED-TEAM FUZZING MOTOR (Adversarial Training)  ")
    print("=========================================================")
    print(f"Goal: Exfiltrate 5MB without triggering CRITICAL (>80) or HIGH (>60) alerts.")
    
    # Create the baseline (clean traffic)
    rng = random.Random(42)
    clean_flows = _benign_day(rng, 2026, 5, 29)
    baseline = Baseline().train(clean_flows)
    
    # Base timestamp calculation matching the sim
    from .sim import _epoch
    start_ts = _epoch(2026, 5, 29, 0, 0, 0)
    
    # Initial Population
    population = [
        ImplantGenome(
            trigger_delay_s=random.uniform(5, 300),
            domain_type=random.choice(["raw_ip", "dga", "short", "trusted_cdn_front"]),
            asn_choice=random.choice(["trusted", "low_trust", "unknown"]),
            use_valid_sni=random.choice([True, False]),
            beacon_count=random.randint(2, 20),
            beacon_interval_s=random.uniform(30, 3600),
            beacon_jitter_pct=random.uniform(0.0, 0.8),
            exfil_total_bytes=5 * 1024 * 1024, # 5MB target
            exfil_chunk_count=random.randint(1, 100),
            exfil_up_ratio=random.uniform(0.5, 0.99),
            operate_during_idle=True
        ) for _ in range(pop_size)
    ]
    
    best_genome = None
    lowest_score = 100.0
    
    for gen in range(generations):
        scored_population = []
        for genome in population:
            # 1. Base time
            attack_start_ts = start_ts + (3600 * 3 if genome.operate_during_idle else 3600 * 14) 
            
            # 2. Generate attack flows
            attack_flows = generate_implant_flows(genome, attack_start_ts)
            
            # 3. Mix with clean background traffic and analyze
            all_flows = clean_flows + attack_flows
            res = analyze(baseline, all_flows)
            
            # 4. Find the incident matching our C2
            c2_incident = next((i for i in res.incidents if i.dst in ("198.51.100.42", "xkqjwqzvpymnt.com", "c2.ru", "cdn.cloudflare-tenant.com")), None)
            score = c2_incident.score if c2_incident else 0.0
            
            scored_population.append((score, genome, c2_incident))
            
            if score < lowest_score:
                lowest_score = score
                best_genome = genome
                
        # Sort population by score (ascending, lower is better for the attacker)
        scored_population.sort(key=lambda x: x[0])
        
        best_in_gen = scored_population[0]
        print(f"Gen {gen+1:02d} | Best Evasion Score: {best_in_gen[0]:.1f} ({best_in_gen[2].verdict if best_in_gen[2] else 'UNDETECTED'})")
        
        # Breed next generation (keep top 20%, mutate the rest)
        elite_count = max(1, pop_size // 5)
        elites = [x[1] for x in scored_population[:elite_count]]
        
        population = elites[:]
        while len(population) < pop_size:
            parent = random.choice(elites)
            population.append(parent.mutate())

    print("\n=========================================================")
    print(" WINNING ADVERSARY PROFILE (Hardest to Detect) ")
    print("=========================================================")
    print(f"Evasion Score achieved: {lowest_score:.1f}")
    print(f"Trigger Delay:     {best_genome.trigger_delay_s:.0f}s (Evades S1 Trigger Window)")
    print(f"Domain/ASN:        {best_genome.domain_type} on {best_genome.asn_choice} ASN")
    print(f"Beacon Jitter:     {best_genome.beacon_jitter_pct*100:.0f}% on {best_genome.beacon_interval_s:.0f}s interval")
    print(f"Exfil Strategy:    {best_genome.exfil_chunk_count} chunks, {best_genome.exfil_up_ratio*100:.0f}% upstream ratio")
    print(f"Time of operation: {'Deep Night (Idle)' if best_genome.operate_during_idle else 'Daytime (Piggybacking)'}")
    print("=========================================================")

if __name__ == "__main__":
    run_fuzzing_generation(generations=10, pop_size=10)
