# Deploying TELLTALE at the chokepoint

TELLTALE's logic is location-independent: feed it `FlowRecord`s and it hunts. The
deployment question is only *where do you stand to watch the wire*, and *how do you
turn packets into flow metadata cheaply and privately*.

The guiding principle: **stand on a boundary the attacker does not own.** An
implant is root on the phone. It is *not* root on your router.

```
        ┌──────────┐        ┌──────────────── chokepoint ────────────────┐
        │  phone   │  Wi-Fi │  router / DNS box / passive tap / gateway    │  WAN
        │ (implant)│ ◄─────► │  -- this is where TELLTALE listens --       │ ◄────► internet
        └──────────┘        └─────────────────────┬───────────────────────┘
                                                   │ flow metadata (JSONL)
                                                   ▼
                                       telltale analyze  (cron or stream)
```

---

## Vantage points, from easiest to best

1. **Offline triage (no deployment).** Capture on any box that sees the phone's
   traffic and analyze the file:
   ```bash
   # mirror/SPAN the phone's Wi-Fi, or run a hotspot from a laptop:
   sudo tcpdump -i en0 -w phone.pcap
   python3 -m telltale analyze phone.pcap --pcap
   ```
   Establish a baseline once on a clean day, then analyze new captures against it.

2. **DNS box (Pi-hole / unbound).** Query logs alone power S1 (message → novel
   domain), S2 (novelty), and most of S6 (the absence of a name). DNS is the
   cheapest, highest-signal vantage there is. Tail the query log → emit JSONL.

3. **Home router (OpenWRT / pfSense).** Export flows with the tools already on the
   box — **IPFIX/NetFlow** (`softflowd`, `pmacct`) or **conntrack** accounting —
   and convert to `FlowRecord` JSONL. This is the "small passive box" sweet spot.

4. **Linux gateway with eBPF.** The highest-fidelity, lowest-overhead sensor:
   attach to kernel hooks and emit a flow-start event per connection without ever
   copying payloads. See [`telltale-sensor.bt`](telltale-sensor.bt) for a working
   `bpftrace` sketch you can run today.

---

## The eBPF sensor (Linux gateway or endpoint)

`bpftrace -f json telltale-sensor.bt` emits one event per outbound TCP connect:
timestamp, process (`comm`/`pid` if on a host), destination, and port. On a host
endpoint the `comm` field is gold — it is the closest thing to "was there a
foreground app?" you can get without screen access: **a beacon from a process with
no UI is the tell.** On a pure gateway there is no process context, so you lean on
the network-shape signals instead (timing, direction, novelty, SNI absence).

A tiny adapter turns those events into the JSONL `analyze` expects:

```bash
bpftrace -f json deploy/telltale-sensor.bt \
  | python3 deploy/bt2flows.py \
  | python3 -m telltale analyze /dev/stdin --baseline baseline.jsonl
```

> `bt2flows.py` is intentionally left as a ~30-line exercise: map each connect
> event to a `FlowRecord` (fill `bytes_up/down` from a periodic conntrack poll,
> resolve `domain` from your DNS log, leave `asn` to an optional offline GeoIP
> lookup). The detection engine needs no more than that.

### Why eBPF/XDP and not libpcap on a busy gateway

- It runs **in-kernel** — you pay for the events you keep, not for copying every
  packet to user space.
- You attach exactly to the moments that matter (`tcp_connect`, DNS resolution),
  so the data volume is connection-scale, not packet-scale.
- It composes with the device's own keepalive accounting, so the **diurnal**
  baseline stays cheap to maintain 24/7.

---

## Privacy & ethics

- **Metadata only.** TELLTALE needs the 5-tuple, timing, byte counts, DNS names,
  and the *plaintext* TLS SNI/JA3 — never payload. It cannot read your messages
  because it never asks for them.
- **Local processing.** Nothing leaves the box. The baseline and flow logs are
  yours; keep them local.
- **Authorized use.** Watch only networks and devices you own or are authorized to
  protect. This is a shield, not a wiretap.

## Hardening the sensor itself

- Run the analyzer on a device *other* than the one you suspect, so a compromise
  of the phone cannot tamper with its own verdict.
- Keep the baseline on read-only media or a separate host; an attacker who can
  rewrite "normal" can hide in it.
- Rotate and sign flow logs if they feed an incident-response process.
