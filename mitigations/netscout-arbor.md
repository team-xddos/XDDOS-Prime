# Netscout Arbor — XDDOS PRIME Mitigation Guide

> **Vendor**: Netscout Arbor (Sightline + TMS)
> **Request**: Add `XDDOS_PRIME` as a default TMS countermeasure template in Sightline
> **Attack Tool**: [XDDOS PRIME](https://github.com/team-xddos/XDDOS-Prime)

---

## Attack Signature Summary

| Field | Value |
|-------|-------|
| Protocol | UDP (17) |
| IP TTL | 255 |
| IP TOS | 0x00 |
| IP IHL | 5 (no options) |
| Packet Size | 540 bytes |
| UDP Checksum | 0x0000 |
| UDP Payload | 512 bytes random (high entropy) |
| Source IPs | Fully spoofed (random) |
| Fragmentation | None |

---

## Sightline — Alert Configuration

### Managed Object Setup

Create a Managed Object (MO) for the protected infrastructure:

```
Administration > Managed Objects > Add Managed Object

Name:           Protected_Infrastructure
Match Type:     CIDR (your protected prefix)
CIDR:           x.x.x.x/24
Alert Settings: Profiled or Auto-Detect
```

### Alert Definition

```
Configuration > Detection > Alerts

Alert Name:     XDDOS_PRIME_DETECTION
Type:           Profiled (recommended) or Threshold
Protocol:       UDP

Severity Triggers:
  ├── UDP PPS         > 5x learned baseline to single /32 destination
  ├── UDP BPS         > 3x learned baseline
  ├── Packet Size     = 540 bytes comprises > 80% of UDP traffic
  └── Source IP Count > 1,000 unique /32s within 10-second window

Auto-Mitigation:  ENABLED
Template:         XDDOS_PRIME_MITIGATION (see below)
TMS Group:        [your TMS appliance group]
```

---

## TMS — Countermeasure Template

### Creating the Template

```
Administration > Mitigation > Templates > Add Template

Template Name:  XDDOS_PRIME_MITIGATION
Description:    Mitigates XDDOS PRIME raw UDP flood (TTL=255, UDP checksum=0, 540-byte fixed)
```

### Countermeasure 1: Filter-based Countermeasure (FCM) — Primary

This is the **highest confidence** rule. Zero false positive risk.

```
Countermeasure Type:  Filter (Packet Header)
Name:                 XDDOS_PRIME_EXACT_MATCH
Priority:             1 (highest)

Match Conditions (ALL must match):
  ├── IP Protocol:      UDP (17)
  ├── IP TTL:           255 (exact)
  ├── IP Total Length:  540 (exact)
  ├── IP TOS:           0x00
  ├── IP IHL:           5
  ├── UDP Checksum:     0x0000
  └── Fragmentation:    None (frag_off = 0)

Action:  DROP
Logging: Enabled (sample rate: 1:1000)
```

### Countermeasure 2: Filter-based Countermeasure — Relaxed Match

Catches variants where the attacker slightly modifies payload size:

```
Countermeasure Type:  Filter (Packet Header)
Name:                 XDDOS_PRIME_RELAXED
Priority:             2

Match Conditions (ALL must match):
  ├── IP Protocol:      UDP (17)
  ├── IP TTL:           255 (exact)
  ├── IP TOS:           0x00
  ├── UDP Checksum:     0x0000
  └── IP Total Length:  Between 500 and 600

Action:  DROP
Logging: Enabled
```

### Countermeasure 3: Rate-based Countermeasure

Handles cases where TTL or checksum might be normalized by intermediate routers:

```
Countermeasure Type:  Rate Limiting
Name:                 XDDOS_PRIME_RATE_LIMIT
Priority:             3

Match Conditions:
  ├── IP Protocol:      UDP (17)
  ├── IP Total Length:  536-544 bytes (±4 for encapsulation variance)
  └── IP TTL:           >= 200

Rate Limit:
  ├── Per Source /24:   1,000 PPS
  ├── Per Source /32:   100 PPS
  └── Global:           Auto-detect baseline

Action:  Rate-limit → DROP excess
Logging: Enabled
```

### Countermeasure 4: Payload Regex / Content Filter

Detects the high-entropy random payload characteristic of XDDOS PRIME:

```
Countermeasure Type:  Payload Regular Expression
Name:                 XDDOS_PRIME_PAYLOAD
Priority:             4

Match Conditions:
  ├── IP Protocol:       UDP (17)
  ├── Payload Length:    512 bytes (exact)
  ├── Entropy Analysis:  > 7.5 bits/byte (if supported)
  └── Protocol Match:    Does NOT match any known UDP protocol
                         (not DNS, NTP, SSDP, SNMP, etc.)

Action:  DROP
```

### Countermeasure 5: Zombie Detection

Identifies spoofed sources by checking for return traffic:

```
Countermeasure Type:  Zombie Detection
Name:                 XDDOS_PRIME_ZOMBIE
Priority:             5

Settings:
  ├── Mode:             Active
  ├── Protocol:         UDP
  ├── Timeout:          5 seconds
  ├── No-response:      Mark as zombie → DROP
  └── Threshold:        10 PPS from unverified source

Action:  DROP traffic from zombie-classified sources
```

---

## Complete Template Structure

```
Template: XDDOS_PRIME_MITIGATION
│
├── [P1] FCM: XDDOS_PRIME_EXACT_MATCH
│         TTL=255 + UDP_Checksum=0 + Size=540 → DROP
│
├── [P2] FCM: XDDOS_PRIME_RELAXED
│         TTL=255 + UDP_Checksum=0 + Size=500-600 → DROP
│
├── [P3] Rate Limit: XDDOS_PRIME_RATE_LIMIT
│         TTL>=200 + UDP + Size=536-544 → Rate-limit 1000pps/source
│
├── [P4] Payload: XDDOS_PRIME_PAYLOAD
│         512-byte high-entropy non-protocol payload → DROP
│
├── [P5] Zombie: XDDOS_PRIME_ZOMBIE
│         No return traffic from source → DROP
│
└── Logging: All countermeasures → Sightline event log
```

---

## Flowspec Integration (BGP-Based Edge Filtering)

For upstream filtering before traffic reaches TMS, push these via BGP Flowspec:

```
Flowspec Rule 1 (Exact Match):
  match:
    protocol:       UDP
    packet-length:  540
    ip-ttl:         255
  action:
    traffic-action: discard

Flowspec Rule 2 (Rate Limit):
  match:
    protocol:       UDP
    packet-length:  >=500 <=600
    ip-ttl:         >=200
  action:
    traffic-rate:   10000 (10 Kbps — effectively drops most attack traffic)
```

---

## Verification & Monitoring

### Sightline Dashboard

After deploying the template, monitor these metrics:

```
Monitoring > Mitigation > Active Mitigations

Check:
  ├── Packets matched per countermeasure
  ├── Drop rate vs pass rate
  ├── Source IP cardinality (should be extremely high for XDDOS PRIME)
  ├── Packet size distribution (should show spike at 540 bytes)
  └── False positive rate (should be 0% with exact match rule)
```

### TMS Real-Time Dashboard

```
TMS > Real-Time Mitigation Dashboard

Verify:
  ├── XDDOS_PRIME_EXACT_MATCH is dropping > 99% of attack traffic
  ├── No legitimate traffic matching the filter (check pass counters)
  └── Attack traffic completely eliminated before reaching protected network
```

---

## Why This Should Be a Default Template

1. **Fixed, deterministic signature** — TTL=255 + UDP checksum=0 + 540 bytes is not produced by any legitimate application
2. **Zero false positive risk** — No legitimate UDP stack sends packets with all these characteristics simultaneously
3. **Open-source tool** — Source code is publicly available for verification at [github.com/team-xddos/XDDOS-Prime](https://github.com/team-xddos/XDDOS-Prime)
4. **Growing adoption** — Tool is freely available and actively used in the wild
5. **Simple to implement** — Single FCM rule with 4 header field matches

---

## Contact

**TEAM XDDOS** — [github.com/team-xddos/XDDOS-Prime](https://github.com/team-xddos/XDDOS-Prime)
