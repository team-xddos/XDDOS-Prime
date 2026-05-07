# XDDOS PRIME — Threat Analysis & Mitigation Guide

> **Purpose**: This document provides a complete traffic signature analysis of the XDDOS PRIME UDP flood tool, enabling DDoS mitigation vendors — particularly **Netscout Arbor (Sightline/TMS)**, **Cloudflare Magic Transit**, **Akamai Prolexic**, and **F5 Silverline** — to build default mitigation profiles that detect and neutralize this attack pattern automatically.

---

## 📋 Table of Contents

- [Attack Overview](#attack-overview)
- [Traffic Fingerprint](#traffic-fingerprint)
- [Detection Signatures](#detection-signatures)
- [Mitigation Rules](#mitigation-rules)
  - [Netscout Arbor Sightline / TMS](#netscout-arbor-sightline--tms)
  - [Cloudflare Magic Transit](#cloudflare-magic-transit)
  - [Akamai Prolexic](#akamai-prolexic)
  - [Generic Firewall Rules (iptables / nftables)](#generic-firewall-rules)
- [PCAP Signature](#pcap-signature)
- [Snort / Suricata Rules](#snort--suricata-rules)
- [Call to Action for Vendors](#call-to-action-for-vendors)

---

## Attack Overview

| Property | Value |
|----------|-------|
| **Tool Name** | XDDOS PRIME (`rawudp`) |
| **Attack Type** | UDP Flood (Volumetric) |
| **Layer** | L3/L4 (Network/Transport) |
| **Protocol** | UDP over IPv4 |
| **Spoofing** | Full source IP randomization (RAW mode) |
| **Amplification** | None — direct flood |
| **Packet Size** | 540 bytes (20 IP + 8 UDP + 512 payload) |
| **Payload** | 512 bytes of random data |
| **Threading** | Multi-threaded (typically 8–64 threads) |
| **Throughput** | ~4 Gbps per node (cloud environment) |
| **Source** | [github.com/team-xddos/XDDOS-Prime](https://github.com/team-xddos/XDDOS-Prime) |

---

## Traffic Fingerprint

The following unique characteristics identify XDDOS PRIME traffic and distinguish it from legitimate UDP flows:

### IP Header Fingerprint

| Field | Value | Notes |
|-------|-------|-------|
| **Version** | `4` | IPv4 only |
| **IHL** | `5` (20 bytes) | No IP options — minimum header |
| **TOS / DSCP** | `0x00` | Always zero — no QoS markings |
| **Total Length** | `540` (`0x021C`) | Fixed — never varies |
| **IP ID** | Random (CMWC) | Uniformly distributed, no sequencing |
| **Flags / Frag Offset** | `0x0000` | No fragmentation flags, no DF bit |
| **TTL** | `255` | Maximum value — major red flag |
| **Protocol** | `17` (UDP) | — |
| **Source IP** | Random (CMWC) | Full 32-bit range, no subnet pattern |
| **Checksum** | Valid | Properly calculated |

### UDP Header Fingerprint

| Field | Value | Notes |
|-------|-------|-------|
| **Source Port** | Random (full 0–65535 range) | No weighting toward common ports |
| **Destination Port** | Fixed (user-specified) | All packets hit same port |
| **Length** | `520` (`0x0208`) | Fixed — 8 header + 512 payload |
| **Checksum** | `0x0000` | **Always zero** — UDP checksum disabled |

### Payload Fingerprint

| Property | Value |
|----------|-------|
| **Size** | Exactly 512 bytes |
| **Content** | Pseudo-random (CMWC PRNG) |
| **Entropy** | Very high (~7.99 bits/byte) |
| **Pattern** | No protocol structure, no ASCII, no repeating patterns |

---

## Detection Signatures

### Primary Indicators (High Confidence)

Any **3 or more** of these simultaneously = XDDOS PRIME with high confidence:

1. **TTL = 255** — Legitimate traffic almost never uses max TTL. Most OS defaults: Windows=128, Linux=64, macOS=64
2. **UDP checksum = 0** — Legitimate UDP stacks almost always compute checksums
3. **Fixed packet size = 540 bytes** — Constant across all packets in the flow
4. **IP TOS = 0 + IHL = 5** — No options, no DSCP markings
5. **No fragmentation flags** — DF bit not set, no fragments
6. **High entropy payload** — 512 bytes of random data with no protocol structure
7. **Source IP diversity** — Thousands of unique source IPs with no subnet clustering
8. **Single destination port** — All traffic hits one port from random source ports

### Secondary Indicators

- **No return traffic** — Purely unidirectional flood
- **No prior DNS resolution** — Source IPs have no PTR records
- **Rate anomaly** — Sudden spike in UDP PPS to a single destination
- **IP ID non-sequential** — Random IP IDs with no incrementing pattern

---

## Mitigation Rules

### Netscout Arbor Sightline / TMS

#### Countermeasure: UDP Filter

Arbor TMS operators can create a **Managed Object** with the following countermeasures:

**1. Filter-based Countermeasure (FCM)**

```
Filter Name: XDDOS_PRIME_UDP_FLOOD
Match Conditions:
  - Protocol: UDP (17)
  - IP TTL: 255
  - UDP Checksum: 0
  - Packet Size: 540 bytes
  - IP Header Length: 20 bytes (IHL=5)
  - IP TOS: 0
Action: Drop
```

**2. Rate-based Countermeasure**

```
Countermeasure: UDP Rate Limiting
  Protocol: UDP
  Threshold: Auto-detect baseline
  Packet Size Filter: 536-544 bytes (allow ±4 for encapsulation)
  Rate Limit: 10% of baseline or 1000 PPS per source subnet /24
  Action: Rate-limit → Drop excess
```

**3. Payload Regex Countermeasure**

Since the payload is random with high entropy and no protocol structure:

```
Countermeasure: Payload Analysis
  Protocol: UDP
  Payload Length: 512 bytes (exact)
  Entropy Check: > 7.5 bits/byte
  Known Protocol Match: None
  Action: Drop
```

**4. Recommended Arbor TMS Template**

```
Template: XDDOS_PRIME_MITIGATION
  ├── FCM: TTL=255 + UDP Checksum=0 → DROP
  ├── FCM: Packet Size=540 + Protocol=UDP → RATE-LIMIT (1000 pps)
  ├── DNS Malformed: ENABLED (payload is not valid DNS)
  ├── UDP Reflection: ENABLED
  ├── Zombie Detection: ENABLED (no return traffic from sources)
  └── Black/White List: Auto-populate from detected source IPs
```

**5. Arbor Sightline Alert Configuration**

```
Alert: XDDOS_PRIME_DETECTION
  Type: Profiled (or Auto)
  Protocol: UDP
  Severity Trigger:
    - UDP PPS > 5x baseline to single host
    - Packet size = 540 bytes > 80% of UDP traffic
    - Source IP cardinality > 1000 unique /32s in 10 seconds
  Auto-Mitigation: Enable → Apply XDDOS_PRIME_MITIGATION template
```

---

### Cloudflare Magic Transit

#### Network Analytics Filter

```
Firewall Rule: Block XDDOS PRIME
  Expression:
    ip.proto == 17 AND
    ip.ttl == 255 AND
    ip.len == 540 AND
    udp.checksum == 0
  Action: Block
```

#### Rate Limiting (Advanced)

```
Rule: Rate Limit Suspicious UDP
  Expression:
    ip.proto == 17 AND
    ip.ttl >= 200 AND
    ip.len >= 536 AND ip.len <= 544
  Rate: 100 requests per second per /24 source
  Action: Block for 60 seconds
```

---

### Akamai Prolexic

#### Recommended Profile

```
Mitigation Profile: XDDOS_PRIME
  Protocol: UDP
  Detection:
    - Volumetric UDP flood to single destination
    - Packet signature: TTL=255, Size=540, UDP_Checksum=0
  Mitigation:
    - ACL: Block UDP with TTL=255 + Checksum=0
    - Rate shape: UDP 540-byte packets > 500 PPS per source /24
    - Scrubbing: Enable deep packet inspection
    - Payload validation: Drop non-protocol-conformant UDP
```

---

### Generic Firewall Rules

#### iptables (Linux)

```bash
# Block XDDOS PRIME signature: TTL=255 + UDP + 540 byte packets
iptables -A INPUT -p udp -m ttl --ttl-eq 255 -m length --length 540 -j DROP

# Rate limit suspicious UDP patterns
iptables -A INPUT -p udp -m ttl --ttl-eq 255 -m hashlimit \
  --hashlimit-above 100/sec --hashlimit-burst 50 \
  --hashlimit-mode srcip --hashlimit-name udp_flood \
  -j DROP

# Log and drop for forensics
iptables -A INPUT -p udp -m ttl --ttl-eq 255 -m length --length 540 \
  -j LOG --log-prefix "XDDOS_PRIME: " --log-level 4
iptables -A INPUT -p udp -m ttl --ttl-eq 255 -m length --length 540 -j DROP
```

#### nftables (Linux)

```bash
nft add rule inet filter input \
  ip protocol udp \
  ip ttl 255 \
  meta length 540 \
  drop

nft add rule inet filter input \
  ip protocol udp \
  ip ttl 255 \
  limit rate over 100/second \
  drop
```

---

## PCAP Signature

For mitigation vendors doing PCAP-based analysis, here's the expected packet structure:

```
Frame (540 bytes on wire):
├── IP Header (20 bytes)
│   ├── Version: 4
│   ├── IHL: 5
│   ├── TOS: 0x00
│   ├── Total Length: 540
│   ├── ID: [random]
│   ├── Flags: 0x00 (none set)
│   ├── Fragment Offset: 0
│   ├── TTL: 255
│   ├── Protocol: 17 (UDP)
│   ├── Checksum: [valid]
│   ├── Source: [random spoofed]
│   └── Destination: [target]
├── UDP Header (8 bytes)
│   ├── Source Port: [random 0-65535]
│   ├── Destination Port: [target port]
│   ├── Length: 520
│   └── Checksum: 0x0000          ← KEY INDICATOR
└── Payload (512 bytes)
    └── [high-entropy random data] ← KEY INDICATOR
```

### Wireshark Display Filter

```
udp.checksum == 0x0000 && ip.ttl == 255 && frame.len == 554
```

> Note: `frame.len` = 540 + 14 (Ethernet header) = 554 at the capture level.

### BPF Filter (tcpdump)

```bash
tcpdump -i eth0 'udp and ip[8]=255 and ip[2:2]=540' -c 100 -w xddos_capture.pcap
```

---

## Snort / Suricata Rules

### Snort 3

```
alert udp any any -> $HOME_NET any (
    msg:"XDDOS PRIME UDP Flood Detected";
    ttl:255;
    dsize:512;
    flags:0;
    metadata:service udp, attack_type flood;
    classtype:attempted-dos;
    sid:1000001;
    rev:1;
)
```

### Suricata

```yaml
alert udp any any -> $HOME_NET any (
    msg:"XDDOS PRIME UDP Flood - TTL255 + Zero Checksum";
    ttl:255;
    dsize:512;
    udp.hdr;
    content:"|00 00|"; offset:6; depth:2;  # UDP checksum = 0
    threshold: type both, track by_dst, count 100, seconds 10;
    classtype:attempted-dos;
    sid:2000001;
    rev:1;
)
```

---

## Call to Action for Vendors

### Why Default Mitigation Profiles Are Needed

XDDOS PRIME is an **open-source, freely available** UDP flood tool. Its fixed traffic signature makes it trivially detectable — yet **no major mitigation platform currently ships a default profile** for it.

### What We're Asking

| Vendor | Request |
|--------|---------|
| **Netscout Arbor** | Add `XDDOS_PRIME` as a default TMS countermeasure template in Sightline |
| **Cloudflare** | Include signature in Magic Transit's automatic DDoS detection |
| **Akamai Prolexic** | Add to default scrubbing signatures |
| **F5 Silverline** | Include in managed DDoS protection rules |
| **Radware DefensePro** | Add to automatic behavioral detection baselines |
| **AWS Shield Advanced** | Include pattern in automatic L3/L4 mitigation |
| **Azure DDoS Protection** | Add to standard protection detection signatures |
| **Google Cloud Armor** | Include in network DDoS protection policies |

### Traffic Characteristics Summary for Quick Implementation

```
MATCH ALL:
  ✓ Protocol    = UDP (17)
  ✓ TTL         = 255
  ✓ Packet Size = 540 bytes
  ✓ UDP Chksum  = 0x0000
  ✓ IP IHL      = 5 (no options)
  ✓ IP TOS      = 0x00
  ✓ Payload     = 512 bytes high-entropy random
  ✓ No fragmentation
ACTION:
  → DROP
```

This single rule would neutralize 100% of XDDOS PRIME traffic with **zero false positives** — no legitimate application sends UDP packets matching all these criteria simultaneously.

---

## Contact

**TEAM XDDOS**
- **XDMEOW** — Shadow
- **XDCAT** — Vansh
- **Repository**: [github.com/team-xddos/XDDOS-Prime](https://github.com/team-xddos/XDDOS-Prime)
- **Issues**: [github.com/team-xddos/XDDOS-Prime/issues](https://github.com/team-xddos/XDDOS-Prime/issues)

> For responsible disclosure or to report misuse, open an issue on the repository.
