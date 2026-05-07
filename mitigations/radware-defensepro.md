# Radware DefensePro — XDDOS PRIME Mitigation Guide

> **Vendor**: Radware (DefensePro)
> **Request**: Add XDDOS PRIME to automatic behavioral detection baselines
> **Attack Tool**: [XDDOS PRIME](https://github.com/team-xddos/XDDOS-Prime)

---

## Attack Signature Summary

| Field | Value |
|-------|-------|
| Protocol | UDP (17) |
| IP TTL | 255 |
| IP TOS | 0x00 |
| Packet Size | 540 bytes |
| UDP Checksum | 0x0000 |
| UDP Payload | 512 bytes random (high entropy) |
| Source IPs | Fully spoofed (random) |

---

## BDoS (Behavioral DoS) — Baseline Integration

### Why BDoS Alone Is Not Enough

Radware's BDoS engine learns traffic baselines and detects anomalies. However:

- **Learning period** — BDoS requires 10–14 days to establish baseline. XDDOS PRIME attacks can start before learning completes.
- **Signature generation delay** — BDoS typically generates a filter 10–18 seconds after detection. At ~4 Gbps, this means ~5–9 GB of attack traffic passes through before mitigation kicks in.
- **Known signature** — Since XDDOS PRIME has a fixed, deterministic signature, there's no reason to wait for behavioral detection. A static signature eliminates it instantly.

### Recommendation

Add XDDOS PRIME as a **pre-defined signature** in DefensePro's signature database, applied **before** BDoS behavioral analysis.

---

## Network Protection Policy

### Step 1: Create Signature Profile

```
Configuration > Security > Signature Protection > Signature Profiles

Profile Name:     XDDOS_PRIME_SIGNATURE
Description:      Detects XDDOS PRIME raw UDP flood tool
Category:         DoS / Flood

Signature Rules:
  Rule 1 - Exact Match:
    Protocol:       UDP
    IP TTL:         255
    IP TOS:         0x00
    Packet Size:    540 bytes
    Direction:      Inbound
    Action:         Drop & Report
    Severity:       Critical
    Confidence:     High

  Rule 2 - Relaxed Match:
    Protocol:       UDP
    IP TTL:         >= 200
    Packet Size:    500-600 bytes
    Direction:      Inbound
    Action:         Drop & Report
    Severity:       High
    Confidence:     Medium
```

### Step 2: Create Network Protection Policy

```
Configuration > Network Protection > Network Protection Policies

Policy Name:        XDDOS_PRIME_PROTECTION
Source:              Any
Destination:        Protected_Network (your CIDR)
Direction:          Inbound

Applied Profiles:
  ├── Signature Profile:  XDDOS_PRIME_SIGNATURE
  ├── BDoS Profile:       Default (UDP flood detection)
  └── Connection Limit:   Enabled

BDoS Settings:
  ├── UDP Flood:          Enabled
  ├── Learning Mode:      Active
  ├── Sensitivity:        High
  └── Reporting:          Enabled
```

### Step 3: Configure Out-of-Profile (OOP) Detection

```
Configuration > Network Protection > Out-of-Profile

OOP Settings:
  Protocol:           UDP
  Baseline Deviation: 3x standard deviation
  Packet Size Alert:  Single size > 80% of traffic → Alert
  Source Diversity:    > 1000 unique IPs/10sec → Alert

Action:               Trigger BDoS + Apply XDDOS_PRIME_SIGNATURE
```

---

## Packet Scrubbing — Custom Filters

### Filter 1: Header-based Drop

```
Configuration > Security > Packet Anomaly Detection

Filter Name:      XDDOS_PRIME_HEADER_CHECK
Status:           Active

Conditions:
  AND:
    ├── IP Protocol = 17 (UDP)
    ├── IP TTL = 255
    ├── IP Total Length = 540
    └── UDP Checksum = 0

Action:           Drop
Log:              Yes
Alert:            Yes
```

### Filter 2: Rate Limiting

```
Configuration > Security > Connection Rate Limit

Rule Name:        XDDOS_PRIME_RATE_LIMIT
Protocol:         UDP
Source Mask:       /24
Destination:      Protected_Network

Thresholds:
  PPS Limit:      1,000 per source /24
  BPS Limit:      5 Mbps per source /24
  
Exceed Action:    Drop
Duration:         Until rate drops below threshold
```

---

## CLI Configuration (DefensePro CLI)

```bash
# Create signature filter for XDDOS PRIME
dp signatures filter add XDDOS_PRIME_EXACT \
    --protocol udp \
    --ip-ttl 255 \
    --packet-size 540 \
    --action drop \
    --severity critical \
    --log enable

# Create rate limit for high-TTL UDP
dp security rate-limit add XDDOS_PRIME_RATE \
    --protocol udp \
    --ip-ttl-min 200 \
    --source-mask 24 \
    --pps-limit 1000 \
    --exceed-action drop

# Apply to network protection policy
dp network-protection policy add XDDOS_PRIME_POLICY \
    --source any \
    --destination protected_network \
    --signature-profile XDDOS_PRIME_SIGNATURE \
    --bdos-profile default_udp \
    --rate-limit XDDOS_PRIME_RATE

# Commit changes
dp config commit
```

---

## APSolute Vision — Monitoring

### Attack Detection Dashboard

```
Monitoring > Security > Attack Log

Filter:
  ├── Signature:    XDDOS_PRIME_*
  ├── Protocol:     UDP
  ├── Severity:     Critical / High
  └── Time Range:   Real-time

Monitor:
  ├── Packets Dropped per second
  ├── Source IP diversity (should be very high)
  ├── Destination concentration (single IP/port)
  └── Attack duration
```

### SNMP Traps

```
Configure SNMP trap for:
  ├── rsBDoSAttackStarted      (BDoS attack detected)
  ├── rsSignatureAttackDetected (Signature match)
  └── rsRateLimitExceeded       (Rate limit triggered)

Send to: [your SIEM/monitoring system]
```

---

## Why This Should Be a Default Signature

1. **Fixed fingerprint** — Static header values make signature-based detection instant (vs 10-18 sec BDoS delay)
2. **Zero false positives** — No legitimate UDP stack produces TTL=255 + checksum=0 + 540 bytes
3. **Complements BDoS** — Static signature catches the attack immediately while BDoS handles variants
4. **Open source** — Radware's research team can verify from source code
5. **Simple rule** — 4 header field matches, no payload inspection needed

---

## Contact

**TEAM XDDOS** — [github.com/team-xddos/XDDOS-Prime](https://github.com/team-xddos/XDDOS-Prime)
