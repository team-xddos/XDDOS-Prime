# Akamai Prolexic — XDDOS PRIME Mitigation Guide

> **Vendor**: Akamai (Prolexic + Network Cloud Firewall)
> **Request**: Add XDDOS PRIME to default scrubbing signatures
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

## Prolexic — Proactive Mitigation Posture

### Recommended Default Scrubbing Signature

Akamai SOCC should add the following to the **proactive mitigation controls** applied during onboarding:

```
Signature Name:   XDDOS_PRIME_UDP_FLOOD
Category:         Volumetric UDP Flood
Severity:         Critical

Match (ALL):
  ├── Protocol:       UDP (17)
  ├── IP TTL:         255
  ├── Packet Size:    540 bytes total
  ├── UDP Checksum:   0x0000
  ├── IP TOS:         0x00
  └── IP IHL:         5 (20 bytes, no options)

Action:  DROP
Mode:    Always-on (proactive)
```

### Why Proactive (Not Reactive)

This signature has **zero false positive risk**. No legitimate UDP application produces packets matching all 6 criteria. It should be enabled in proactive mode without waiting for an attack to be detected.

---

## Network Cloud Firewall — ACL Rules

For Prolexic customers with access to **Network Cloud Firewall** via Akamai Control Center:

### Rule 1: Exact Match (Drop)

```
Rule Name:        XDDOS_PRIME_BLOCK
Direction:        Inbound
Priority:         High

Source:            Any
Destination:      Protected Prefixes

Match:
  Protocol:       UDP
  IP TTL:         255
  Packet Length:  540
  
Action:           Deny
Logging:          Enabled
```

### Rule 2: Relaxed Match (Drop)

```
Rule Name:        XDDOS_PRIME_VARIANT_BLOCK
Direction:        Inbound
Priority:         Medium

Source:            Any
Destination:      Protected Prefixes

Match:
  Protocol:       UDP
  IP TTL:         >= 200
  Packet Length:  500-600

Action:           Deny
Logging:          Enabled
```

### Rule 3: Rate Limit

```
Rule Name:        XDDOS_PRIME_RATE_LIMIT
Direction:        Inbound
Priority:         Low

Source:            Any /24
Destination:      Protected Prefixes

Match:
  Protocol:       UDP
  IP TTL:         >= 200

Rate Limit:       1,000 PPS per source /24
Exceed Action:    Deny
Logging:          Enabled
```

---

## SOCC Engagement — Attack Briefing Template

When engaging the Akamai SOCC about XDDOS PRIME, provide this briefing:

```
Subject: XDDOS PRIME UDP Flood — Signature for Default Mitigation

Attack Tool:      XDDOS PRIME (open-source)
Source Code:      https://github.com/team-xddos/XDDOS-Prime
Attack Type:      Raw UDP flood with spoofed source IPs

Unique Fingerprint:
  - IP TTL:         Always 255 (no legitimate OS uses this)
  - UDP Checksum:   Always 0x0000 (tool skips checksum)
  - Packet Size:    Always 540 bytes (20 IP + 8 UDP + 512 random payload)
  - IP TOS:         Always 0x00
  - IP Options:     None (IHL=5)
  - Source IPs:     Randomly generated (CMWC PRNG, no pattern)
  - Payload:        512 bytes of pseudo-random data, no protocol structure

Recommended Action:
  Add to proactive mitigation posture as an always-on drop rule.
  Single ACL matching TTL=255 + UDP + Size=540 eliminates 100%.
  Zero false positive risk confirmed via source code analysis.
```

---

## Service Validation Checklist

During onboarding or mitigation posture review:

| Step | Action | Status |
|------|--------|--------|
| 1 | Review protected prefix UDP traffic baseline | ☐ |
| 2 | Confirm no legitimate services send TTL=255 UDP | ☐ |
| 3 | Deploy XDDOS_PRIME_BLOCK ACL rule | ☐ |
| 4 | Deploy XDDOS_PRIME_RATE_LIMIT rule | ☐ |
| 5 | Enable proactive mitigation signature | ☐ |
| 6 | Verify rule in monitoring-only mode (24 hours) | ☐ |
| 7 | Switch to active blocking mode | ☐ |
| 8 | Confirm zero false positives in logs | ☐ |

---

## Why This Should Be a Default Signature

1. **Deterministic fingerprint** — 4 header fields uniquely identify this attack
2. **Zero false positives** — Confirmed via source code analysis
3. **Open source** — Available for Akamai's threat research team to verify
4. **Simple implementation** — Single ACL rule
5. **Growing threat** — Tool is freely available and being distributed

---

## Contact

**TEAM XDDOS** — [github.com/team-xddos/XDDOS-Prime](https://github.com/team-xddos/XDDOS-Prime)
