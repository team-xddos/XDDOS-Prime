# F5 Silverline — XDDOS PRIME Mitigation Guide

> **Vendor**: F5 (Silverline DDoS Protection + BIG-IP AFM)
> **Request**: Include XDDOS PRIME in managed DDoS protection rules
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

## Silverline Cloud — SOC Configuration Request

Silverline is a managed service. Submit this to the **F5 Silverline SOC** via the Customer Portal:

### Mitigation Request Template

```
Subject: Add XDDOS PRIME UDP Flood Signature to Default Protection

Description:
  XDDOS PRIME is an open-source raw UDP flood tool with a fixed,
  deterministic packet signature. Requesting addition to default
  scrubbing rules for all Silverline-protected prefixes.

Attack Fingerprint:
  Protocol:       UDP (17)
  IP TTL:         255 (always)
  IP TOS:         0x00 (always)
  Packet Size:    540 bytes (always)
  UDP Checksum:   0x0000 (always)
  IP IHL:         5 / no options (always)
  Payload:        512 bytes random data
  Source IPs:     Randomly spoofed

Recommended Rule:
  MATCH: Protocol=UDP AND TTL=255 AND PacketSize=540 AND UDPChecksum=0
  ACTION: DROP

False Positive Risk: ZERO
  No legitimate application produces packets matching all criteria.

Source Code: https://github.com/team-xddos/XDDOS-Prime
```

---

## BIG-IP AFM — On-Premises Rules

For customers with F5 BIG-IP Advanced Firewall Manager (AFM) deployed alongside Silverline:

### DoS Protection Profile

```
tmsh create security dos profile xddos_prime_protection {
    protocol-dns disabled
    protocol-sip disabled
    network {
        udp {
            rate-limit enabled
            rate-threshold 10000
            floor 1000
            auto-threshold enabled
            detection-mode fully-automatic
        }
    }
}
```

### Packet Filter — Exact Match

```bash
# Block XDDOS PRIME exact signature
tmsh create net packet-filter xddos_prime_block \
    order 1 \
    action discard \
    rule "( proto UDP ) and ( ip-ttl 255 ) and ( ip-len 540 )"
```

### Packet Filter — Relaxed Match

```bash
# Block XDDOS PRIME variants
tmsh create net packet-filter xddos_prime_relaxed \
    order 2 \
    action discard \
    rule "( proto UDP ) and ( ip-ttl 255 ) and ( ip-len >= 500 ) and ( ip-len <= 600 )"
```

### Packet Filter — Rate Limit High-TTL UDP

```bash
# Rate limit suspicious high-TTL UDP
tmsh create net packet-filter xddos_prime_rate \
    order 3 \
    action rate-class \
    rate-class xddos_rate_1mbps \
    rule "( proto UDP ) and ( ip-ttl >= 200 )"
```

### iRule — Advanced Detection

```tcl
# iRule: XDDOS_PRIME_DETECTOR
when CLIENT_ACCEPTED {
    # Check for XDDOS PRIME signature
    set ttl [IP::ttl]
    set pkt_len [IP::total_length]
    
    if { $ttl == 255 && [IP::protocol] == 17 && $pkt_len == 540 } {
        # Log and drop
        log local0. "XDDOS PRIME detected from [IP::client_addr]:[UDP::client_port]"
        drop
        return
    }
    
    # Rate limit high-TTL UDP
    if { $ttl >= 200 && [IP::protocol] == 17 } {
        set key "udp_rate_[IP::client_addr]"
        set count [table incr $key]
        if { $count == 1 } {
            table timeout $key 1
        }
        if { $count > 100 } {
            drop
            return
        }
    }
}
```

---

## Virtual Server Configuration

### Connection Rate Limiting

```bash
# Apply rate limiting to virtual server
tmsh modify ltm virtual my_udp_virtual \
    rate-limit 10000 \
    rate-limit-mode source \
    rate-limit-src-mask 24
```

---

## Monitoring

### tmsh Statistics

```bash
# Monitor packet filter hits
tmsh show net packet-filter xddos_prime_block
tmsh show net packet-filter xddos_prime_relaxed

# Monitor DoS profile stats
tmsh show security dos profile xddos_prime_protection
```

### SNMP Monitoring

```
OID: .1.3.6.1.4.1.3375.2.1.1.2.21 (ltmVirtualServStatDroppedPackets)
```

---

## Why This Should Be a Default Rule

1. **Deterministic signature** — Fixed header values make detection trivial
2. **Zero false positives** — No legitimate UDP stack produces this exact combination
3. **Open source** — F5 Labs can verify the signature from source code
4. **Single rule** — One packet filter handles 100% of attack traffic
5. **Growing threat** — Freely available tool with increasing adoption

---

## Contact

**TEAM XDDOS** — [github.com/team-xddos/XDDOS-Prime](https://github.com/team-xddos/XDDOS-Prime)
