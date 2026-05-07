# AWS Shield Advanced — XDDOS PRIME Mitigation Guide

> **Vendor**: Amazon Web Services (Shield Advanced + Network Firewall)
> **Request**: Include XDDOS PRIME pattern in automatic L3/L4 mitigation
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

## AWS Shield Advanced — Automatic Detection

### Current Gap

AWS Shield Advanced provides **automatic** L3/L4 DDoS mitigation but uses generic volumetric detection. It does **not** currently have a specific signature for XDDOS PRIME traffic, meaning:

- Detection relies on traffic volume anomalies
- Mitigation triggers only after thresholds are breached
- Attack traffic passes until automatic detection kicks in

### Recommended Enhancement

AWS should add XDDOS PRIME to its **automatic mitigation signatures**:

```
Signature: XDDOS_PRIME_UDP_FLOOD
Layer:     L3/L4 (Network/Transport)
Protocol:  UDP

Match (ALL):
  ├── IP TTL:         255
  ├── IP Total Len:   540
  ├── UDP Checksum:   0x0000
  └── IP TOS:         0x00

Action:    Automatic drop
Mode:      Always-on (pre-threshold)
```

---

## Shield Response Team (SRT) — Engagement Template

Shield Advanced customers have 24/7 access to the SRT. Use this template:

```
Subject: Custom Mitigation for XDDOS PRIME UDP Flood

Attack Details:
  Tool:           XDDOS PRIME (open-source UDP flooder)
  Source Code:    https://github.com/team-xddos/XDDOS-Prime
  Protocol:       UDP
  Spoofing:       Full source IP randomization

Packet Signature:
  IP TTL:         255 (always)
  Packet Size:    540 bytes (always)
  UDP Checksum:   0x0000 (always)
  IP TOS:         0x00 (always)
  Payload:        512 bytes random data

Request:
  1. Add signature-based drop rule for exact match
  2. Apply to all protected resources
  3. Enable always-on (proactive, not threshold-triggered)

False Positive Assessment:
  ZERO risk — no legitimate application uses TTL=255 + UDP checksum=0 + 540 bytes
```

---

## AWS Network Firewall — Custom Rules

For customers who want immediate protection alongside Shield Advanced:

### Suricata-compatible Rule (Network Firewall uses Suricata)

```yaml
# Rule Group: XDDOS_PRIME_PROTECTION
# Capacity: 10

# Rule 1: Exact signature match
drop udp any any -> $HOME_NET any (
    msg:"XDDOS PRIME UDP Flood - Exact Match";
    ttl:255;
    dsize:512;
    threshold: type both, track by_dst, count 50, seconds 10;
    classtype:attempted-dos;
    sid:1000001;
    rev:1;
)

# Rule 2: Relaxed match for variants
drop udp any any -> $HOME_NET any (
    msg:"XDDOS PRIME UDP Flood - Variant";
    ttl:>200;
    dsize:>400<600;
    threshold: type both, track by_dst, count 100, seconds 10;
    classtype:attempted-dos;
    sid:1000002;
    rev:1;
)
```

### AWS CLI — Create Firewall Rule Group

```bash
# Create the rule group
aws network-firewall create-rule-group \
    --rule-group-name "XDDOS-PRIME-Protection" \
    --type STATELESS \
    --capacity 10 \
    --rule-group '{
        "RulesSource": {
            "StatelessRulesAndCustomActions": {
                "StatelessRules": [
                    {
                        "Priority": 1,
                        "RuleDefinition": {
                            "MatchAttributes": {
                                "Protocols": [17],
                                "Sources": [{"AddressDefinition": "0.0.0.0/0"}],
                                "Destinations": [{"AddressDefinition": "YOUR_CIDR/24"}],
                                "SourcePorts": [{"FromPort": 0, "ToPort": 65535}],
                                "DestinationPorts": [{"FromPort": 0, "ToPort": 65535}]
                            },
                            "Actions": ["aws:drop"]
                        }
                    }
                ],
                "CustomActions": []
            }
        }
    }' \
    --tags Key=Purpose,Value=DDoS-Mitigation \
    --region us-east-1
```

> **Note**: AWS Network Firewall stateless rules don't support TTL matching directly. Use **stateful Suricata rules** (shown above) for full signature matching.

### Stateful Rule Group (Suricata-based)

```bash
aws network-firewall create-rule-group \
    --rule-group-name "XDDOS-PRIME-Stateful" \
    --type STATEFUL \
    --capacity 10 \
    --rule-group '{
        "RulesSource": {
            "RulesString": "drop udp any any -> any any (msg:\"XDDOS PRIME UDP Flood\"; ttl:255; dsize:512; sid:1000001; rev:1;)"
        }
    }' \
    --region us-east-1
```

---

## VPC Network ACLs — Quick Protection

For immediate, simple protection at the VPC level:

```bash
# If your application doesn't need UDP at all, block it entirely:
aws ec2 create-network-acl-entry \
    --network-acl-id acl-xxxxxxxx \
    --rule-number 50 \
    --protocol udp \
    --rule-action deny \
    --ingress \
    --cidr-block 0.0.0.0/0 \
    --port-range From=0,To=65535

# Or block only the specific target port being attacked:
aws ec2 create-network-acl-entry \
    --network-acl-id acl-xxxxxxxx \
    --rule-number 50 \
    --protocol udp \
    --rule-action deny \
    --ingress \
    --cidr-block 0.0.0.0/0 \
    --port-range From=TARGET_PORT,To=TARGET_PORT
```

---

## Security Groups — Per-Instance Protection

```bash
# Remove UDP access if not needed
aws ec2 revoke-security-group-ingress \
    --group-id sg-xxxxxxxx \
    --protocol udp \
    --port 0-65535 \
    --cidr 0.0.0.0/0

# Or restrict UDP to only known source IPs
aws ec2 authorize-security-group-ingress \
    --group-id sg-xxxxxxxx \
    --protocol udp \
    --port YOUR_UDP_PORT \
    --cidr TRUSTED_IP/32
```

---

## CloudWatch — Monitoring & Alerting

### Shield Advanced Metrics

```bash
# Create CloudWatch alarm for DDoS detection
aws cloudwatch put-metric-alarm \
    --alarm-name "XDDOS-PRIME-Detection" \
    --metric-name "DDoSDetected" \
    --namespace "AWS/DDoSProtection" \
    --statistic Maximum \
    --period 60 \
    --threshold 1 \
    --comparison-operator GreaterThanOrEqualToThreshold \
    --evaluation-periods 1 \
    --alarm-actions "arn:aws:sns:us-east-1:ACCOUNT:ddos-alerts"
```

### Network Firewall Metrics

```bash
# Monitor dropped packets
aws cloudwatch get-metric-statistics \
    --namespace "AWS/NetworkFirewall" \
    --metric-name "DroppedPackets" \
    --dimensions Name=FirewallName,Value=my-firewall \
    --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
    --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
    --period 300 \
    --statistics Sum
```

---

## Terraform Configuration

```hcl
# AWS Network Firewall rule group for XDDOS PRIME
resource "aws_networkfirewall_rule_group" "xddos_prime" {
  capacity = 10
  name     = "xddos-prime-protection"
  type     = "STATEFUL"

  rule_group {
    rules_source {
      rules_string = <<EOF
drop udp any any -> $HOME_NET any (msg:"XDDOS PRIME UDP Flood"; ttl:255; dsize:512; sid:1000001; rev:1;)
drop udp any any -> $HOME_NET any (msg:"XDDOS PRIME Variant"; ttl:>200; dsize:>400<600; sid:1000002; rev:1;)
EOF
    }
  }

  tags = {
    Purpose = "DDoS-Mitigation"
    Threat  = "XDDOS-PRIME"
  }
}
```

---

## Why This Should Be in Automatic Mitigation

1. **Deterministic signature** — Header-only matching, no heuristics needed
2. **Zero false positives** — No legitimate UDP traffic matches this exact combination
3. **Complements Shield** — Static signature catches attack instantly vs. waiting for volume anomaly
4. **Open source** — AWS security team can verify from source code
5. **Growing threat** — Tool is freely available and actively distributed

---

## Contact

**TEAM XDDOS** — [github.com/team-xddos/XDDOS-Prime](https://github.com/team-xddos/XDDOS-Prime)
