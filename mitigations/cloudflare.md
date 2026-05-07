# Cloudflare — XDDOS PRIME Mitigation Guide

> **Vendor**: Cloudflare (Magic Transit + Network Firewall)
> **Request**: Include XDDOS PRIME signature in Magic Transit's automatic DDoS detection
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

## Magic Transit — DDoS Managed Rulesets

### Recommended Managed Rule Addition

Cloudflare should add the following to the **Network-layer DDoS Attack Protection** managed ruleset:

```
Rule ID:          cf-xddos-prime-udp-flood
Rule Name:        XDDOS PRIME UDP Flood
Category:         UDP Flood
Sensitivity:      High (default)
Action:           Block (default)

Match Expression:
  ip.proto == 17 AND
  ip.ttl == 255 AND
  ip.len == 540 AND
  ip.hdr_len == 20
```

This rule should be **always-on** and included in the default managed ruleset for all Magic Transit customers.

---

## Network Firewall (Magic Firewall) — Custom Rules

For customers who want to deploy protection immediately, create these rules in the Cloudflare dashboard or via API.

### Rule 1: Exact Signature Block (Highest Priority)

**Dashboard**: Network Security > Magic Firewall > Add Rule

```
Rule Name:    Block XDDOS PRIME - Exact Match
Expression:   ip.proto == 17 and ip.ttl == 255 and ip.len == 540
Action:       Block
Priority:     1
```

### Rule 2: Relaxed Signature Block

```
Rule Name:    Block XDDOS PRIME - Relaxed
Expression:   ip.proto == 17 and ip.ttl == 255 and ip.len >= 500 and ip.len <= 600
Action:       Block
Priority:     2
```

### Rule 3: Rate Limit Suspicious UDP

```
Rule Name:    Rate Limit Suspicious UDP (TTL 255)
Expression:   ip.proto == 17 and ip.ttl >= 200
Rate:         100 requests per 10 seconds per source /24
Action:       Block for 60 seconds
Priority:     3
```

---

## API Configuration

### Create Firewall Rule via Cloudflare API

```bash
# Set variables
CF_API_TOKEN="your-api-token"
ACCOUNT_ID="your-account-id"
RULESET_ID="your-magic-firewall-ruleset-id"

# Add XDDOS PRIME block rule
curl -X POST \
  "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/rulesets/${RULESET_ID}/rules" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "expression": "ip.proto == 17 and ip.ttl == 255 and ip.len == 540",
    "description": "Block XDDOS PRIME UDP Flood (TTL=255, Size=540)",
    "enabled": true
  }'
```

### Create Rate Limiting Rule via API

```bash
curl -X POST \
  "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/rulesets/${RULESET_ID}/rules" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "expression": "ip.proto == 17 and ip.ttl >= 200 and ip.len >= 500 and ip.len <= 600",
    "description": "Block suspicious UDP flood variants (high TTL, ~540 bytes)",
    "enabled": true
  }'
```

---

## Network Analytics — Detection

### GraphQL Query for Monitoring

Use the Network Analytics GraphQL API to detect XDDOS PRIME traffic:

```graphql
query XddosPrimeDetection($accountTag: string!, $since: Time!, $until: Time!) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      magicTransitNetworkAnalyticsAdaptiveGroups(
        filter: {
          datetime_geq: $since,
          datetime_leq: $until,
          ipProtocol: 17,
          ipTtl: 255
        }
        limit: 100
        orderBy: [sum_packets_DESC]
      ) {
        dimensions {
          destinationIP
          destinationPort
          ipTtl
        }
        sum {
          packets
          bytes
        }
      }
    }
  }
}
```

### Dashboard Monitoring

```
Navigate: Analytics & Logs > Network Analytics

Filter:
  ├── Protocol:     UDP
  ├── Action:       Blocked
  ├── Packet Size:  ~540 bytes
  └── Time Range:   Last 24 hours

Look for:
  ├── Spike in blocked UDP packets
  ├── High source IP diversity
  └── Single destination IP/port concentration
```

---

## Terraform Configuration

For infrastructure-as-code deployments:

```hcl
resource "cloudflare_magic_firewall_ruleset" "xddos_prime_protection" {
  account_id  = var.cloudflare_account_id
  name        = "XDDOS PRIME Protection"
  description = "Blocks XDDOS PRIME UDP flood attack pattern"

  rules {
    action      = "block"
    expression  = "ip.proto == 17 and ip.ttl == 255 and ip.len == 540"
    description = "Block XDDOS PRIME exact signature"
    enabled     = true
  }

  rules {
    action      = "block"
    expression  = "ip.proto == 17 and ip.ttl == 255 and ip.len >= 500 and ip.len <= 600"
    description = "Block XDDOS PRIME variants"
    enabled     = true
  }
}
```

---

## Why This Should Be in Managed Rulesets

1. **Trivially detectable** — 3 header fields uniquely identify this attack
2. **Zero false positives** — No legitimate application uses TTL=255 + UDP checksum=0 + 540 bytes
3. **Open source** — Full source code available for Cloudflare's threat research team
4. **Single rule** — One expression handles 100% of this tool's traffic
5. **No performance impact** — Header-only matching, no payload inspection needed

---

## Contact

**TEAM XDDOS** — [github.com/team-xddos/XDDOS-Prime](https://github.com/team-xddos/XDDOS-Prime)
