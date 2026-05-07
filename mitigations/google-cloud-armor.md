# Google Cloud Armor — XDDOS PRIME Mitigation Guide

> **Vendor**: Google Cloud (Cloud Armor + Advanced Network DDoS Protection)
> **Request**: Include XDDOS PRIME in network DDoS protection policies
> **Attack Tool**: [XDDOS PRIME](https://github.com/team-xddos/XDDOS-Prime)

---

## Attack Signature Summary

| Field | Value |
|-------|-------|
| Protocol | UDP (17) |
| IP TTL | 255 |
| Packet Size | 540 bytes |
| UDP Checksum | 0x0000 |
| UDP Payload | 512 bytes random |
| Source IPs | Fully spoofed |

---

## Advanced Network DDoS Protection

### Current Behavior

Google Cloud's **Advanced Network DDoS Protection** is always-on and managed by Google for:
- External passthrough Network Load Balancers
- Protocol forwarding
- VMs with public IPs

It does **not** support custom rules — detection and mitigation is fully automated.

### Recommended Enhancement

Google should add XDDOS PRIME to the automatic detection signatures:

```
Signature:      XDDOS_PRIME_UDP_FLOOD
Layer:          L3/L4
Protocol:       UDP
Match ALL:      TTL=255, Size=540, UDP_Checksum=0, TOS=0x00
Action:         Automatic drop (always-on)
False Positive: Zero
```

---

## Cloud Armor Security Policies

For HTTP/HTTPS workloads behind Application Load Balancers, Cloud Armor provides custom rule support. While primarily L7, it can complement network DDoS protection.

### Enable Advanced Network DDoS Protection

```bash
# Create security policy with advanced DDoS protection
gcloud compute security-policies create xddos-prime-protection \
    --type=CLOUD_ARMOR_NETWORK \
    --region=us-central1

# Enable advanced protection on the policy
gcloud compute security-policies update xddos-prime-protection \
    --network-ddos-protection=ADVANCED \
    --region=us-central1
```

### Apply to Backend Service

```bash
# Apply policy to your backend
gcloud compute backend-services update my-backend \
    --security-policy=xddos-prime-protection \
    --global
```

---

## VPC Firewall Rules — Quick Protection

### Block All UDP (If Not Needed)

```bash
gcloud compute firewall-rules create block-all-udp \
    --direction=INGRESS \
    --action=DENY \
    --rules=udp:0-65535 \
    --source-ranges=0.0.0.0/0 \
    --priority=100 \
    --network=default \
    --description="Block all inbound UDP - XDDOS PRIME mitigation"
```

### Block Specific Port Under Attack

```bash
gcloud compute firewall-rules create block-udp-target-port \
    --direction=INGRESS \
    --action=DENY \
    --rules=udp:TARGET_PORT \
    --source-ranges=0.0.0.0/0 \
    --priority=100 \
    --network=default \
    --description="Block UDP on attacked port"
```

### Allow Only Trusted UDP Sources

```bash
# Allow trusted
gcloud compute firewall-rules create allow-trusted-udp \
    --direction=INGRESS \
    --action=ALLOW \
    --rules=udp:YOUR_PORT \
    --source-ranges=TRUSTED_IP/32 \
    --priority=100 \
    --network=default

# Deny all other UDP
gcloud compute firewall-rules create deny-other-udp \
    --direction=INGRESS \
    --action=DENY \
    --rules=udp:0-65535 \
    --source-ranges=0.0.0.0/0 \
    --priority=200 \
    --network=default
```

---

## Cloud Logging — Detection

### Create Log-based Alert

```bash
# Create a metric for UDP traffic spikes
gcloud logging metrics create xddos_prime_detection \
    --description="Detect XDDOS PRIME UDP flood" \
    --filter='resource.type="gce_subnetwork" AND jsonPayload.connection.protocol="17" AND jsonPayload.rule_details.action="DENY"'

# Create alert policy
gcloud alpha monitoring policies create \
    --display-name="XDDOS PRIME Detection" \
    --condition-display-name="High UDP deny rate" \
    --condition-filter='metric.type="logging.googleapis.com/user/xddos_prime_detection"' \
    --condition-threshold-value=1000 \
    --condition-threshold-duration=60s \
    --notification-channels=YOUR_CHANNEL_ID
```

### Cloud Logging Query

```
resource.type="gce_subnetwork"
jsonPayload.connection.protocol="17"
jsonPayload.rule_details.action="DENY"
severity>=WARNING
```

---

## Terraform Configuration

```hcl
# VPC Firewall Rule to block suspicious UDP
resource "google_compute_firewall" "block_suspicious_udp" {
  name    = "block-xddos-prime-udp"
  network = var.network_name

  deny {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  source_ranges = ["0.0.0.0/0"]
  priority      = 100
  direction     = "INGRESS"
  description   = "Block XDDOS PRIME UDP flood - all inbound UDP"
}

# Cloud Armor policy with advanced DDoS protection
resource "google_compute_security_policy" "xddos_protection" {
  name = "xddos-prime-protection"
  type = "CLOUD_ARMOR_NETWORK"

  advanced_options_config {
    enable_ml = true
  }
}
```

---

## Why This Should Be in Automatic Protection

1. **Deterministic signature** — Fixed header values, no ML learning needed
2. **Zero false positives** — No legitimate UDP stack uses TTL=255 + checksum=0 + 540 bytes
3. **Instant mitigation** — Static rule eliminates 100% of attack traffic immediately
4. **Open source** — Google's security team can verify from source code
5. **Complements ML** — Works instantly while ML-based detection learns baseline

---

## Contact

**TEAM XDDOS** — [github.com/team-xddos/XDDOS-Prime](https://github.com/team-xddos/XDDOS-Prime)
