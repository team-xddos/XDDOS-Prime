# Azure DDoS Protection — XDDOS PRIME Mitigation Guide

> **Vendor**: Microsoft Azure (DDoS Protection + Azure Firewall)
> **Request**: Add XDDOS PRIME to standard protection detection signatures
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

## Recommended Enhancement for Azure DDoS Protection

Azure DDoS Protection uses adaptive ML-based tuning with a 30-day learning period. XDDOS PRIME has a fixed signature that should be detected instantly without waiting for baseline learning.

```
Signature:      XDDOS_PRIME_UDP_FLOOD
Match ALL:      Protocol=UDP, TTL=255, Size=540, UDP_Checksum=0
Action:         Automatic drop (always-on)
False Positive: Zero
```

---

## DDoS Rapid Response (DRR) — Engagement Template

```
Subject: Custom Mitigation — XDDOS PRIME UDP Flood

Tool:       XDDOS PRIME (open-source)
Source:     https://github.com/team-xddos/XDDOS-Prime
Signature:  TTL=255, Size=540, UDP Checksum=0x0000, TOS=0x00
Request:    Static signature-based drop, bypass adaptive learning
Risk:       Zero false positives
```

---

## NSG — Quick Protection

```bash
# Block all UDP (if not needed)
az network nsg rule create \
    --resource-group myRG --nsg-name myNSG \
    --name Block-All-UDP --priority 100 \
    --direction Inbound --access Deny --protocol Udp \
    --source-address-prefixes '*' --destination-port-ranges '*'

# Or block specific attacked port
az network nsg rule create \
    --resource-group myRG --nsg-name myNSG \
    --name Block-UDP-Port --priority 100 \
    --direction Inbound --access Deny --protocol Udp \
    --source-address-prefixes '*' --destination-port-ranges TARGET_PORT
```

---

## Azure Monitor — Alerting

```bash
az monitor metrics alert create \
    --resource-group myRG --name "XDDOS-PRIME-Alert" \
    --scopes "/subscriptions/SUB_ID/resourceGroups/myRG/providers/Microsoft.Network/publicIPAddresses/myPublicIP" \
    --condition "avg IfUnderDDoSAttack > 0" \
    --window-size 5m --evaluation-frequency 1m --severity 1

# Enable diagnostic logs
az monitor diagnostic-settings create \
    --resource "/subscriptions/SUB_ID/resourceGroups/myRG/providers/Microsoft.Network/publicIPAddresses/myPublicIP" \
    --name "DDoS-Diagnostics" \
    --workspace "YOUR_LOG_ANALYTICS_WORKSPACE_ID" \
    --logs '[{"category":"DDoSProtectionNotifications","enabled":true},{"category":"DDoSMitigationFlowLogs","enabled":true}]'
```

### KQL Query — Detect Attack

```kql
AzureDiagnostics
| where Category == "DDoSMitigationFlowLogs"
| where protocol_s == "UDP"
| summarize PacketCount=count(), UniqueIPs=dcount(sourceAddress_s)
    by bin(TimeGenerated, 1m), destinationAddress_s
| where PacketCount > 10000 and UniqueIPs > 500
```

---

## Terraform

```hcl
resource "azurerm_network_security_rule" "block_udp" {
  name                        = "Block-Suspicious-UDP"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Udp"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = var.resource_group_name
  network_security_group_name = var.nsg_name
}
```

---

## Contact

**TEAM XDDOS** — [github.com/team-xddos/XDDOS-Prime](https://github.com/team-xddos/XDDOS-Prime)
